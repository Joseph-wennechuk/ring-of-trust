#!/usr/bin/env python3
"""
BLE GATT Explorer
==================
A simple Tkinter GUI (Linux/BlueZ, via bleak) to:
  1. Scan for nearby BLE devices
  2. Connect to a selected device
  3. Browse its GATT services and characteristics with human-readable
     names resolved from the Bluetooth SIG assigned-numbers list
     (falls back to raw UUID + "Custom" label for vendor-specific ones)
  4. Read, write, and subscribe to notifications on characteristics
     (right-click a characteristic in the tree)

Install:
    pip install bleak --break-system-packages

Run:
    python3 ble_gatt_explorer.py

Notes for Linux:
  - Requires BlueZ (bluetoothd) running, which is standard on most
    distros. No root/capabilities needed for the default bleak/BlueZ
    D-Bus backend.
  - If scanning finds nothing, make sure Bluetooth is powered on
    (e.g. `bluetoothctl power on`) and your adapter isn't blocked
    (`rfkill list`).
"""

import asyncio
import threading
import queue
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from bleak import BleakScanner, BleakClient
from bleak.uuids import uuidstr_to_str


# --------------------------------------------------------------------------
# Background asyncio worker
# --------------------------------------------------------------------------
class BLEWorker:
    """Runs an asyncio event loop on a background thread and exposes
    thread-safe methods the Tkinter GUI can call. Results are pushed
    onto a queue.Queue that the GUI polls on the main thread."""

    def __init__(self, result_queue: "queue.Queue"):
        self.result_queue = result_queue
        self.loop = asyncio.new_event_loop()
        self.client = None
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    # --- Scanning ---------------------------------------------------------
    def scan(self, timeout=6.0):
        self._submit(self._scan(timeout))

    async def _scan(self, timeout):
        try:
            devices = await BleakScanner.discover(timeout=timeout)
            self.result_queue.put(("scan_done", devices))
        except Exception as e:
            self.result_queue.put(("error", f"Scan failed: {e}"))

    # --- Connect / disconnect ----------------------------------------------
    def connect(self, address):
        self._submit(self._connect(address))

    async def _connect(self, address):
        try:
            client = BleakClient(address)
            await client.connect()
            self.client = client
            self.result_queue.put(("connected", address))
            # client.services is populated automatically after connect()
            self.result_queue.put(("services", client.services))
        except Exception as e:
            self.result_queue.put(("error", f"Connect failed: {e}"))

    def disconnect(self):
        if self.client:
            self._submit(self._disconnect())

    async def _disconnect(self):
        try:
            await self.client.disconnect()
            self.result_queue.put(("disconnected", None))
        except Exception as e:
            self.result_queue.put(("error", f"Disconnect failed: {e}"))

    # --- Read / write / notify --------------------------------------------
    def read_char(self, uuid):
        self._submit(self._read_char(uuid))

    async def _read_char(self, uuid):
        try:
            data = await self.client.read_gatt_char(uuid)
            self.result_queue.put(("char_value", (uuid, bytes(data))))
        except Exception as e:
            self.result_queue.put(("error", f"Read failed ({uuid}): {e}"))

    def write_char(self, uuid, data, response):
        self._submit(self._write_char(uuid, data, response))

    async def _write_char(self, uuid, data, response):
        try:
            await self.client.write_gatt_char(uuid, data, response=response)
            self.result_queue.put(("write_done", (uuid, data)))
        except Exception as e:
            self.result_queue.put(("error", f"Write failed ({uuid}): {e}"))

    def start_notify(self, uuid):
        self._submit(self._start_notify(uuid))

    async def _start_notify(self, uuid):
        def callback(_sender, data):
            self.result_queue.put(("notify_data", (uuid, bytes(data))))

        try:
            await self.client.start_notify(uuid, callback)
            self.result_queue.put(("notify_started", uuid))
        except Exception as e:
            self.result_queue.put(("error", f"Subscribe failed ({uuid}): {e}"))

    def stop_notify(self, uuid):
        self._submit(self._stop_notify(uuid))

    async def _stop_notify(self, uuid):
        try:
            await self.client.stop_notify(uuid)
            self.result_queue.put(("notify_stopped", uuid))
        except Exception as e:
            self.result_queue.put(("error", f"Unsubscribe failed ({uuid}): {e}"))

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


# --------------------------------------------------------------------------
# UUID -> human readable helper
# --------------------------------------------------------------------------
def human_name(uuid_str: str, fallback: str) -> str:
    name = uuidstr_to_str(uuid_str)
    if name and name.lower() != uuid_str.lower():
        return name
    return fallback


def format_bytes(data: bytes) -> str:
    hex_str = data.hex(" ")
    try:
        text = data.decode("utf-8")
        printable = all(32 <= b < 127 for b in data) or not data
        if printable:
            return f'hex[{hex_str}]  text["{text}"]'
    except UnicodeDecodeError:
        pass
    return f"hex[{hex_str}]"


# --------------------------------------------------------------------------
# Write-value dialog
# --------------------------------------------------------------------------
class WriteDialog(tk.Toplevel):
    """Modal dialog to collect a value (hex or UTF-8 text) to write."""

    def __init__(self, parent, char_label, can_respond, can_write_no_response):
        super().__init__(parent)
        self.title(f"Write to {char_label}")
        self.resizable(False, False)
        self.result = None  # (bytes, response_bool)
        self.transient(parent)
        self.grab_set()

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Value:").grid(row=0, column=0, sticky="w")
        self.value_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.value_var, width=40).grid(
            row=0, column=1, columnspan=2, sticky="ew", padx=(6, 0)
        )

        self.format_var = tk.StringVar(value="hex")
        ttk.Radiobutton(frm, text="Hex (e.g. 01 0A FF)", variable=self.format_var,
                         value="hex").grid(row=1, column=1, sticky="w", pady=(4, 0))
        ttk.Radiobutton(frm, text="Text (UTF-8)", variable=self.format_var,
                         value="text").grid(row=1, column=2, sticky="w", pady=(4, 0))

        # Response mode, only offered if both are supported by the characteristic
        self.response_var = tk.BooleanVar(value=can_respond)
        if can_respond and can_write_no_response:
            ttk.Checkbutton(frm, text="Wait for response (write with response)",
                             variable=self.response_var).grid(
                row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        else:
            self.response_var.set(can_respond)

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=3, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Write", command=self._on_write).pack(side="right")

        self.bind("<Return>", lambda _e: self._on_write())
        self.value_var_entry_focus = frm

    def _on_write(self):
        raw = self.value_var.get().strip()
        try:
            if self.format_var.get() == "hex":
                cleaned = raw.replace(" ", "").replace("0x", "").replace(",", "")
                if len(cleaned) % 2 != 0:
                    raise ValueError("Hex string must have an even number of digits")
                data = bytes.fromhex(cleaned)
            else:
                data = raw.encode("utf-8")
        except ValueError as e:
            messagebox.showerror("Invalid value", str(e), parent=self)
            return
        self.result = (data, self.response_var.get())
        self.destroy()


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BLE GATT Explorer")
        self.geometry("900x680")

        self.result_queue = queue.Queue()
        self.worker = BLEWorker(self.result_queue)
        self.devices = {}       # address -> BLEDevice
        self.tree_chars = {}    # tree item id -> characteristic object
        self.uuid_to_item = {}  # char uuid -> tree item id (for logging by name)
        self.notifying = set()  # uuids currently subscribed

        self._build_ui()
        self.after(100, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        self.scan_btn = ttk.Button(top, text="Scan for devices", command=self.on_scan)
        self.scan_btn.pack(side="left")

        self.connect_btn = ttk.Button(top, text="Connect", command=self.on_connect, state="disabled")
        self.connect_btn.pack(side="left", padx=6)

        self.disconnect_btn = ttk.Button(top, text="Disconnect", command=self.on_disconnect, state="disabled")
        self.disconnect_btn.pack(side="left")

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(top, textvariable=self.status_var).pack(side="right")

        paned = ttk.Panedwindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        # Left: discovered devices
        left = ttk.Frame(paned)
        ttk.Label(left, text="Devices").pack(anchor="w")
        self.device_list = tk.Listbox(left, width=38)
        self.device_list.pack(fill="both", expand=True)
        self.device_list.bind("<<ListboxSelect>>", self.on_device_select)
        paned.add(left, weight=1)

        # Right: services/characteristics tree + activity log, stacked vertically
        right = ttk.Panedwindow(paned, orient="vertical")
        paned.add(right, weight=3)

        tree_frame = ttk.Frame(right)
        ttk.Label(tree_frame, text="GATT Services (right-click a characteristic for actions)").pack(anchor="w")
        self.tree = ttk.Treeview(tree_frame, columns=("uuid",), show="tree headings")
        self.tree.heading("#0", text="Service / Characteristic")
        self.tree.heading("uuid", text="UUID")
        self.tree.column("#0", width=380)
        self.tree.column("uuid", width=300)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        right.add(tree_frame, weight=3)

        log_frame = ttk.Frame(right)
        ttk.Label(log_frame, text="Activity Log").pack(anchor="w")
        self.log = scrolledtext.ScrolledText(log_frame, height=10, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)
        right.add(log_frame, weight=1)

        self.context_menu = tk.Menu(self, tearoff=0)

    # --- UI event handlers ---------------------------------------------
    def on_scan(self):
        self.device_list.delete(0, tk.END)
        self.devices.clear()
        self.status_var.set("Scanning...")
        self.scan_btn.config(state="disabled")
        self.worker.scan()

    def on_device_select(self, _event):
        self.connect_btn.config(state="normal" if self.device_list.curselection() else "disabled")

    def on_connect(self):
        sel = self.device_list.curselection()
        if not sel:
            return
        label = self.device_list.get(sel[0])
        address = label.split(" | ")[-1]
        self.status_var.set(f"Connecting to {address} ...")
        self.connect_btn.config(state="disabled")
        self.worker.connect(address)

    def on_disconnect(self):
        self.worker.disconnect()

    def _on_close(self):
        self.worker.stop()
        self.destroy()

    # --- Context menu / actions ------------------------------------------
    def on_tree_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item or item not in self.tree_chars:
            return  # only characteristics have actions, not services
        self.tree.selection_set(item)
        char = self.tree_chars[item]
        props = set(char.properties)

        menu = tk.Menu(self, tearoff=0)
        if "read" in props:
            menu.add_command(label="Read", command=lambda: self.on_read(item))
        if "write" in props or "write-without-response" in props:
            menu.add_command(label="Write...", command=lambda: self.on_write(item))
        if "notify" in props or "indicate" in props:
            if char.uuid in self.notifying:
                menu.add_command(label="Unsubscribe", command=lambda: self.on_unsubscribe(item))
            else:
                menu.add_command(label="Subscribe to notifications", command=lambda: self.on_subscribe(item))
        if menu.index("end") is None:
            menu.add_command(label="(no read/write/notify properties)", state="disabled")
        menu.tk_popup(event.x_root, event.y_root)

    def on_read(self, item):
        char = self.tree_chars[item]
        self._log(f"Reading {self._char_label(char)} ...")
        self.worker.read_char(char.uuid)

    def on_write(self, item):
        char = self.tree_chars[item]
        props = set(char.properties)
        dlg = WriteDialog(
            self,
            self._char_label(char),
            can_respond="write" in props,
            can_write_no_response="write-without-response" in props,
        )
        self.wait_window(dlg)
        if dlg.result is None:
            return
        data, response = dlg.result
        self._log(f"Writing {format_bytes(data)} to {self._char_label(char)} "
                   f"({'with' if response else 'without'} response) ...")
        self.worker.write_char(char.uuid, data, response)

    def on_subscribe(self, item):
        char = self.tree_chars[item]
        self._log(f"Subscribing to {self._char_label(char)} ...")
        self.worker.start_notify(char.uuid)

    def on_unsubscribe(self, item):
        char = self.tree_chars[item]
        self._log(f"Unsubscribing from {self._char_label(char)} ...")
        self.worker.stop_notify(char.uuid)

    def _char_label(self, char):
        return f"{human_name(char.uuid, 'Custom Characteristic')} ({char.uuid})"

    def _log(self, message):
        ts = time.strftime("%H:%M:%S")
        self.log.config(state="normal")
        self.log.insert("end", f"[{ts}] {message}\n")
        self.log.see("end")
        self.log.config(state="disabled")

    # --- Background-thread message pump ---------------------------------
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                self._handle_message(kind, payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_message(self, kind, payload):
        if kind == "scan_done":
            self.scan_btn.config(state="normal")
            self.status_var.set(f"Found {len(payload)} device(s)")
            for d in payload:
                name = d.name or "(unnamed)"
                self.devices[d.address] = d
                self.device_list.insert(tk.END, f"{name} | {d.address}")

        elif kind == "connected":
            self.status_var.set(f"Connected to {payload}")
            self.disconnect_btn.config(state="normal")
            self.connect_btn.config(state="disabled")
            self._log(f"Connected to {payload}")

        elif kind == "services":
            self._populate_tree(payload)

        elif kind == "disconnected":
            self.status_var.set("Disconnected")
            self.disconnect_btn.config(state="disabled")
            self.connect_btn.config(state="normal")
            self.tree.delete(*self.tree.get_children())
            self.tree_chars.clear()
            self.uuid_to_item.clear()
            self.notifying.clear()
            self._log("Disconnected")

        elif kind == "char_value":
            uuid, data = payload
            self._log(f"Read {self._label_for_uuid(uuid)}: {format_bytes(data)}")

        elif kind == "write_done":
            uuid, data = payload
            self._log(f"Wrote {format_bytes(data)} to {self._label_for_uuid(uuid)}")

        elif kind == "notify_started":
            uuid = payload
            self.notifying.add(uuid)
            self._log(f"Subscribed to {self._label_for_uuid(uuid)}")

        elif kind == "notify_stopped":
            uuid = payload
            self.notifying.discard(uuid)
            self._log(f"Unsubscribed from {self._label_for_uuid(uuid)}")

        elif kind == "notify_data":
            uuid, data = payload
            self._log(f"Notify {self._label_for_uuid(uuid)}: {format_bytes(data)}")

        elif kind == "error":
            self.status_var.set("Error")
            self.scan_btn.config(state="normal")
            self.connect_btn.config(state="normal")
            self._log(f"ERROR: {payload}")
            messagebox.showerror("BLE Error", str(payload))

    def _label_for_uuid(self, uuid):
        item = self.uuid_to_item.get(uuid)
        if item and item in self.tree_chars:
            return self._char_label(self.tree_chars[item])
        return uuid

    def _populate_tree(self, services):
        self.tree.delete(*self.tree.get_children())
        self.tree_chars.clear()
        self.uuid_to_item.clear()
        for service in services:
            s_name = human_name(service.uuid, fallback="Custom / Vendor-specific Service")
            s_node = self.tree.insert("", "end", text=s_name, values=(service.uuid,))
            for char in service.characteristics:
                c_name = human_name(char.uuid, fallback="Custom / Vendor-specific Characteristic")
                props = ", ".join(char.properties)
                c_label = f"{c_name}  [{props}]" if props else c_name
                c_item = self.tree.insert(s_node, "end", text=c_label, values=(char.uuid,))
                self.tree_chars[c_item] = char
                self.uuid_to_item[char.uuid] = c_item


if __name__ == "__main__":
    app = App()
    app.mainloop()
