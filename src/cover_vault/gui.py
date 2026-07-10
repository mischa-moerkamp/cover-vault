from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .errors import CoverVaultError
from .gui_logic import MODES, build_excludes, capacity_summary, suggested_output_path
from .progress import ProgressEvent
from .stego import DEFAULT_MAX_USAGE_RATIO
from .vault import hide_folder, plan_folder, reveal_folder

try:
    from PIL import Image, ImageTk
except ImportError:
    ImageTk = None


class CoverVaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cover Vault")
        self.geometry("820x650")
        self.minsize(720, 590)
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._icon_photo = None  # Keep reference to prevent garbage collection
        self._load_icon()
        self._build_ui()
        self.after(100, self._drain_events)

    def _load_icon(self) -> None:
        """Load and set the window icon from cover-vault.png."""
        try:
            if ImageTk is None:
                return
            
            # Try multiple possible paths
            possible_paths = [
                Path(__file__).parent.parent.parent / "assets" / "cover-vault.png",  # Development
                Path(__file__).parent / "assets" / "cover-vault.png",  # Installed package
            ]
            
            icon_path = None
            for path in possible_paths:
                if path.exists():
                    icon_path = path
                    break
            
            if icon_path is None:
                return
            
            icon_image = Image.open(icon_path)
            self._icon_photo = ImageTk.PhotoImage(icon_image)
            self.iconphoto(False, self._icon_photo)
            
        except Exception:
            # Silently fail if icon loading fails
            pass

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="Cover Vault", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(root, text="Encrypt a folder into an image, WAV, or PDF cover, or restore an existing vault.").pack(anchor="w", pady=(2, 12))

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True)
        self.hide_tab = ttk.Frame(self.tabs, padding=12)
        self.reveal_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.hide_tab, text="Create vault")
        self.tabs.add(self.reveal_tab, text="Restore vault")
        self._build_hide_tab()
        self._build_reveal_tab()

        status = ttk.Frame(root)
        status.pack(fill="x", pady=(12, 0))
        self.progress = ttk.Progressbar(status, maximum=100)
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status, textvariable=self.status_var).pack(anchor="w", pady=(4, 0))

    def _row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, command, button: str) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text=button, command=command).grid(row=row, column=2, padx=(8, 0), pady=5)

    def _build_hide_tab(self) -> None:
        f = self.hide_tab
        f.columnconfigure(1, weight=1)
        self.source_var = tk.StringVar()
        self.cover_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.hide_password_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.hide_mode_var = tk.StringVar(value="auto")
        self.ratio_var = tk.DoubleVar(value=DEFAULT_MAX_USAGE_RATIO)
        self.git_var = tk.BooleanVar(value=False)
        self.custom_excludes_var = tk.StringVar()
        self.plan_var = tk.StringVar(value="Select a source folder and cover, then preview capacity.")

        self._row(f, 0, "Folder", self.source_var, lambda: self._pick_directory(self.source_var), "Browse…")
        self._row(f, 1, "Cover file", self.cover_var, self._pick_cover, "Browse…")
        self._row(f, 2, "Output file", self.output_var, self._pick_output, "Save as…")
        ttk.Label(f, text="Password").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.hide_password_var, show="•").grid(row=3, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(f, text="Confirm").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.confirm_var, show="•").grid(row=4, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(f, text="Carrier mode").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Combobox(f, textvariable=self.hide_mode_var, values=MODES, state="readonly").grid(row=5, column=1, sticky="w", pady=5)
        ttk.Label(f, text="Maximum usage").grid(row=6, column=0, sticky="w", pady=5)
        ratio = ttk.Frame(f)
        ratio.grid(row=6, column=1, columnspan=2, sticky="ew")
        ttk.Scale(ratio, from_=0.05, to=1.0, variable=self.ratio_var).pack(side="left", fill="x", expand=True)
        self.ratio_label = ttk.Label(ratio, width=8)
        self.ratio_label.pack(side="left", padx=(8, 0))
        self.ratio_var.trace_add("write", lambda *_: self.ratio_label.configure(text=f"{self.ratio_var.get():.0%}"))
        self.ratio_label.configure(text=f"{self.ratio_var.get():.0%}")
        ttk.Checkbutton(f, text="Include Git commit history (.git)", variable=self.git_var).grid(row=7, column=1, columnspan=2, sticky="w", pady=5)
        ttk.Label(f, text="Extra excludes").grid(row=8, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.custom_excludes_var).grid(row=8, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(f, text="Comma-separated names, for example node_modules, dist, .venv").grid(row=9, column=1, columnspan=2, sticky="w")
        ttk.Separator(f).grid(row=10, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(f, textvariable=self.plan_var, wraplength=680).grid(row=11, column=0, columnspan=3, sticky="w", pady=(0, 10))
        actions = ttk.Frame(f)
        actions.grid(row=12, column=0, columnspan=3, sticky="e")
        self.preview_button = ttk.Button(actions, text="Preview capacity", command=self._preview)
        self.preview_button.pack(side="left", padx=(0, 8))
        self.hide_button = ttk.Button(actions, text="Create vault", command=self._hide)
        self.hide_button.pack(side="left")

    def _build_reveal_tab(self) -> None:
        f = self.reveal_tab
        f.columnconfigure(1, weight=1)
        self.stego_var = tk.StringVar()
        self.original_var = tk.StringVar()
        self.destination_var = tk.StringVar()
        self.reveal_password_var = tk.StringVar()
        self.reveal_mode_var = tk.StringVar(value="auto")
        self.overwrite_var = tk.BooleanVar(value=False)
        self._row(f, 0, "Vault file", self.stego_var, lambda: self._pick_file(self.stego_var), "Browse…")
        self._row(f, 1, "Original cover", self.original_var, lambda: self._pick_file(self.original_var), "Browse…")
        self._row(f, 2, "Destination", self.destination_var, lambda: self._pick_directory(self.destination_var), "Browse…")
        ttk.Label(f, text="Password").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.reveal_password_var, show="•").grid(row=3, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(f, text="Carrier mode").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Combobox(f, textvariable=self.reveal_mode_var, values=MODES, state="readonly").grid(row=4, column=1, sticky="w", pady=5)
        ttk.Checkbutton(f, text="Overwrite destination if it exists", variable=self.overwrite_var).grid(row=5, column=1, columnspan=2, sticky="w", pady=5)
        self.reveal_button = ttk.Button(f, text="Restore folder", command=self._reveal)
        self.reveal_button.grid(row=6, column=2, sticky="e", pady=(18, 0))

    def _pick_directory(self, variable: tk.StringVar) -> None:
        value = filedialog.askdirectory()
        if value:
            variable.set(value)

    def _pick_file(self, variable: tk.StringVar) -> None:
        value = filedialog.askopenfilename(filetypes=[("Supported covers", "*.png *.bmp *.tif *.tiff *.wav *.pdf"), ("All files", "*.*")])
        if value:
            variable.set(value)

    def _pick_cover(self) -> None:
        self._pick_file(self.cover_var)
        if self.cover_var.get() and not self.output_var.get():
            self.output_var.set(suggested_output_path(self.cover_var.get()))

    def _pick_output(self) -> None:
        cover = Path(self.cover_var.get()) if self.cover_var.get() else None
        value = filedialog.asksaveasfilename(defaultextension=cover.suffix if cover else "", initialfile=Path(suggested_output_path(str(cover))).name if cover else "")
        if value:
            self.output_var.set(value)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.preview_button, self.hide_button, self.reveal_button):
            button.configure(state=state)

    def _run(self, operation) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self.progress["value"] = 0
        def worker() -> None:
            try:
                result = operation()
                self._events.put(("success", result))
            except Exception as exc:
                self._events.put(("error", exc))
        threading.Thread(target=worker, daemon=True).start()

    def _progress_callback(self, event: ProgressEvent) -> None:
        self._events.put(("progress", event))

    def _preview(self) -> None:
        if not self.source_var.get() or not self.cover_var.get():
            messagebox.showerror("Missing information", "Select both a source folder and cover file.")
            return
        excludes = build_excludes(self.git_var.get(), self.custom_excludes_var.get())
        self.status_var.set("Calculating capacity…")
        self._run(lambda: ("plan", plan_folder(self.source_var.get(), self.cover_var.get(), mode=self.hide_mode_var.get(), excludes=excludes, max_usage_ratio=self.ratio_var.get())))

    def _hide(self) -> None:
        if not all((self.source_var.get(), self.cover_var.get(), self.output_var.get(), self.hide_password_var.get())):
            messagebox.showerror("Missing information", "Complete the folder, cover, output, and password fields.")
            return
        if self.hide_password_var.get() != self.confirm_var.get():
            messagebox.showerror("Password mismatch", "The password fields do not match.")
            return
        excludes = build_excludes(self.git_var.get(), self.custom_excludes_var.get())
        self._run(lambda: ("hide", hide_folder(self.source_var.get(), self.cover_var.get(), self.output_var.get(), self.hide_password_var.get(), mode=self.hide_mode_var.get(), excludes=excludes, max_usage_ratio=self.ratio_var.get(), progress=self._progress_callback)))

    def _reveal(self) -> None:
        if not all((self.stego_var.get(), self.original_var.get(), self.destination_var.get(), self.reveal_password_var.get())):
            messagebox.showerror("Missing information", "Complete the vault, original cover, destination, and password fields.")
            return
        self._run(lambda: ("reveal", reveal_folder(self.stego_var.get(), self.original_var.get(), self.destination_var.get(), self.reveal_password_var.get(), mode=self.reveal_mode_var.get(), overwrite=self.overwrite_var.get(), progress=self._progress_callback)))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "progress":
                    event = payload
                    self.progress["value"] = event.fraction * 100
                    self.status_var.set(event.message)
                elif kind == "error":
                    self._set_busy(False)
                    self.status_var.set("Operation failed")
                    messagebox.showerror("Cover Vault", str(payload))
                elif kind == "success":
                    self._set_busy(False)
                    operation, result = payload
                    if operation == "plan":
                        self.plan_var.set(capacity_summary(result) + (f"\n{result['advisory']}" if result.get("advisory") else ""))
                        self.progress["value"] = 100
                        self.status_var.set("Capacity preview complete")
                    elif operation == "hide":
                        self.hide_password_var.set("")
                        self.confirm_var.set("")
                        self.status_var.set("Vault created")
                        messagebox.showinfo("Cover Vault", f"Vault created successfully.\n\n{result['output']}\nMode: {result['mode']}\nFiles: {result['files_encrypted']}\nUsage: {result['usage_percent']:.2f}%")
                    else:
                        self.reveal_password_var.set("")
                        self.status_var.set("Folder restored")
                        messagebox.showinfo("Cover Vault", f"Folder restored successfully.\n\n{result['destination']}\nFiles: {result['files_decrypted']}")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)


def main() -> None:
    app = CoverVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
