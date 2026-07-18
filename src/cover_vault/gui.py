from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.parse import urlparse

from .arxiv import (
    ArxivPdfCandidate,
    minimum_pdf_bytes_for_folder,
    search_arxiv_pdfs,
)
from .cover import (
    CachedRemoteCover,
    cache_remote_cover,
    is_remote_cover_source,
    preserve_cached_cover,
)
from .errors import CoverVaultError
from .gui_logic import (
    MODES,
    build_excludes,
    capacity_summary,
    cover_suffix,
    format_bytes,
    suggested_output_filename,
    suggested_output_path,
)
from .progress import ProgressEvent
from .stego import DEFAULT_MAX_USAGE_RATIO
from .vault import (
    estimate_folder_payload,
    hide_folder,
    plan_folder,
    reveal_folder,
)

try:
    from PIL import Image, ImageTk
except ImportError:
    ImageTk = None


class CoverVaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cover Vault")
        self.geometry("930x720")
        self.minsize(800, 650)
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._icon_photo = None
        self._remote_cache: dict[str, CachedRemoteCover] = {}
        self._load_icon()
        self._build_ui()
        self.after(100, self._drain_events)

    def _load_icon(self) -> None:
        try:
            if ImageTk is None:
                return
            possible_paths = [
                Path(__file__).parent.parent.parent / "assets" / "cover-vault.png",
                Path(__file__).parent / "assets" / "cover-vault.png",
            ]
            icon_path = next((path for path in possible_paths if path.exists()), None)
            if icon_path is None:
                return
            icon_image = Image.open(icon_path)
            self._icon_photo = ImageTk.PhotoImage(icon_image)
            self.iconphoto(False, self._icon_photo)
        except Exception:
            pass

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="Cover Vault", font=("TkDefaultFont", 18, "bold")).pack(
            anchor="w"
        )
        ttk.Label(
            root,
            text=(
                "Encrypt a folder into an image or WAV carrier, or attach it to a PDF, "
                "then restore it later."
            ),
        ).pack(anchor="w", pady=(2, 12))

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

    def _row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        command,
        button: str,
    ) -> None:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 8), pady=5
        )
        ttk.Entry(parent, textvariable=variable).grid(
            row=row, column=1, sticky="ew", pady=5
        )
        ttk.Button(parent, text=button, command=command).grid(
            row=row, column=2, padx=(8, 0), pady=5
        )

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
        self.overwrite_output_var = tk.BooleanVar(value=False)
        self.preserve_remote_var = tk.BooleanVar(value=True)
        self.custom_excludes_var = tk.StringVar()
        self.plan_var = tk.StringVar(
            value="Select a source folder and cover, then preview capacity."
        )

        self._row(
            f,
            0,
            "Folder",
            self.source_var,
            lambda: self._pick_directory(self.source_var),
            "Browse…",
        )
        ttk.Label(f, text="Cover path / HTTPS URL").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=5
        )
        ttk.Entry(f, textvariable=self.cover_var).grid(
            row=1, column=1, sticky="ew", pady=5
        )
        cover_actions = ttk.Frame(f)
        cover_actions.grid(row=1, column=2, padx=(8, 0), pady=5)
        ttk.Button(cover_actions, text="Browse…", command=self._pick_cover).pack(
            side="left"
        )
        self.arxiv_button = ttk.Button(
            cover_actions, text="Find arXiv PDF…", command=self._find_arxiv
        )
        self.arxiv_button.pack(side="left", padx=(6, 0))
        ttk.Label(
            f,
            text=(
                "Remote covers are downloaded once. By default, the exact bytes and a "
                "SHA-256 receipt are saved beside the vault."
            ),
            wraplength=690,
        ).grid(row=2, column=1, columnspan=2, sticky="w")
        self._row(f, 3, "Output file", self.output_var, self._pick_output, "Save as…")
        ttk.Label(f, text="Password").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.hide_password_var, show="•").grid(
            row=4, column=1, columnspan=2, sticky="ew", pady=5
        )
        ttk.Label(f, text="Confirm").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.confirm_var, show="•").grid(
            row=5, column=1, columnspan=2, sticky="ew", pady=5
        )
        ttk.Label(f, text="Carrier mode").grid(row=6, column=0, sticky="w", pady=5)
        ttk.Combobox(
            f, textvariable=self.hide_mode_var, values=MODES, state="readonly"
        ).grid(row=6, column=1, sticky="w", pady=5)
        ttk.Label(f, text="Maximum usage").grid(row=7, column=0, sticky="w", pady=5)
        ratio = ttk.Frame(f)
        ratio.grid(row=7, column=1, columnspan=2, sticky="ew")
        ttk.Scale(ratio, from_=0.05, to=1.0, variable=self.ratio_var).pack(
            side="left", fill="x", expand=True
        )
        self.ratio_label = ttk.Label(ratio, width=8)
        self.ratio_label.pack(side="left", padx=(8, 0))
        self.ratio_var.trace_add(
            "write",
            lambda *_: self.ratio_label.configure(text=f"{self.ratio_var.get():.0%}"),
        )
        self.ratio_label.configure(text=f"{self.ratio_var.get():.0%}")
        ttk.Checkbutton(
            f, text="Include Git commit history (.git)", variable=self.git_var
        ).grid(row=8, column=1, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(
            f,
            text="Replace output file if it already exists",
            variable=self.overwrite_output_var,
        ).grid(row=9, column=1, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(
            f,
            text="Preserve an exact local copy of a downloaded cover",
            variable=self.preserve_remote_var,
        ).grid(row=10, column=1, columnspan=2, sticky="w", pady=5)
        ttk.Label(f, text="Extra excludes").grid(row=11, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.custom_excludes_var).grid(
            row=11, column=1, columnspan=2, sticky="ew", pady=5
        )
        ttk.Label(
            f, text="Comma-separated names, for example node_modules, dist, .venv"
        ).grid(row=12, column=1, columnspan=2, sticky="w")
        ttk.Separator(f).grid(row=13, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(f, textvariable=self.plan_var, wraplength=780).grid(
            row=14, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )
        actions = ttk.Frame(f)
        actions.grid(row=15, column=0, columnspan=3, sticky="e")
        self.preview_button = ttk.Button(
            actions, text="Preview capacity", command=self._preview
        )
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
        self._row(
            f,
            0,
            "Vault file",
            self.stego_var,
            lambda: self._pick_file(self.stego_var),
            "Browse…",
        )
        self._row(
            f,
            1,
            "Original cover path / URL",
            self.original_var,
            lambda: self._pick_file(self.original_var),
            "Browse…",
        )
        ttk.Label(
            f,
            text=(
                "For remote covers, prefer the preserved original-cover file named in "
                "the cover receipt rather than downloading the URL again."
            ),
            wraplength=690,
        ).grid(row=2, column=1, columnspan=2, sticky="w")
        self._row(
            f,
            3,
            "Destination",
            self.destination_var,
            lambda: self._pick_directory(self.destination_var),
            "Browse…",
        )
        ttk.Label(f, text="Password").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.reveal_password_var, show="•").grid(
            row=4, column=1, columnspan=2, sticky="ew", pady=5
        )
        ttk.Label(f, text="Carrier mode").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Combobox(
            f, textvariable=self.reveal_mode_var, values=MODES, state="readonly"
        ).grid(row=5, column=1, sticky="w", pady=5)
        ttk.Checkbutton(
            f, text="Overwrite destination if it exists", variable=self.overwrite_var
        ).grid(row=6, column=1, columnspan=2, sticky="w", pady=5)
        self.reveal_button = ttk.Button(f, text="Restore folder", command=self._reveal)
        self.reveal_button.grid(row=7, column=2, sticky="e", pady=(18, 0))

    def _pick_directory(self, variable: tk.StringVar) -> None:
        value = filedialog.askdirectory()
        if value:
            variable.set(value)

    def _pick_file(self, variable: tk.StringVar) -> None:
        value = filedialog.askopenfilename(
            filetypes=[
                ("Supported covers", "*.png *.bmp *.tif *.tiff *.wav *.pdf"),
                ("All files", "*.*"),
            ]
        )
        if value:
            variable.set(value)

    def _pick_cover(self) -> None:
        self._pick_file(self.cover_var)
        if self.cover_var.get() and not self.output_var.get():
            self.output_var.set(suggested_output_path(self.cover_var.get()))

    def _pick_output(self) -> None:
        source = self.cover_var.get()
        value = filedialog.asksaveasfilename(
            defaultextension=cover_suffix(source),
            initialfile=suggested_output_filename(source),
        )
        if value:
            self.output_var.set(value)

    def _confirm_insecure_http(self, source: str) -> bool | None:
        if urlparse(source).scheme.lower() != "http":
            return False
        accepted = messagebox.askyesno(
            "Insecure HTTP cover",
            "Plain HTTP can be changed in transit. Continue with this URL anyway?",
        )
        return True if accepted else None

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (
            self.preview_button,
            self.hide_button,
            self.reveal_button,
            self.arxiv_button,
        ):
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

    def _mapped_progress(self, start: float, span: float):
        def callback(event: ProgressEvent) -> None:
            self._progress_callback(
                ProgressEvent(start + event.fraction * span, event.message)
            )

        return callback

    def _materialize_cover(
        self,
        source: str,
        *,
        allow_http: bool,
        progress_start: float,
        progress_span: float,
    ) -> tuple[str, CachedRemoteCover | None]:
        if not is_remote_cover_source(source):
            return source, None
        cached = self._remote_cache.get(source)
        if cached is not None and cached.local_path.exists():
            return str(cached.local_path), cached
        cached = cache_remote_cover(
            source,
            allow_http=allow_http,
            progress=self._mapped_progress(progress_start, progress_span),
        )
        self._remote_cache[source] = cached
        return str(cached.local_path), cached

    def _preview(self) -> None:
        source = self.source_var.get()
        cover_source = self.cover_var.get()
        if not source or not cover_source:
            messagebox.showerror(
                "Missing information", "Select both a source folder and cover."
            )
            return
        allow_http = self._confirm_insecure_http(cover_source)
        if allow_http is None:
            return
        excludes = build_excludes(self.git_var.get(), self.custom_excludes_var.get())
        mode = self.hide_mode_var.get()
        ratio = self.ratio_var.get()
        self.status_var.set("Calculating capacity…")

        def operation():
            cover, cached = self._materialize_cover(
                cover_source,
                allow_http=allow_http,
                progress_start=0.0,
                progress_span=0.25,
            )
            return (
                "plan",
                {
                    "plan": plan_folder(
                        source,
                        cover,
                        mode=mode,
                        excludes=excludes,
                        max_usage_ratio=ratio,
                    ),
                    "cached": cached,
                },
            )

        self._run(operation)

    def _hide(self) -> None:
        source = self.source_var.get()
        cover_source = self.cover_var.get()
        output = self.output_var.get()
        password = self.hide_password_var.get()
        confirmation = self.confirm_var.get()
        if not all((source, cover_source, output, password)):
            messagebox.showerror(
                "Missing information",
                "Complete the folder, cover, output, and password fields.",
            )
            return
        if password != confirmation:
            messagebox.showerror(
                "Password mismatch", "The password fields do not match."
            )
            return
        allow_http = self._confirm_insecure_http(cover_source)
        if allow_http is None:
            return
        excludes = build_excludes(self.git_var.get(), self.custom_excludes_var.get())
        mode = self.hide_mode_var.get()
        ratio = self.ratio_var.get()
        overwrite_output = self.overwrite_output_var.get()
        preserve_remote = self.preserve_remote_var.get()

        def operation():
            cover, cached = self._materialize_cover(
                cover_source,
                allow_http=allow_http,
                progress_start=0.0,
                progress_span=0.15,
            )
            progress = (
                self._mapped_progress(0.15, 0.85) if cached else self._progress_callback
            )
            result = hide_folder(
                source,
                cover,
                output,
                password,
                mode=mode,
                excludes=excludes,
                max_usage_ratio=ratio,
                overwrite_output=overwrite_output,
                progress=progress,
            )
            preserved = None
            preservation_warning = None
            if cached is not None and preserve_remote:
                try:
                    preserved = preserve_cached_cover(cached, output)
                except CoverVaultError as exc:
                    preservation_warning = str(exc)
            return (
                "hide",
                {
                    "result": result,
                    "cached": cached,
                    "preserved": preserved,
                    "preservation_warning": preservation_warning,
                },
            )

        self._run(operation)

    def _reveal(self) -> None:
        stego = self.stego_var.get()
        original = self.original_var.get()
        destination = self.destination_var.get()
        password = self.reveal_password_var.get()
        if not all((stego, original, destination, password)):
            messagebox.showerror(
                "Missing information",
                "Complete the vault, original cover, destination, and password fields.",
            )
            return
        allow_http = self._confirm_insecure_http(original)
        if allow_http is None:
            return
        mode = self.reveal_mode_var.get()
        overwrite = self.overwrite_var.get()

        def operation():
            cover, cached = self._materialize_cover(
                original,
                allow_http=allow_http,
                progress_start=0.0,
                progress_span=0.15,
            )
            progress = (
                self._mapped_progress(0.15, 0.85) if cached else self._progress_callback
            )
            return (
                "reveal",
                reveal_folder(
                    stego,
                    cover,
                    destination,
                    password,
                    mode=mode,
                    overwrite=overwrite,
                    progress=progress,
                ),
            )

        self._run(operation)

    def _find_arxiv(self) -> None:
        source = self.source_var.get()
        if not source:
            messagebox.showerror(
                "Missing folder",
                "Select the folder first so Cover Vault can calculate the required PDF size.",
            )
            return
        query = simpledialog.askstring(
            "Find an arXiv PDF cover",
            "Search terms (for example: cryptography systems):",
            parent=self,
        )
        if query is None or not query.strip():
            return
        query = query.strip()
        excludes = build_excludes(self.git_var.get(), self.custom_excludes_var.get())
        ratio = self.ratio_var.get()
        self.status_var.set("Estimating payload and searching arXiv…")

        def operation():
            estimate = estimate_folder_payload(source, excludes=excludes)
            minimum = minimum_pdf_bytes_for_folder(
                estimate["estimated_payload_bytes"], ratio
            )
            candidates = search_arxiv_pdfs(query, minimum_bytes=minimum, max_results=25)
            return (
                "arxiv",
                {
                    "query": query,
                    "estimate": estimate,
                    "minimum_bytes": minimum,
                    "candidates": candidates,
                },
            )

        self._run(operation)

    def _show_arxiv_results(self, payload: dict) -> None:
        candidates = payload["candidates"]
        if not candidates:
            messagebox.showinfo(
                "No suitable arXiv PDFs found",
                (
                    f"No probed result was between {format_bytes(payload['minimum_bytes'])} "
                    "and the 256 MiB remote-cover limit. Try broader search terms, a smaller "
                    "folder, or a higher maximum-usage setting."
                ),
            )
            return

        dialog = tk.Toplevel(self)
        dialog.title("Suitable arXiv PDF covers")
        dialog.geometry("900x430")
        dialog.transient(self)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=(
                f"Required PDF reference size: {format_bytes(payload['minimum_bytes'])}. "
                "Select a PDF; it will be downloaded only when previewing "
                "or creating the vault."
            ),
            wraplength=850,
        ).pack(anchor="w", pady=(0, 10))

        tree = ttk.Treeview(
            frame,
            columns=("size", "id", "published", "title"),
            show="headings",
            selectmode="browse",
        )
        tree.heading("size", text="Size")
        tree.heading("id", text="arXiv ID")
        tree.heading("published", text="Published")
        tree.heading("title", text="Title")
        tree.column("size", width=90, anchor="e")
        tree.column("id", width=130)
        tree.column("published", width=100)
        tree.column("title", width=520)
        tree.pack(fill="both", expand=True)
        by_item: dict[str, ArxivPdfCandidate] = {}
        for candidate in candidates:
            item = tree.insert(
                "",
                "end",
                values=(
                    format_bytes(candidate.size_bytes),
                    candidate.arxiv_id,
                    candidate.published[:10],
                    candidate.title,
                ),
            )
            by_item[item] = candidate
        first = tree.get_children()
        if first:
            tree.selection_set(first[0])
            tree.focus(first[0])

        details_var = tk.StringVar(
            value="arXiv search is opt-in. Review the paper and its licence before reuse or redistribution."
        )
        ttk.Label(frame, textvariable=details_var, wraplength=850).pack(
            anchor="w", pady=(8, 8)
        )

        def update_details(_event=None) -> None:
            selected = tree.selection()
            if not selected:
                return
            candidate = by_item[selected[0]]
            authors = ", ".join(candidate.authors[:4]) or "Unknown authors"
            if len(candidate.authors) > 4:
                authors += ", …"
            licence = candidate.license_url or "No licence URL in API metadata"
            details_var.set(f"{authors} — {licence}")

        def use_selected() -> None:
            selected = tree.selection()
            if not selected:
                return
            candidate = by_item[selected[0]]
            self.cover_var.set(candidate.pdf_url)
            self.hide_mode_var.set("pdf-attachment")
            if not self.output_var.get():
                self.output_var.set(suggested_output_path(candidate.pdf_url))
            self.plan_var.set(
                f"Selected arXiv {candidate.arxiv_id}: {candidate.title} "
                f"({format_bytes(candidate.size_bytes)}). Preview capacity before creating the vault."
            )
            dialog.destroy()

        tree.bind("<<TreeviewSelect>>", update_details)
        update_details()
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right")
        ttk.Button(buttons, text="Use selected PDF", command=use_selected).pack(
            side="right", padx=(0, 8)
        )

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
                        plan = result["plan"]
                        remote = result["cached"]
                        extra = ""
                        if remote is not None:
                            extra = (
                                f"\nDownloaded from {remote.final_url}\n"
                                f"SHA-256: {remote.sha256}"
                            )
                        self.plan_var.set(
                            capacity_summary(plan)
                            + (f"\n{plan['advisory']}" if plan.get("advisory") else "")
                            + extra
                        )
                        self.progress["value"] = 100
                        self.status_var.set("Capacity preview complete")
                    elif operation == "hide":
                        payload_result = result["result"]
                        self.hide_password_var.set("")
                        self.confirm_var.set("")
                        self.status_var.set("Vault created")
                        preservation = ""
                        if result["preserved"]:
                            original, receipt = result["preserved"]
                            preservation = (
                                f"\n\nOriginal cover saved as:\n{original}\n"
                                f"Receipt:\n{receipt}"
                            )
                        if result["preservation_warning"]:
                            preservation += (
                                "\n\nWarning: the vault was created, but the downloaded "
                                f"cover could not be preserved:\n{result['preservation_warning']}"
                            )
                        messagebox.showinfo(
                            "Cover Vault",
                            (
                                f"Vault created successfully.\n\n{payload_result['output']}\n"
                                f"Mode: {payload_result['mode']}\n"
                                f"Files: {payload_result['files_encrypted']}\n"
                                f"Usage: {payload_result['usage_percent']:.2f}%"
                                f"{preservation}"
                            ),
                        )
                    elif operation == "arxiv":
                        self.progress["value"] = 100
                        self.status_var.set("arXiv search complete")
                        self._show_arxiv_results(result)
                    else:
                        self.reveal_password_var.set("")
                        self.status_var.set("Folder restored")
                        messagebox.showinfo(
                            "Cover Vault",
                            (
                                f"Folder restored successfully.\n\n{result['destination']}\n"
                                f"Files: {result['files_decrypted']}"
                            ),
                        )
        except queue.Empty:
            pass
        self.after(100, self._drain_events)


def main() -> None:
    app = CoverVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
