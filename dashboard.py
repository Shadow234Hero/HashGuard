"""Local Tk desktop dashboard for live monitoring and the offline college demo."""
import os
import queue
import subprocess
import threading
import tkinter as tk
from collections import deque
from pathlib import Path
from tkinter import messagebox, ttk

from detector import DemoSample, Live, demo, trust
from evidence import file_hash, idle_seconds, powershell

# Warm obsidian & tactile hairline palette (Linear / Raycast inspired)
PALETTE = {
    "bg": "#0D0E11",
    "sidebar": "#111216",
    "surface": "#14161B",
    "surface_alt": "#191C23",
    "surface_hover": "#20242D",
    "hairline": "#232732",
    "hairline_soft": "#1B1E26",
    "text": "#F1F3F7",
    "text_secondary": "#9CA3AF",
    "muted": "#6B7280",
    "accent": "#10B981",        # Crisp emerald primary
    "accent_dark": "#065F46",
    "accent_hover": "#059669",
    "amber": "#F59E0B",
    "coral": "#F43F5E",
    "coral_bg": "#2B141B",
    "coral_border": "#881337",
    "indigo": "#818CF8",
    "select_bg": "#1F2937",
    "select_fg": "#F9FAFB",
}

FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"


def format_evidence_sections(item):
    """Return structured (tag, text) tuples for syntax-highlighted evidence rendering."""
    def group(label, values, empty):
        lines = [("section", f"\n{label}\n")]
        if values:
            for v in values:
                lines.append(("bullet", f"  • {v}\n"))
        else:
            lines.append(("muted", f"  {empty}\n"))
        return lines

    cpu = "unavailable" if item["cpu"] is None else f"{item['cpu']}% (1 logical CPU)"
    gpu = "unavailable" if item["gpu"] is None else f"{item['gpu']}%"
    idle = "unavailable" if item["idle"] is None else f"{item['idle']:.0f}s"

    verdict = item["verdict"]
    v_tag = "verdict_danger" if verdict == "Mining indicators" else (
        "verdict_warn" if verdict == "Sustained load" else "verdict_neutral"
    )

    tokens = [
        (v_tag, f"{verdict.upper()}"),
        ("muted", f"  ·  {item['mode']}  ·  {item['time']}\n"),
        ("title", f"{item['name']}"),
        ("mono_accent", f"  PID {item['pid']}\n"),
        ("path", f"{item['path'] or 'Path unavailable'}\n"),
        ("section", "\nResource Telemetry\n"),
        ("key", "  CPU / GPU   "), ("val", f"{cpu}  ·  {gpu}\n"),
        ("key", "  User Idle   "), ("val", f"{idle}\n"),
        ("key", "  Trigger     "), ("val", f"{item['load'] or 'Selected for manual review'}\n"),
    ]
    tokens.extend(group("Mining-Specific Evidence", item["markers"] + item["pool_matches"], "No match in checks performed"))
    tokens.extend(group(f"Network  ({item['network']})", item["endpoints"], "No peer data"))

    trusted = bool(item.get("trusted"))
    tokens.extend([
        ("section", "\nBinary & Signature Inspection\n"),
        ("key", "  Signature   "), ("val", f"{item['signature']}\n"),
        ("key", "  Entropy     "), ("val", f"{item['entropy']}\n"),
        ("key", "  Allowlist   "), ("ok" if trusted else "muted", "Approved hash\n" if trusted else "Not approved\n"),
    ])
    tokens.extend(group("Matching Startup Entries", item["startup"], "No matches reported"))
    tokens.extend(group("Coverage & Notes", item["notes"], "No additional notes"))
    return tokens


class Dashboard:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.session = 0
        self.live = None
        self.worker = None
        self.mode = "Ready"
        self.sample = None
        self.findings = {}
        self.finding_items = []
        self.all_rows = []
        self.rows = {}
        self.selected_item = None
        self.series = deque(maxlen=100)
        self.sidebar_expanded = True
        self.active_nav = "dashboard"
        self.last_idle = None
        self.last_gpu_status = "Awaiting telemetry"
        self.last_peak_cpu = 0.0

        root.title("HashGuard — Local Cryptojacking Telemetry")
        root.geometry("1240x790")
        root.minsize(940, 620)
        root.configure(bg=PALETTE["bg"])

        self._configure_styles()
        self._build_layout()

        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(70, self.drain)

    def _configure_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=(FONT_UI, 10), background=PALETTE["bg"], foreground=PALETTE["text"])
        style.configure("Dark.TFrame", background=PALETTE["bg"])
        style.configure("Card.TFrame", background=PALETTE["surface"])

        # Tactile neutral button
        style.configure(
            "Ghost.TButton",
            background=PALETTE["surface_alt"],
            foreground=PALETTE["text"],
            bordercolor=PALETTE["hairline"],
            lightcolor=PALETTE["surface_alt"],
            darkcolor=PALETTE["surface_alt"],
            focusthickness=0,
            padding=(12, 6),
            font=(FONT_UI, 9),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", PALETTE["surface_hover"]), ("disabled", PALETTE["surface"])],
            foreground=[("disabled", PALETTE["muted"])],
        )

        # Primary emerald button
        style.configure(
            "Primary.TButton",
            background=PALETTE["accent_dark"],
            foreground="#ECFDF5",
            bordercolor=PALETTE["accent"],
            lightcolor=PALETTE["accent_dark"],
            darkcolor=PALETTE["accent_dark"],
            focusthickness=0,
            padding=(13, 6),
            font=(FONT_UI, 9, "bold"),
        )
        style.map(
            "Primary.TButton",
            background=[("active", PALETTE["accent_hover"]), ("disabled", PALETTE["surface"])],
            foreground=[("disabled", PALETTE["muted"])],
        )

        # Coral stop button
        style.configure(
            "Stop.TButton",
            background=PALETTE["coral_bg"],
            foreground="#FECDD3",
            bordercolor=PALETTE["coral_border"],
            lightcolor=PALETTE["coral_bg"],
            darkcolor=PALETTE["coral_bg"],
            focusthickness=0,
            padding=(12, 6),
            font=(FONT_UI, 9),
        )
        style.map(
            "Stop.TButton",
            background=[("active", "#3F1722"), ("disabled", PALETTE["surface"])],
            foreground=[("disabled", PALETTE["muted"])],
        )

        # Inputs
        style.configure(
            "Field.TEntry",
            fieldbackground=PALETTE["surface_alt"],
            foreground=PALETTE["text"],
            insertcolor=PALETTE["accent"],
            bordercolor=PALETTE["hairline"],
            padding=6,
        )
        style.configure(
            "Field.TCombobox",
            fieldbackground=PALETTE["surface_alt"],
            background=PALETTE["surface_alt"],
            foreground=PALETTE["text"],
            arrowcolor=PALETTE["text_secondary"],
            bordercolor=PALETTE["hairline"],
            padding=5,
        )
        style.map(
            "Field.TCombobox",
            fieldbackground=[("readonly", PALETTE["surface_alt"])],
            selectbackground=[("readonly", PALETTE["surface_alt"])],
            selectforeground=[("readonly", PALETTE["text"])],
        )

        # Clean flat notebook tabs
        style.configure(
            "Clean.TNotebook",
            background=PALETTE["surface"],
            borderwidth=0,
            tabmargins=[0, 0, 0, 4],
        )
        style.configure(
            "Clean.TNotebook.Tab",
            background=PALETTE["surface"],
            foreground=PALETTE["text_secondary"],
            padding=(12, 6),
            borderwidth=0,
            font=(FONT_UI, 9, "bold"),
        )
        style.map(
            "Clean.TNotebook.Tab",
            background=[("selected", PALETTE["surface_alt"]), ("active", PALETTE["surface_hover"])],
            foreground=[("selected", PALETTE["text"]), ("active", PALETTE["text"])],
        )

        # Crisp data table
        style.configure(
            "Work.Treeview",
            background=PALETTE["surface"],
            fieldbackground=PALETTE["surface"],
            foreground=PALETTE["text"],
            bordercolor=PALETTE["hairline"],
            borderwidth=0,
            rowheight=29,
            font=(FONT_UI, 9),
        )
        style.configure(
            "Work.Treeview.Heading",
            background=PALETTE["surface_alt"],
            foreground=PALETTE["text_secondary"],
            bordercolor=PALETTE["hairline"],
            relief="flat",
            font=(FONT_UI, 8, "bold"),
            padding=(8, 7),
        )
        style.map(
            "Work.Treeview.Heading",
            background=[("active", PALETTE["surface_hover"])],
        )
        style.map(
            "Work.Treeview",
            background=[("selected", PALETTE["select_bg"])],
            foreground=[("selected", PALETTE["select_fg"])],
        )

        # Minimal scrollbars
        style.configure(
            "Thin.Vertical.TScrollbar",
            background=PALETTE["surface_alt"],
            troughcolor=PALETTE["surface"],
            bordercolor=PALETTE["surface"],
            arrowcolor=PALETTE["muted"],
            width=10,
        )

    def _build_layout(self):
        shell = tk.Frame(self.root, bg=PALETTE["bg"])
        shell.pack(fill="both", expand=True)

        # --- Left Navigation Rail ---
        self.sidebar = tk.Frame(shell, bg=PALETTE["sidebar"], width=216)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # 1px vertical hairline divider
        tk.Frame(shell, bg=PALETTE["hairline"], width=1).pack(side="left", fill="y")

        brand_row = tk.Frame(self.sidebar, bg=PALETTE["sidebar"], padx=14, pady=16)
        brand_row.pack(fill="x")

        self.logo_canvas = tk.Canvas(
            brand_row, width=24, height=24, bg=PALETTE["sidebar"], highlightthickness=0
        )
        self.logo_canvas.pack(side="left")
        self._draw_logo()

        self.brand_title = tk.Label(
            brand_row,
            text="HashGuard",
            font=(FONT_UI, 12, "bold"),
            bg=PALETTE["sidebar"],
            fg=PALETTE["text"],
        )
        self.brand_title.pack(side="left", padx=(9, 0))

        self.toggle_btn = tk.Button(
            brand_row,
            text="«",
            font=(FONT_UI, 10),
            bg=PALETTE["sidebar"],
            fg=PALETTE["muted"],
            activebackground=PALETTE["surface_hover"],
            activeforeground=PALETTE["text"],
            relief="flat",
            bd=0,
            padx=5,
            pady=1,
            cursor="hand2",
            command=self.toggle_sidebar,
        )
        self.toggle_btn.pack(side="right")

        tk.Frame(self.sidebar, bg=PALETTE["hairline_soft"], height=1).pack(fill="x", padx=12)

        self.nav_label = tk.Label(
            self.sidebar,
            text="WORKSPACE",
            font=(FONT_UI, 8, "bold"),
            bg=PALETTE["sidebar"],
            fg=PALETTE["muted"],
            anchor="w",
        )
        self.nav_label.pack(fill="x", padx=16, pady=(14, 6))

        self.nav_buttons = {}
        nav_specs = [
            ("dashboard", "◉", "Overview"),
            ("processes", "≡", "Processes"),
            ("findings", "⚑", "Findings"),
            ("logs", "⌥", "Session Log"),
        ]
        for key, icon, text in nav_specs:
            btn = tk.Button(
                self.sidebar,
                text=f" {icon}   {text}",
                font=(FONT_UI, 10),
                bg=PALETTE["sidebar"],
                fg=PALETTE["text_secondary"],
                activebackground=PALETTE["surface_hover"],
                activeforeground=PALETTE["text"],
                relief="flat",
                bd=0,
                anchor="w",
                padx=14,
                pady=8,
                cursor="hand2",
                command=lambda k=key: self.switch_view(k),
            )
            btn.pack(fill="x", padx=10, pady=2)
            btn.bind("<Enter>", lambda _, b=btn, k=key: self._on_nav_hover(b, k, True))
            btn.bind("<Leave>", lambda _, b=btn, k=key: self._on_nav_hover(b, k, False))
            self.nav_buttons[key] = (btn, icon, text)

        # Sidebar bottom session readout
        side_foot = tk.Frame(self.sidebar, bg=PALETTE["sidebar"], padx=14, pady=14)
        side_foot.pack(side="bottom", fill="x")
        tk.Frame(self.sidebar, bg=PALETTE["hairline_soft"], height=1).pack(side="bottom", fill="x", padx=12)

        self.side_mode_lbl = tk.Label(
            side_foot,
            text="IDLE",
            font=(FONT_MONO, 8, "bold"),
            bg=PALETTE["sidebar"],
            fg=PALETTE["muted"],
            anchor="w",
        )
        self.side_mode_lbl.pack(fill="x")
        self.meter = tk.Label(
            side_foot,
            text="Select Live or Demo to start.",
            font=(FONT_UI, 8),
            bg=PALETTE["sidebar"],
            fg=PALETTE["text_secondary"],
            anchor="w",
            wraplength=186,
            justify="left",
        )
        self.meter.pack(fill="x", pady=(4, 0))

        # --- Main Workstation Column ---
        main_col = tk.Frame(shell, bg=PALETTE["bg"])
        main_col.pack(side="left", fill="both", expand=True)

        # Clean command bar header
        header = tk.Frame(main_col, bg=PALETTE["bg"], padx=20, pady=14)
        header.pack(fill="x")

        title_box = tk.Frame(header, bg=PALETTE["bg"])
        title_box.pack(side="left")
        self.page_title = tk.Label(
            title_box,
            text="Cryptojacking Detector",
            font=(FONT_UI, 15, "bold"),
            bg=PALETTE["bg"],
            fg=PALETTE["text"],
        )
        self.page_title.pack(anchor="w")
        self.page_subtitle = tk.Label(
            title_box,
            text="Process resource telemetry, mining pool peer inspection & binary verification",
            font=(FONT_UI, 9),
            bg=PALETTE["bg"],
            fg=PALETTE["muted"],
        )
        self.page_subtitle.pack(anchor="w", pady=(1, 0))

        ctrl_box = tk.Frame(header, bg=PALETTE["bg"])
        ctrl_box.pack(side="right")

        self.mode_pill = tk.Label(
            ctrl_box,
            text="● READY",
            font=(FONT_MONO, 8, "bold"),
            bg=PALETTE["surface_alt"],
            fg=PALETTE["text_secondary"],
            padx=10,
            pady=5,
        )
        self.mode_pill.pack(side="left", padx=(0, 12))
        self.mode_label = self.mode_pill

        self.go_live = ttk.Button(
            ctrl_box,
            text="Start Live",
            style="Primary.TButton",
            command=lambda: self.start("Live"),
        )
        self.go_demo = ttk.Button(
            ctrl_box,
            text="Run Demo",
            style="Ghost.TButton",
            command=lambda: self.start("Demo"),
        )
        self.halt = ttk.Button(
            ctrl_box,
            text="Stop",
            style="Stop.TButton",
            command=self.cancel,
            state="disabled",
        )
        self.go_live.pack(side="left", padx=3)
        self.go_demo.pack(side="left", padx=3)
        self.halt.pack(side="left", padx=(3, 0))

        tk.Frame(main_col, bg=PALETTE["hairline"], height=1).pack(fill="x")

        # Page container
        self.pages = {}
        self.page_host = tk.Frame(main_col, bg=PALETTE["bg"])
        self.page_host.pack(fill="both", expand=True, padx=18, pady=14)

        self._build_dashboard_page()
        self._build_processes_page()
        self._build_findings_page()
        self._build_logs_page()

        # Minimal bottom status strip
        tk.Frame(main_col, bg=PALETTE["hairline"], height=1).pack(fill="x", side="bottom")
        status_bar = tk.Frame(main_col, bg=PALETTE["sidebar"], padx=18, pady=6)
        status_bar.pack(fill="x", side="bottom")
        self.status = tk.StringVar(value="Ready")
        tk.Label(
            status_bar,
            textvariable=self.status,
            font=(FONT_MONO, 8),
            bg=PALETTE["sidebar"],
            fg=PALETTE["text_secondary"],
            anchor="w",
        ).pack(fill="x")

        self._refresh_nav_styles()
        self.switch_view("dashboard")

    def _draw_logo(self):
        c = self.logo_canvas
        c.delete("all")
        # Minimal geometric hash-shield mark
        c.create_rectangle(3, 3, 21, 21, outline=PALETTE["accent"], width=1.6, fill="#111C18")
        c.create_line(9, 7, 9, 17, fill=PALETTE["text"], width=1.5)
        c.create_line(15, 7, 15, 17, fill=PALETTE["text"], width=1.5)
        c.create_line(7, 10, 17, 10, fill=PALETTE["accent"], width=1.5)
        c.create_line(7, 14, 17, 14, fill=PALETTE["accent"], width=1.5)

    def toggle_sidebar(self):
        self.sidebar_expanded = not self.sidebar_expanded
        if self.sidebar_expanded:
            self.sidebar.configure(width=216)
            self.brand_title.pack(side="left", padx=(9, 0))
            self.nav_label.pack(fill="x", padx=16, pady=(14, 6))
            self.side_mode_lbl.pack(fill="x")
            self.meter.pack(fill="x", pady=(4, 0))
            self.toggle_btn.configure(text="«")
            for btn, icon, text in self.nav_buttons.values():
                btn.configure(text=f" {icon}   {text}", padx=14)
        else:
            self.sidebar.configure(width=58)
            self.brand_title.pack_forget()
            self.nav_label.pack_forget()
            self.side_mode_lbl.pack_forget()
            self.meter.pack_forget()
            self.toggle_btn.configure(text="»")
            for btn, icon, _ in self.nav_buttons.values():
                btn.configure(text=icon, padx=0)

    def _on_nav_hover(self, btn, key, entering):
        if key == self.active_nav:
            return
        btn.configure(
            bg=PALETTE["surface_hover"] if entering else PALETTE["sidebar"],
            fg=PALETTE["text"] if entering else PALETTE["text_secondary"],
        )

    def _refresh_nav_styles(self):
        for key, (btn, icon, text) in self.nav_buttons.items():
            selected = key == self.active_nav
            btn.configure(
                bg=PALETTE["surface_alt"] if selected else PALETTE["sidebar"],
                fg=PALETTE["text"] if selected else PALETTE["text_secondary"],
                font=(FONT_UI, 10, "bold" if selected else "normal"),
            )
            if self.sidebar_expanded:
                btn.configure(text=f" {icon}   {text}")
            else:
                btn.configure(text=icon)

    def switch_view(self, key):
        self.active_nav = key
        self._refresh_nav_styles()
        for k, page in self.pages.items():
            if k == key:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
        if key == "dashboard":
            self._redraw_chart()

    def _build_dashboard_page(self):
        page = tk.Frame(self.page_host, bg=PALETTE["bg"])
        self.pages["dashboard"] = page

        # Unified Telemetry Strip (replaces generic 4-card AI grid)
        strip = tk.Frame(
            page,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
        )
        strip.pack(fill="x", pady=(0, 12))

        self.stat_procs_val = tk.StringVar(value="—")
        self.stat_procs_sub = tk.StringVar(value="Awaiting mode")
        self.stat_find_val = tk.StringVar(value="0")
        self.stat_find_sub = tk.StringVar(value="0 mining · 0 review")
        self.stat_cpu_val = tk.StringVar(value="0.0%")
        self.stat_cpu_sub = tk.StringVar(value="Busiest process")
        self.stat_env_val = tk.StringVar(value="—")
        self.stat_env_sub = tk.StringVar(value="Idle & GPU status")

        segments = [
            ("ACTIVE PROCESSES", self.stat_procs_val, self.stat_procs_sub, PALETTE["text"]),
            ("RECORDED FINDINGS", self.stat_find_val, self.stat_find_sub, PALETTE["coral"]),
            ("PEAK PROCESS CPU", self.stat_cpu_val, self.stat_cpu_sub, PALETTE["accent"]),
            ("HOST TELEMETRY", self.stat_env_val, self.stat_env_sub, PALETTE["amber"]),
        ]

        for idx, (label, v_var, s_var, color) in enumerate(segments):
            cell = tk.Frame(strip, bg=PALETTE["surface"], padx=16, pady=10)
            cell.pack(side="left", fill="both", expand=True)
            tk.Label(
                cell,
                text=label,
                font=(FONT_UI, 7, "bold"),
                bg=PALETTE["surface"],
                fg=PALETTE["muted"],
                anchor="w",
            ).pack(fill="x")

            row = tk.Frame(cell, bg=PALETTE["surface"])
            row.pack(fill="x", pady=(3, 0))
            tk.Label(
                row,
                textvariable=v_var,
                font=(FONT_MONO, 14, "bold"),
                bg=PALETTE["surface"],
                fg=color,
            ).pack(side="left")
            tk.Label(
                row,
                textvariable=s_var,
                font=(FONT_UI, 8),
                bg=PALETTE["surface"],
                fg=PALETTE["text_secondary"],
            ).pack(side="left", padx=(8, 0), pady=(3, 0))

            if idx < len(segments) - 1:
                tk.Frame(strip, bg=PALETTE["hairline"], width=1).pack(side="left", fill="y", pady=8)

        # Compact CPU Sparkline Panel
        chart_card = tk.Frame(
            page,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=14,
            pady=10,
        )
        chart_card.pack(fill="x", pady=(0, 12))

        chart_hdr = tk.Frame(chart_card, bg=PALETTE["surface"])
        chart_hdr.pack(fill="x", pady=(0, 6))
        tk.Label(
            chart_hdr,
            text="CPU LOAD TIMELINE  ·  BUSIEST PROCESS",
            font=(FONT_UI, 8, "bold"),
            bg=PALETTE["surface"],
            fg=PALETTE["text_secondary"],
        ).pack(side="left")
        self.chart_meta_lbl = tk.Label(
            chart_hdr,
            text="No samples",
            font=(FONT_MONO, 8),
            bg=PALETTE["surface"],
            fg=PALETTE["accent"],
        )
        self.chart_meta_lbl.pack(side="right")

        self.graph = tk.Canvas(
            chart_card,
            background=PALETTE["bg"],
            height=96,
            highlightthickness=1,
            highlightbackground=PALETTE["hairline_soft"],
        )
        self.graph.pack(fill="x")
        self.graph.bind("<Configure>", lambda _e: self._redraw_chart())

        # Split bottom workspace: left = processes/findings, right = evidence inspector
        split = tk.PanedWindow(
            page,
            orient="horizontal",
            sashwidth=8,
            sashrelief="flat",
            bg=PALETTE["bg"],
            bd=0,
        )
        split.pack(fill="both", expand=True)

        left_card = tk.Frame(
            split,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        right_card = tk.Frame(
            split,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=14,
            pady=10,
        )
        split.add(left_card, stretch="always", minsize=440)
        split.add(right_card, stretch="always", minsize=340)

        tabs = ttk.Notebook(left_card, style="Clean.TNotebook")
        tabs.pack(fill="both", expand=True)
        running_tab = tk.Frame(tabs, bg=PALETTE["surface"], pady=6)
        history_tab = tk.Frame(tabs, bg=PALETTE["surface"], pady=6)
        tabs.add(running_tab, text="Live Processes")
        tabs.add(history_tab, text="Findings")
        self.tabs = tabs

        self.processes = self._make_table(
            running_tab,
            ("Process", "PID", "CPU %", "GPU %"),
            (200, 75, 80, 80),
        )
        proc_bar = tk.Frame(running_tab, bg=PALETTE["surface"])
        proc_bar.pack(fill="x", pady=(8, 0))
        ttk.Button(
            proc_bar,
            text="Inspect Process",
            style="Primary.TButton",
            command=self.inspect,
        ).pack(side="left")
        ttk.Button(
            proc_bar,
            text="Expand View",
            style="Ghost.TButton",
            command=lambda: self.switch_view("processes"),
        ).pack(side="left", padx=(6, 0))
        self.processes.bind("<Double-1>", lambda _: self.inspect())

        self.history = self._make_table(
            history_tab,
            ("Time", "Process", "Verdict"),
            (82, 165, 155),
        )
        self.history.bind("<<TreeviewSelect>>", self.choose)
        hist_bar = tk.Frame(history_tab, bg=PALETTE["surface"])
        hist_bar.pack(fill="x", pady=(8, 0))
        ttk.Button(
            hist_bar,
            text="Search & Filter Findings",
            style="Ghost.TButton",
            command=lambda: self.switch_view("findings"),
        ).pack(side="left")

        # Evidence Inspector on right
        ev_hdr = tk.Frame(right_card, bg=PALETTE["surface"])
        ev_hdr.pack(fill="x", pady=(0, 8))
        tk.Label(
            ev_hdr,
            text="EVIDENCE INSPECTOR",
            font=(FONT_UI, 8, "bold"),
            bg=PALETTE["surface"],
            fg=PALETTE["text_secondary"],
        ).pack(side="left")

        box = tk.Frame(
            right_card,
            bg=PALETTE["bg"],
            highlightbackground=PALETTE["hairline_soft"],
            highlightthickness=1,
        )
        box.pack(fill="both", expand=True)
        self.detail = self._create_evidence_text(box)
        self.write_detail("Select a finding from the list to inspect its forensic evidence.")

        actions = tk.Frame(right_card, bg=PALETTE["surface"])
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            actions,
            text="Review Actions…",
            style="Ghost.TButton",
            command=self.actions,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Quarantine Demo…",
            style="Ghost.TButton",
            command=self.training,
        ).pack(side="left", padx=(6, 0))

    def _create_evidence_text(self, parent):
        txt = tk.Text(
            parent,
            wrap="word",
            relief="flat",
            bg=PALETTE["bg"],
            fg=PALETTE["text"],
            insertbackground=PALETTE["accent"],
            selectbackground=PALETTE["select_bg"],
            selectforeground=PALETTE["select_fg"],
            padx=14,
            pady=12,
            font=(FONT_MONO, 9),
            width=34,
        )
        scroll = ttk.Scrollbar(parent, style="Thin.Vertical.TScrollbar", command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)

        # Syntax highlight tags for crisp scannability
        txt.tag_configure("verdict_danger", foreground=PALETTE["coral"], font=(FONT_MONO, 9, "bold"))
        txt.tag_configure("verdict_warn", foreground=PALETTE["amber"], font=(FONT_MONO, 9, "bold"))
        txt.tag_configure("verdict_neutral", foreground=PALETTE["indigo"], font=(FONT_MONO, 9, "bold"))
        txt.tag_configure("title", foreground=PALETTE["text"], font=(FONT_UI, 11, "bold"))
        txt.tag_configure("mono_accent", foreground=PALETTE["accent"], font=(FONT_MONO, 9, "bold"))
        txt.tag_configure("path", foreground=PALETTE["text_secondary"], font=(FONT_MONO, 8))
        txt.tag_configure("section", foreground=PALETTE["text"], font=(FONT_UI, 9, "bold"))
        txt.tag_configure("key", foreground=PALETTE["muted"], font=(FONT_MONO, 9))
        txt.tag_configure("val", foreground=PALETTE["text"], font=(FONT_MONO, 9))
        txt.tag_configure("bullet", foreground=PALETTE["text"], font=(FONT_MONO, 9))
        txt.tag_configure("muted", foreground=PALETTE["muted"], font=(FONT_MONO, 9))
        txt.tag_configure("ok", foreground=PALETTE["accent"], font=(FONT_MONO, 9, "bold"))
        return txt

    def _render_evidence_to_widget(self, widget, item_or_msg):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if isinstance(item_or_msg, dict):
            for tag, chunk in format_evidence_sections(item_or_msg):
                widget.insert("end", chunk, tag)
        else:
            widget.insert("end", str(item_or_msg), "muted")
        widget.configure(state="disabled")

    def _build_processes_page(self):
        page = tk.Frame(self.page_host, bg=PALETTE["bg"])
        self.pages["processes"] = page

        card = tk.Frame(
            page,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        card.pack(fill="both", expand=True)

        top = tk.Frame(card, bg=PALETTE["surface"])
        top.pack(fill="x", pady=(0, 10))
        tk.Label(
            top,
            text="PROCESS SNAPSHOT",
            font=(FONT_UI, 10, "bold"),
            bg=PALETTE["surface"],
            fg=PALETTE["text"],
        ).pack(side="left")

        self.proc_search_var = tk.StringVar()
        self.proc_search_var.trace_add("write", lambda *_: self._refresh_proc_view_table())
        ttk.Entry(top, textvariable=self.proc_search_var, style="Field.TEntry", width=26).pack(side="right")
        tk.Label(
            top,
            text="Filter:",
            font=(FONT_UI, 9),
            bg=PALETTE["surface"],
            fg=PALETTE["text_secondary"],
        ).pack(side="right", padx=(0, 8))

        self.proc_full_table = self._make_table(
            card,
            ("Process", "PID", "CPU %", "GPU %"),
            (280, 95, 110, 110),
        )
        self.proc_full_table.bind("<Double-1>", lambda _: self._inspect_from_full_table())

        bar = tk.Frame(card, bg=PALETTE["surface"])
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(
            bar,
            text="Inspect Selected Process",
            style="Primary.TButton",
            command=self._inspect_from_full_table,
        ).pack(side="left")

    def _build_findings_page(self):
        page = tk.Frame(self.page_host, bg=PALETTE["bg"])
        self.pages["findings"] = page

        split = tk.PanedWindow(
            page,
            orient="horizontal",
            sashwidth=8,
            sashrelief="flat",
            bg=PALETTE["bg"],
            bd=0,
        )
        split.pack(fill="both", expand=True)

        left = tk.Frame(
            split,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=14,
            pady=14,
        )
        right = tk.Frame(
            split,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=14,
            pady=14,
        )
        split.add(left, stretch="always", minsize=460)
        split.add(right, stretch="always", minsize=340)

        flt = tk.Frame(left, bg=PALETTE["surface"])
        flt.pack(fill="x", pady=(0, 10))
        self.finding_search_var = tk.StringVar()
        self.finding_search_var.trace_add("write", lambda *_: self._refresh_findings_filter())
        ttk.Entry(flt, textvariable=self.finding_search_var, style="Field.TEntry", width=22).pack(side="left")

        self.finding_verdict_var = tk.StringVar(value="All")
        verdict_box = ttk.Combobox(
            flt,
            textvariable=self.finding_verdict_var,
            state="readonly",
            values=("All", "Mining indicators", "Sustained load", "Process review"),
            style="Field.TCombobox",
            width=18,
        )
        verdict_box.pack(side="left", padx=(8, 0))
        verdict_box.bind("<<ComboboxSelected>>", lambda _e: self._refresh_findings_filter())

        self.findings_filtered_table = self._make_table(
            left,
            ("Time", "Process", "PID", "Verdict", "Mode"),
            (82, 150, 65, 135, 68),
        )
        self.findings_filtered_table.bind("<<TreeviewSelect>>", self._on_filtered_finding_select)

        tk.Label(
            right,
            text="DETAILED EVIDENCE",
            font=(FONT_UI, 8, "bold"),
            bg=PALETTE["surface"],
            fg=PALETTE["text_secondary"],
        ).pack(anchor="w", pady=(0, 8))

        ev_box = tk.Frame(
            right,
            bg=PALETTE["bg"],
            highlightbackground=PALETTE["hairline_soft"],
            highlightthickness=1,
        )
        ev_box.pack(fill="both", expand=True)
        self.findings_detail = self._create_evidence_text(ev_box)
        self._write_findings_detail("Select a finding to view complete evidence.")

        f_actions = tk.Frame(right, bg=PALETTE["surface"])
        f_actions.pack(fill="x", pady=(10, 0))
        ttk.Button(f_actions, text="Review Actions…", style="Ghost.TButton", command=self.actions).pack(side="left")
        ttk.Button(f_actions, text="Quarantine Demo…", style="Ghost.TButton", command=self.training).pack(side="left", padx=(6, 0))

    def _build_logs_page(self):
        page = tk.Frame(self.page_host, bg=PALETTE["bg"])
        self.pages["logs"] = page

        card = tk.Frame(
            page,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["hairline"],
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text="SESSION ACTIVITY & PERSISTENCE",
            font=(FONT_UI, 10, "bold"),
            bg=PALETTE["surface"],
            fg=PALETTE["text"],
        ).pack(anchor="w")
        tk.Label(
            card,
            text="Findings persist automatically to CSV and JSONL beside detector.py (alerts, process_reviews, demo_alerts). Trust approvals store in %LOCALAPPDATA%\\CryptojackingDetector\\review.sqlite3.",
            font=(FONT_UI, 9),
            bg=PALETTE["surface"],
            fg=PALETTE["text_secondary"],
            wraplength=820,
            justify="left",
        ).pack(anchor="w", pady=(3, 10))

        log_box = tk.Frame(
            card,
            bg=PALETTE["bg"],
            highlightbackground=PALETTE["hairline_soft"],
            highlightthickness=1,
        )
        log_box.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            log_box,
            wrap="word",
            relief="flat",
            bg=PALETTE["bg"],
            fg=PALETTE["text_secondary"],
            padx=12,
            pady=10,
            font=(FONT_MONO, 9),
            state="disabled",
        )
        l_scroll = ttk.Scrollbar(log_box, style="Thin.Vertical.TScrollbar", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=l_scroll.set)
        l_scroll.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)

        act = tk.Frame(card, bg=PALETTE["surface"])
        act.pack(fill="x", pady=(10, 0))
        ttk.Button(act, text="Review Actions…", style="Ghost.TButton", command=self.actions).pack(side="left")
        ttk.Button(act, text="Quarantine Demo…", style="Ghost.TButton", command=self.training).pack(side="left", padx=(6, 0))

    def _append_log(self, msg):
        if not msg:
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"› {msg.rstrip()}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    @staticmethod
    def _make_table(parent, columns, widths):
        frame = tk.Frame(parent, bg=PALETTE["surface"])
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Work.Treeview",
        )
        for col, width in zip(columns, widths):
            tree.heading(col, text=col.upper())
            anchor = "e" if "%" in col or col == "PID" else "w"
            tree.column(col, width=width, minwidth=48, anchor=anchor)

        # Zebra striping & semantic verdict tags
        tree.tag_configure("odd", background="#161920")
        tree.tag_configure("even", background=PALETTE["surface"])
        tree.tag_configure("verdict_danger", foreground=PALETTE["coral"], background="#1E1418")
        tree.tag_configure("verdict_warn", foreground=PALETTE["amber"], background="#1D1913")

        v_scroll = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=tree.yview)
        tree.configure(yscrollcommand=v_scroll.set)
        v_scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    def write_detail(self, item_or_msg):
        self._render_evidence_to_widget(self.detail, item_or_msg)

    def _write_findings_detail(self, item_or_msg):
        self._render_evidence_to_widget(self.findings_detail, item_or_msg)

    def _set_status(self, text):
        self.status.set(text)
        self._append_log(text)

    def _update_mode_pill(self, mode):
        if mode == "Live":
            fg, bg = PALETTE["accent"], "#102820"
        elif mode == "Demo":
            fg, bg = PALETTE["amber"], "#261E11"
        else:
            fg, bg = PALETTE["text_secondary"], PALETTE["surface_alt"]
        self.mode_pill.configure(text=f"● {mode.upper()}", fg=fg, bg=bg)
        self.side_mode_lbl.configure(text=f"STATE · {mode.upper()}", fg=fg)

    def _update_finding_card(self):
        total = len(self.finding_items)
        mining = sum(1 for it in self.finding_items if it.get("verdict") == "Mining indicators")
        other = total - mining
        self.stat_find_val.set(str(total))
        self.stat_find_sub.set(f"{mining} mining · {other} review")

    def start(self, mode):
        if self.worker and self.worker.is_alive():
            return
        self.session += 1
        ticket = self.session
        self.mode = mode
        self.stop = threading.Event()
        stop = self.stop
        self.findings.clear()
        self.finding_items.clear()
        self.all_rows = []
        self.rows.clear()
        self.selected_item = None
        self.last_idle = None
        self.last_gpu_status = "Awaiting telemetry"
        self.last_peak_cpu = 0.0
        self.series.clear()
        self.graph.delete("all")
        for tree in (self.history, self.processes, self.proc_full_table, self.findings_filtered_table):
            tree.delete(*tree.get_children())
        self.tabs.select(0)
        self.write_detail("Select a finding from the list to inspect its forensic evidence.")
        self._write_findings_detail("Select a finding to view complete evidence.")
        self.stat_procs_val.set("—")
        self.stat_procs_sub.set("Collecting…")
        self.stat_cpu_val.set("0.0%")
        self.stat_cpu_sub.set("Busiest process")
        self.stat_env_val.set("—")
        self.stat_env_sub.set("Awaiting telemetry")
        self._update_finding_card()
        self._redraw_chart()
        self.live = None
        self._update_mode_pill(mode)
        self._set_status("Sampling live process telemetry…" if mode == "Live" else "Running offline college demo stream…")
        self.go_live.configure(state="disabled")
        self.go_demo.configure(state="disabled")
        self.halt.configure(state="normal")

        def emit(kind, data):
            self.events.put((ticket, kind, data))

        def work():
            try:
                if mode == "Demo":
                    demo(emit, stop, .15)
                else:
                    self.live = Live(emit, stop)
                    self.live.run()
            except Exception as exc:
                emit("status", f"Could not run {mode.lower()}: {exc}")
            finally:
                stop.set()
                emit("finished", None)

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def cancel(self):
        self.stop.set()
        self._update_mode_pill("Stopped")
        self._set_status("Monitoring stopped.")
        self.halt.configure(state="disabled")

    def close(self):
        self.stop.set()
        self.root.destroy()

    def draw_snapshot(self, rows, idle, gpu_status):
        self.all_rows = list(rows)
        self.last_idle = idle
        self.last_gpu_status = gpu_status

        old = self.processes.selection()
        self.rows = {f"{r['pid']}_{r['born']}": r for r in rows}
        for key in self.processes.get_children():
            if key not in self.rows:
                self.processes.delete(key)
        for pos, (key, r) in enumerate(self.rows.items()):
            vals = (r["name"], r["pid"], r["cpu"], "—" if r["gpu"] is None else r["gpu"])
            row_tag = ("odd",) if pos % 2 else ("even",)
            if self.processes.exists(key):
                self.processes.item(key, values=vals, tags=row_tag)
                self.processes.move(key, "", pos)
            else:
                self.processes.insert("", "end", iid=key, values=vals, tags=row_tag)
        if old and old[0] in self.rows:
            self.processes.selection_set(old[0])

        self._refresh_proc_view_table()

        idle_text = "" if idle is None else f" · Idle {idle:.0f}s"
        self.meter.configure(text=f"{len(rows)} procs · {gpu_status}{idle_text}")
        peak = max((r["cpu"] for r in rows), default=0.0)
        self.last_peak_cpu = peak
        self.series.append(peak)

        self.stat_procs_val.set(str(len(rows)))
        self.stat_procs_sub.set(self.mode)
        self.stat_cpu_val.set(f"{peak:.1f}%")
        self.stat_cpu_sub.set("1 logical CPU")
        idle_sub = "Idle N/A" if idle is None else f"Idle {idle:.0f}s"
        self.stat_env_val.set(gpu_status.split(" · ")[0])
        self.stat_env_sub.set(idle_sub)

        self._redraw_chart()

    def _redraw_chart(self):
        if not hasattr(self, "graph"):
            return
        width = max(240, self.graph.winfo_width())
        height = max(70, self.graph.winfo_height())
        self.graph.delete("all")

        pad_l, pad_r, pad_t, pad_b = 14, 14, 12, 12
        plot_w = max(40, width - pad_l - pad_r)
        plot_h = max(30, height - pad_t - pad_b)

        for frac in (0.25, 0.5, 0.75):
            gy = pad_t + plot_h * frac
            self.graph.create_line(pad_l, gy, width - pad_r, gy, fill=PALETTE["hairline_soft"], dash=(2, 4))

        if not self.series:
            self.chart_meta_lbl.configure(text="No samples")
            self.graph.create_text(
                width / 2,
                height / 2,
                text="Awaiting CPU readings…",
                fill=PALETTE["muted"],
                font=(FONT_UI, 9),
            )
            return

        ceiling = max(100.0, max(self.series))
        n_pts = len(self.series)
        pts = []
        for i, v in enumerate(self.series):
            x = pad_l if n_pts == 1 else pad_l + i * plot_w / (n_pts - 1)
            y = pad_t + plot_h - (plot_h * v / ceiling)
            pts.append((x, y))

        if len(pts) >= 2:
            poly = [pad_l, pad_t + plot_h]
            for x, y in pts:
                poly.extend([x, y])
            poly.extend([pts[-1][0], pad_t + plot_h])
            self.graph.create_polygon(poly, fill="#11241D", outline="")
            self.graph.create_line(
                *[coord for pt in pts for coord in pt],
                fill=PALETTE["accent"],
                width=2,
            )

        last_x, last_y = pts[-1]
        self.graph.create_oval(
            last_x - 3.5, last_y - 3.5, last_x + 3.5, last_y + 3.5,
            fill=PALETTE["accent"], outline=PALETTE["text"]
        )
        self.chart_meta_lbl.configure(
            text=f"PEAK {self.last_peak_cpu:.1f}%  ·  0–{ceiling:.0f}%  ·  {n_pts} SAMPLES"
        )

    def _refresh_proc_view_table(self):
        if not hasattr(self, "proc_full_table"):
            return
        query = self.proc_search_var.get().strip().lower() if hasattr(self, "proc_search_var") else ""
        filtered = [
            r for r in self.all_rows
            if not query or query in str(r["name"]).lower() or query in str(r["pid"])
        ]
        self.proc_full_table.delete(*self.proc_full_table.get_children())
        for pos, r in enumerate(filtered):
            key = f"{r['pid']}_{r['born']}"
            vals = (r["name"], r["pid"], r["cpu"], "—" if r["gpu"] is None else r["gpu"])
            row_tag = ("odd",) if pos % 2 else ("even",)
            self.proc_full_table.insert("", "end", iid=key, values=vals, tags=row_tag)

    def _inspect_from_full_table(self):
        ids = self.proc_full_table.selection()
        if ids and ids[0] in self.rows:
            self.processes.selection_set(ids[0])
        self.inspect()

    @staticmethod
    def _verdict_tag(verdict):
        if verdict == "Mining indicators":
            return ("verdict_danger",)
        if verdict == "Sustained load":
            return ("verdict_warn",)
        return ("even",)

    def _refresh_findings_filter(self):
        if not hasattr(self, "findings_filtered_table"):
            return
        query = self.finding_search_var.get().strip().lower()
        verdict = self.finding_verdict_var.get()
        self.findings_filtered_table.delete(*self.findings_filtered_table.get_children())
        for idx, item in enumerate(reversed(self.finding_items)):
            if verdict != "All" and item.get("verdict") != verdict:
                continue
            haystack = f"{item.get('name', '')} {item.get('pid', '')} {item.get('verdict', '')} {item.get('path', '')}".lower()
            if query and query not in haystack:
                continue
            iid = f"f_{idx}"
            self.findings_filtered_table.insert(
                "",
                "end",
                iid=iid,
                values=(
                    item.get("time", "")[11:19],
                    item.get("name", ""),
                    item.get("pid", ""),
                    item.get("verdict", ""),
                    item.get("mode", ""),
                ),
                tags=self._verdict_tag(item.get("verdict")),
            )

    def _on_filtered_finding_select(self, _=None):
        ids = self.findings_filtered_table.selection()
        if not ids:
            return
        try:
            rev_idx = int(ids[0].split("_", 1)[1])
            item = list(reversed(self.finding_items))[rev_idx]
        except (IndexError, ValueError):
            return
        self.selected_item = item
        self._write_findings_detail(item)
        self.write_detail(item)

    def inspect(self):
        ids = self.processes.selection()
        if self.mode != "Live" or self.stop.is_set() or not self.live:
            self._set_status("Start live monitoring to inspect an actual process.")
        elif ids and ids[0] in self.rows:
            row = self.rows[ids[0]]
            self.live.request(row, idle=idle_seconds())
            self._set_status(f"Review queued for {row['name']}. Results appear under Findings.")
        else:
            self._set_status("Select a process from the list.")

    def choose(self, _=None):
        ids = self.history.selection()
        if ids and ids[0] in self.findings:
            self.selected_item = self.findings[ids[0]]
            self.write_detail(self.selected_item)
            self._write_findings_detail(self.selected_item)

    def drain(self):
        try:
            while True:
                ticket, kind, data = self.events.get_nowait()
                if ticket != self.session:
                    continue
                if kind == "snapshot":
                    self.draw_snapshot(*data)
                elif kind == "finding":
                    key = self.history.insert(
                        "",
                        0,
                        values=(data["time"][11:19], data["name"], data["verdict"]),
                        tags=self._verdict_tag(data["verdict"]),
                    )
                    self.findings[key] = data
                    self.finding_items.append(data)
                    self._update_finding_card()
                    self._refresh_findings_filter()
                    self.history.selection_set(key)
                    self.choose()
                    self._set_status(f"{data['verdict']} · {data['name']} · See Findings")
                elif kind == "status":
                    self._set_status(data)
                elif kind == "finished":
                    self.halt.configure(state="disabled")
                    self.go_live.configure(state="normal")
                    self.go_demo.configure(state="normal")
                    if self.mode == "Demo" and self.findings:
                        self.tabs.select(1)
        except queue.Empty:
            pass
        self.root.after(70, self.drain)

    def training(self):
        try:
            if not self.sample:
                self.sample = DemoSample()
            restore = self.sample.isolated.exists()
            verb = "Restore" if restore else "Quarantine"
            if messagebox.askokcancel(f"{verb} demo sample", f"{verb} the app-created text sample?\n\n{self.sample.folder}"):
                path = self.sample.move(restore)
                messagebox.showinfo("Demo sample", f"Sample is now at\n\n{path}")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Demo sample", str(exc))

    def actions(self):
        item = self.selected_item
        if not item or item["mode"] != "Live":
            messagebox.showinfo("Review actions", "Select a live finding or inspect a live process first. Use Quarantine demo for training.")
            return
        window = tk.Toplevel(self.root)
        window.title("Review actions")
        window.configure(bg=PALETTE["surface"])
        panel = ttk.Frame(window, style="Card.TFrame", padding=16)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text=f"{item['name']} · PID {item['pid']}", style="Card.TFrame", font=(FONT_UI, 12, "bold")).pack(anchor="w")
        ttk.Label(panel, text=item["path"] or "Path unavailable", style="Card.TFrame", wraplength=480).pack(anchor="w", pady=6)

        def button(label, action):
            def run():
                try:
                    action()
                except Exception as exc:
                    messagebox.showerror(label, str(exc), parent=window)
            ttk.Button(panel, text=label, style="Ghost.TButton", command=run).pack(fill="x", pady=3)

        def change_trust():
            enable = not item["trusted"]
            trust(item, enable)
            item["trusted"] = enable
            self.choose()
            window.destroy()

        if item.get("digest"):
            button("Remove app approval" if item["trusted"] else "Approve this file hash", change_trust)
        if os.name == "nt":
            button("Scan selected file with Defender…", lambda: self.scan(item))
            button("End selected process…", lambda: self.end_process(item))
            button("Open Windows Security", lambda: os.startfile("windowsdefender://threat/"))
            if item["startup"]:
                button("Review matching startup entries…", lambda: self.startup_review(item))

    def startup_review(self, item):
        win = tk.Toplevel(self.root)
        win.title("Matching startup entries")
        win.configure(bg=PALETTE["surface"])
        panel = ttk.Frame(win, style="Card.TFrame", padding=14)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="\n".join(item["startup"]), style="Card.TFrame", wraplength=600).pack(anchor="w")
        ttk.Label(panel, text="Review the target path in the corresponding Windows tool before changing a startup entry.", style="Card.TFrame", wraplength=500).pack(pady=8)
        system = Path(os.environ["SystemRoot"])
        selection = ttk.Combobox(panel, state="readonly", values=item["startup"], style="Field.TCombobox", width=65)
        selection.pack(fill="x", pady=4)
        selection.current(0)

        def disable():
            entry = selection.get()
            try:
                path = Path(item["path"]).resolve()
                if (not item.get("digest") or file_hash(path) != item["digest"]
                        or path.is_relative_to(system.resolve())):
                    raise ValueError("Target is protected or changed. Inspect it again.")
                if not messagebox.askyesno("Disable startup entry",
                        "Disable this exact entry? A task or service will be disabled. A Run value will be backed up and removed.\n\n" + entry,
                        parent=win):
                    return
                message = powershell("disable-startup", path, 45, entry)
                messagebox.showinfo("Startup review", message, parent=win)
            except Exception as exc:
                messagebox.showerror("Startup review", str(exc), parent=win)

        ttk.Button(panel, text="Disable selected startup entry…", style="Ghost.TButton", command=disable).pack(fill="x")
        for label, filename, arg in [
            ("Task Scheduler", "System32/mmc.exe", "taskschd.msc"),
            ("Services", "System32/mmc.exe", "services.msc"),
            ("Registry Editor", "regedit.exe", ""),
        ]:
            cmd = [str(system / filename)]
            if arg:
                cmd.append(str(system / "System32" / arg))
            ttk.Button(panel, text=label, style="Ghost.TButton", command=lambda command=cmd: subprocess.Popen(command)).pack(fill="x", pady=2)

    def scan(self, item):
        if not item.get("digest") or file_hash(item["path"]) != item["digest"]:
            raise ValueError("File identity unavailable or changed. Inspect again.")
        if not messagebox.askyesno("Microsoft Defender", "Scan this file? Defender can quarantine threats according to your Windows settings.\n\n" + item["path"]):
            return
        ticket = self.session

        def run():
            try:
                text = powershell("scan", item["path"], timeout=240)
            except Exception as exc:
                text = f"Defender scan status unavailable. Check Windows Security. {exc}"
            self.events.put((ticket, "status", text))

        threading.Thread(target=run, daemon=True).start()
        self._set_status("Defender scan requested. Review Protection history for results.")

    def end_process(self, item):
        import psutil
        p = psutil.Process(item["pid"])
        path = Path(p.exe()).resolve()
        if p.create_time() != item["born"] or not item.get("digest") or file_hash(path) != item["digest"]:
            raise ValueError("Process identity or file changed. Inspect again.")
        if (p.pid in {0, 4, os.getpid()} or path.is_relative_to(Path(os.environ["SystemRoot"]).resolve())
                or p.username().casefold() != psutil.Process().username().casefold()):
            raise ValueError("This action is available for non-system applications owned by the current user.")
        if messagebox.askyesno("End selected process", f"Stop {p.name()} (PID {p.pid})? Unsaved work in it may be lost.\n\n{path}"):
            if not p.is_running():
                raise ValueError("The original process has exited.")
            p.terminate()
            self._set_status("Termination requested for the selected process.")


def launch(run_demo=False):
    root = tk.Tk()
    app = Dashboard(root)
    if run_demo:
        root.after(20, lambda: app.start("Demo"))
    root.mainloop()


if __name__ == "__main__":
    launch()