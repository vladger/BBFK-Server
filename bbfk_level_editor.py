#!/usr/bin/env python3
"""
Bubble Bobble for Kakao (BBFK) - Tkinter Level Editor
----------------------------------------------------
Creates and edits multi-section JSON levels compatible with `bbfk_server.py`
(--levels-dir levels).

Features:
  - Multiple tabs (one per map section in a stage)
  - Interactive 32x34 grid (click/drag to paint tiles, place Player, Pet, Enemies, Items, Holes)
  - Right-click any object to select it (or select tool) and edit its properties
  - Level-level config (stage_id, name, goal scores, bonus coin rate)
  - Section-level config (bg_name, hurry_up_time, bubble_speed_rate, bubble_interval_sec)

Usage:
  python3 bbfk_level_editor.py
"""

import copy
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

GRID_W = 32
GRID_H = 34
CELL = 16

ENEMY_NAMES = {
    1: "1: Zen-chan",
    2: "2: Banebou",
    3: "3: Mighta",
    4: "4: Hidegons",
    5: "5: Monsta",
    6: "6: Drunk",
    7: "7: Pulpul",
    8: "8: Invader",
    9: "9: Draagon",
    10: "10: Raise",
    11: "11: Ganchan",
    1000: "1000: Skull",
}


def make_default_tiles():
    tiles = []
    for y in range(GRID_H):
        for x in range(GRID_W):
            if x == 0 or x == GRID_W - 1 or y == 0 or y == GRID_H - 1:
                tiles.append([x, y])
            elif y in (28, 22, 16, 10) and 4 <= x <= 27 and not (14 <= x <= 17):
                tiles.append([x, y])
    return tiles


def make_default_section(name="Map 1"):
    return {
        "name": name,
        "bg_name": "mp_0021_0",
        "hurry_up_time": 60,
        "bubble_speed_rate": 100.0,
        "bubble_interval_sec": 1.0,
        "tiles": make_default_tiles(),
        "players": [
            {"id": 1, "x": 5.0, "y": 30.0, "dir": 1},
            {"id": 2, "x": 7.0, "y": 30.0, "dir": 1},
        ],
        "enemies": [
            {"id": 1, "x": 16.0, "y": 20.0, "dir": -1, "startSec": 0},
            {"id": 2, "x": 22.0, "y": 26.0, "dir": -1, "startSec": 0},
            {"id": 3, "x": 10.0, "y": 14.0, "dir": 1, "startSec": 0},
        ],
        "items": [],
        "holes": [],
    }


def make_default_stage():
    return {
        "stage_id": 1,
        "name": "Stage 1-1",
        "description": "Custom Stage 1-1",
        "goal_score_1": 1000,
        "goal_score_2": 3000,
        "goal_score_3": 5000,
        "bonus_coin_rate": 100,
        "maps": [make_default_section("Map 1"), make_default_section("Map 2")],
    }


class LevelEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BBFK Level Editor")
        self.geometry("1100x720")
        self.minsize(960, 640)

        self.stage = make_default_stage()
        self.current_file = None
        self.tool_var = tk.StringVar(value="tile")
        self.selected_ref = None  # (category, index) in current section
        self.tab_canvases = []

        self._build_ui()
        self._rebuild_tabs()
        self._load_level_config_ui()

    def _build_ui(self):
        # Top toolbar
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill=tk.X)

        ttk.Button(bar, text="New Stage", command=self.new_stage).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Open JSON...", command=self.open_json).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Save JSON...", command=self.save_json_as).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Save to levels/", command=self.save_to_levels).pack(side=tk.LEFT, padx=2)
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Button(bar, text="+ Section", command=self.add_section).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Duplicate Section", command=self.dup_section).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Remove Section", command=self.remove_section).pack(side=tk.LEFT, padx=2)
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Button(bar, text="Add Borders", command=self.add_borders).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Clear Tiles", command=self.clear_tiles).pack(side=tk.LEFT, padx=2)

        main = ttk.Frame(self, padding=6)
        main.pack(fill=tk.BOTH, expand=True)

        # Left palette
        pal = ttk.LabelFrame(main, text="Tools", padding=6)
        pal.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        tools = [
            ("Select / Inspect", "select"),
            ("Tile (Wall/Plat)", "tile"),
            ("Erase Tile", "erase"),
            ("Player 1", "player1"),
            ("Pet (Player 2)", "player2"),
            ("Enemy", "enemy"),
            ("Item", "item"),
            ("Bubble Hole", "hole"),
        ]
        for label, val in tools:
            ttk.Radiobutton(pal, text=label, value=val, variable=self.tool_var).pack(anchor=tk.W, pady=3)

        ttk.Label(pal, text="\nTip:\n- Left-click/drag to paint\n- Right-click object\n  to select/edit", foreground="#555").pack(anchor=tk.W)

        # Center Notebook (one tab per level section)
        center = ttk.Frame(main)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.notebook = ttk.Notebook(center)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Right inspector
        right = ttk.Frame(main, width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(6, 0))
        right.pack_propagate(False)

        # Level Config
        lvl_frm = ttk.LabelFrame(right, text="Level Config", padding=6)
        lvl_frm.pack(fill=tk.X, pady=(0, 6))
        self.lvl_vars = {}
        for idx, (lbl, key) in enumerate([
            ("Stage ID", "stage_id"),
            ("Name", "name"),
            ("Goal Score 1", "goal_score_1"),
            ("Goal Score 2", "goal_score_2"),
            ("Goal Score 3", "goal_score_3"),
            ("Bonus Coin %", "bonus_coin_rate"),
        ]):
            ttk.Label(lvl_frm, text=lbl).grid(row=idx, column=0, sticky=tk.W, pady=2)
            v = tk.StringVar()
            self.lvl_vars[key] = v
            ttk.Entry(lvl_frm, textvariable=v, width=18).grid(row=idx, column=1, sticky=tk.EW, padx=(4, 0), pady=2)
        ttk.Button(lvl_frm, text="Apply Level Config", command=self._apply_level_config).grid(row=6, column=0, columnspan=2, sticky=tk.EW, pady=(4, 0))

        # Section Config
        sec_frm = ttk.LabelFrame(right, text="Section Config", padding=6)
        sec_frm.pack(fill=tk.X, pady=(0, 6))
        self.sec_vars = {}
        for idx, (lbl, key) in enumerate([
            ("Section Name", "name"),
            ("BG Name", "bg_name"),
            ("Hurry Up (s)", "hurry_up_time"),
            ("Bubble Speed", "bubble_speed_rate"),
            ("Bubble Interval", "bubble_interval_sec"),
        ]):
            ttk.Label(sec_frm, text=lbl).grid(row=idx, column=0, sticky=tk.W, pady=2)
            v = tk.StringVar()
            self.sec_vars[key] = v
            ttk.Entry(sec_frm, textvariable=v, width=18).grid(row=idx, column=1, sticky=tk.EW, padx=(4, 0), pady=2)
        ttk.Button(sec_frm, text="Apply Section Config", command=self._apply_section_config).grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=(4, 0))

        # Object Config
        self.obj_frm = ttk.LabelFrame(right, text="Selected Object Config", padding=6)
        self.obj_frm.pack(fill=tk.BOTH, expand=True)
        self._render_object_inspector()

    def _cur_sec_idx(self) -> int:
        if not self.notebook.tabs():
            return 0
        return self.notebook.index(self.notebook.select())

    def _cur_sec(self) -> dict:
        return self.stage["maps"][self._cur_sec_idx()]

    def _rebuild_tabs(self, select_idx=0):
        for tab in self.notebook.tabs():
            self.notebook.forget(tab)
        self.tab_canvases.clear()

        for idx, m in enumerate(self.stage["maps"]):
            frame = ttk.Frame(self.notebook)
            canvas = tk.Canvas(frame, width=GRID_W * CELL, height=GRID_H * CELL, bg="#181c28", highlightthickness=0)
            canvas.pack(padx=6, pady=6)
            canvas.bind("<Button-1>", lambda e, i=idx: self._on_left_click(e, i))
            canvas.bind("<B1-Motion>", lambda e, i=idx: self._on_left_drag(e, i))
            canvas.bind("<Button-3>", lambda e, i=idx: self._on_right_click(e, i))
            self.notebook.add(frame, text=m.get("name", f"Map {idx + 1}"))
            self.tab_canvases.append(canvas)
            self._redraw_canvas(idx)

        if self.stage["maps"]:
            self.notebook.select(min(select_idx, len(self.stage["maps"]) - 1))
        self._load_section_config_ui()

    def _on_tab_changed(self, _event):
        self.selected_ref = None
        self._load_section_config_ui()
        self._render_object_inspector()

    def _redraw_canvas(self, sec_idx: int):
        canvas = self.tab_canvases[sec_idx]
        m = self.stage["maps"][sec_idx]
        canvas.delete("all")

        # Grid lines
        for x in range(GRID_W + 1):
            canvas.create_line(x * CELL, 0, x * CELL, GRID_H * CELL, fill="#262c3f")
        for y in range(GRID_H + 1):
            canvas.create_line(0, y * CELL, GRID_W * CELL, y * CELL, fill="#262c3f")

        # Tiles
        for tx, ty in m.get("tiles", []):
            x0, y0 = tx * CELL, ty * CELL
            canvas.create_rectangle(x0 + 1, y0 + 1, x0 + CELL - 1, y0 + CELL - 1, fill="#4c9f58", outline="#2e6b38")

        def draw_obj(cat, idx, obj, color, label):
            ox = float(obj.get("x", 0)) * CELL
            oy = float(obj.get("y", 0)) * CELL
            is_sel = (self.selected_ref == (cat, idx) and sec_idx == self._cur_sec_idx())
            outline = "#ffffff" if is_sel else "#111111"
            w = 2 if is_sel else 1
            canvas.create_oval(ox + 1, oy + 1, ox + CELL - 1, oy + CELL - 1, fill=color, outline=outline, width=w)
            canvas.create_text(ox + CELL / 2, oy + CELL / 2, text=label, fill="#000000", font=("TkDefaultFont", 7, "bold"))

        for i, hl in enumerate(m.get("holes", [])):
            draw_obj("holes", i, hl, "#b57bff", "H")
        for i, it in enumerate(m.get("items", [])):
            draw_obj("items", i, it, "#ffd633", f"I{it.get('id', 1)}")
        for i, em in enumerate(m.get("enemies", [])):
            draw_obj("enemies", i, em, "#ff5555", f"E{em.get('id', 1)}")
        for i, pl in enumerate(m.get("players", [])):
            draw_obj("players", i, pl, "#33bbff" if i == 0 else "#88eeff", f"P{i + 1}")

    def _grid_xy(self, event):
        gx = max(0, min(GRID_W - 1, event.x // CELL))
        gy = max(0, min(GRID_H - 1, event.y // CELL))
        return gx, gy

    def _find_object_at(self, m: dict, gx: int, gy: int):
        for cat in ("players", "enemies", "items", "holes"):
            for i, obj in enumerate(m.get(cat, [])):
                if int(round(float(obj.get("x", -1)))) == gx and int(round(float(obj.get("y", -1)))) == gy:
                    return (cat, i)
        return None

    def _on_left_click(self, event, sec_idx: int):
        gx, gy = self._grid_xy(event)
        m = self.stage["maps"][sec_idx]
        tool = self.tool_var.get()

        if tool == "select":
            self.selected_ref = self._find_object_at(m, gx, gy)
            self._redraw_canvas(sec_idx)
            self._render_object_inspector()
            return
        if tool in ("tile", "erase"):
            self._paint_tile(m, gx, gy, add=(tool == "tile"))
            self._redraw_canvas(sec_idx)
            return
        if tool == "player1":
            while len(m["players"]) < 2:
                m["players"].append({"id": len(m["players"]) + 1, "x": 5.0, "y": 30.0, "dir": 1})
            m["players"][0]["x"], m["players"][0]["y"] = float(gx), float(gy)
            self.selected_ref = ("players", 0)
        elif tool == "player2":
            while len(m["players"]) < 2:
                m["players"].append({"id": len(m["players"]) + 1, "x": 7.0, "y": 30.0, "dir": 1})
            m["players"][1]["x"], m["players"][1]["y"] = float(gx), float(gy)
            self.selected_ref = ("players", 1)
        elif tool == "enemy":
            m["enemies"].append({"id": 1, "x": float(gx), "y": float(gy), "dir": -1, "startSec": 0})
            self.selected_ref = ("enemies", len(m["enemies"]) - 1)
        elif tool == "item":
            m["items"].append({"id": 1, "flag": 1, "min": 0, "max": 0, "x": float(gx), "y": float(gy)})
            self.selected_ref = ("items", len(m["items"]) - 1)
        elif tool == "hole":
            m["holes"].append({"id": 1, "x": float(gx), "y": float(gy), "flag": 1, "size": 1, "isHole": 1})
            self.selected_ref = ("holes", len(m["holes"]) - 1)

        self._redraw_canvas(sec_idx)
        self._render_object_inspector()

    def _on_left_drag(self, event, sec_idx: int):
        tool = self.tool_var.get()
        if tool not in ("tile", "erase"):
            return
        gx, gy = self._grid_xy(event)
        self._paint_tile(self.stage["maps"][sec_idx], gx, gy, add=(tool == "tile"))
        self._redraw_canvas(sec_idx)

    def _on_right_click(self, event, sec_idx: int):
        gx, gy = self._grid_xy(event)
        m = self.stage["maps"][sec_idx]
        ref = self._find_object_at(m, gx, gy)
        self.selected_ref = ref
        self._redraw_canvas(sec_idx)
        self._render_object_inspector()

    def _paint_tile(self, m: dict, gx: int, gy: int, add: bool):
        tiles = m.setdefault("tiles", [])
        pair = [gx, gy]
        if add:
            if pair not in tiles:
                tiles.append(pair)
        else:
            if pair in tiles:
                tiles.remove(pair)

    def _load_level_config_ui(self):
        for k, v in self.lvl_vars.items():
            v.set(str(self.stage.get(k, "")))

    def _apply_level_config(self):
        try:
            self.stage["stage_id"] = int(self.lvl_vars["stage_id"].get())
            self.stage["name"] = self.lvl_vars["name"].get()
            self.stage["goal_score_1"] = int(self.lvl_vars["goal_score_1"].get())
            self.stage["goal_score_2"] = int(self.lvl_vars["goal_score_2"].get())
            self.stage["goal_score_3"] = int(self.lvl_vars["goal_score_3"].get())
            self.stage["bonus_coin_rate"] = int(self.lvl_vars["bonus_coin_rate"].get())
        except ValueError as exc:
            messagebox.showerror("Invalid Value", f"Check numeric fields: {exc}")

    def _load_section_config_ui(self):
        if not self.stage["maps"]:
            return
        m = self._cur_sec()
        for k, v in self.sec_vars.items():
            v.set(str(m.get(k, "")))

    def _apply_section_config(self):
        try:
            idx = self._cur_sec_idx()
            m = self.stage["maps"][idx]
            m["name"] = self.sec_vars["name"].get()
            m["bg_name"] = self.sec_vars["bg_name"].get()
            m["hurry_up_time"] = int(self.sec_vars["hurry_up_time"].get())
            m["bubble_speed_rate"] = float(self.sec_vars["bubble_speed_rate"].get())
            m["bubble_interval_sec"] = float(self.sec_vars["bubble_interval_sec"].get())
            self.notebook.tab(idx, text=m["name"])
        except ValueError as exc:
            messagebox.showerror("Invalid Value", f"Check numeric fields: {exc}")

    def _render_object_inspector(self):
        for w in self.obj_frm.winfo_children():
            w.destroy()
        if not self.selected_ref:
            ttk.Label(self.obj_frm, text="No object selected.\nUse Select or Right-click\nan object on the grid.", foreground="#555").pack(anchor=tk.W)
            return

        cat, idx = self.selected_ref
        m = self._cur_sec()
        if idx >= len(m.get(cat, [])):
            self.selected_ref = None
            return
        obj = m[cat][idx]
        ttk.Label(self.obj_frm, text=f"Type: {cat[:-1].upper()} #{idx + 1}", font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W, pady=(0, 4))

        self.obj_vars = {}
        fields = [k for k in obj.keys()]
        frm = ttk.Frame(self.obj_frm)
        frm.pack(fill=tk.X)
        for r, k in enumerate(fields):
            ttk.Label(frm, text=k).grid(row=r, column=0, sticky=tk.W, pady=2)
            v = tk.StringVar(value=str(obj[k]))
            self.obj_vars[k] = v
            if cat == "enemies" and k == "id":
                cb = ttk.Combobox(frm, textvariable=v, values=[str(eid) for eid in ENEMY_NAMES.keys()], width=15)
                cb.grid(row=r, column=1, sticky=tk.EW, padx=(4, 0), pady=2)
            else:
                ttk.Entry(frm, textvariable=v, width=17).grid(row=r, column=1, sticky=tk.EW, padx=(4, 0), pady=2)

        if cat == "enemies":
            cur_id = int(obj.get("id", 1))
            ttk.Label(self.obj_frm, text=ENEMY_NAMES.get(cur_id, f"ID {cur_id}"), foreground="#369").pack(anchor=tk.W, pady=(2, 4))

        btns = ttk.Frame(self.obj_frm)
        btns.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btns, text="Apply Object", command=self._apply_object).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 2))
        if cat != "players":
            ttk.Button(btns, text="Delete", command=self._delete_object).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(2, 0))

    def _apply_object(self):
        if not self.selected_ref:
            return
        cat, idx = self.selected_ref
        obj = self._cur_sec()[cat][idx]
        try:
            for k, v in self.obj_vars.items():
                raw = v.get().strip()
                if k in ("x", "y"):
                    obj[k] = float(raw)
                else:
                    obj[k] = int(raw)
            self._redraw_canvas(self._cur_sec_idx())
            self._render_object_inspector()
        except ValueError as exc:
            messagebox.showerror("Invalid Value", f"Check object fields: {exc}")

    def _delete_object(self):
        if not self.selected_ref:
            return
        cat, idx = self.selected_ref
        if cat == "players":
            return
        del self._cur_sec()[cat][idx]
        self.selected_ref = None
        self._redraw_canvas(self._cur_sec_idx())
        self._render_object_inspector()

    def add_section(self):
        n = len(self.stage["maps"]) + 1
        self.stage["maps"].append(make_default_section(f"Map {n}"))
        self._rebuild_tabs(select_idx=n - 1)

    def dup_section(self):
        idx = self._cur_sec_idx()
        dup = copy.deepcopy(self.stage["maps"][idx])
        dup["name"] = dup.get("name", "Map") + " Copy"
        self.stage["maps"].insert(idx + 1, dup)
        self._rebuild_tabs(select_idx=idx + 1)

    def remove_section(self):
        if len(self.stage["maps"]) <= 1:
            messagebox.showinfo("Info", "A stage must have at least 1 section.")
            return
        idx = self._cur_sec_idx()
        del self.stage["maps"][idx]
        self._rebuild_tabs(select_idx=max(0, idx - 1))

    def add_borders(self):
        m = self._cur_sec()
        for y in range(GRID_H):
            for x in range(GRID_W):
                if x == 0 or x == GRID_W - 1 or y == 0 or y == GRID_H - 1:
                    self._paint_tile(m, x, y, add=True)
        self._redraw_canvas(self._cur_sec_idx())

    def clear_tiles(self):
        self._cur_sec()["tiles"] = []
        self._redraw_canvas(self._cur_sec_idx())

    def new_stage(self):
        self.stage = make_default_stage()
        self.current_file = None
        self.selected_ref = None
        self._rebuild_tabs()
        self._load_level_config_ui()

    def open_json(self):
        fp = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not fp:
            return
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                data = data[0]
            self.stage = data
            self.current_file = fp
            self.selected_ref = None
            self._rebuild_tabs()
            self._load_level_config_ui()
        except Exception as exc:
            messagebox.showerror("Open Error", str(exc))

    def save_json_as(self):
        self._apply_level_config()
        self._apply_section_config()
        fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not fp:
            return
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(self.stage, f, indent=2)
        self.current_file = fp
        messagebox.showinfo("Saved", f"Saved stage to {fp}")

    def save_to_levels(self):
        self._apply_level_config()
        self._apply_section_config()
        os.makedirs("levels", exist_ok=True)
        sid = int(self.stage.get("stage_id", 1))
        fp = os.path.join("levels", f"stage_{sid:02d}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(self.stage, f, indent=2)
        self.current_file = fp
        messagebox.showinfo("Saved", f"Saved to {fp}\nRestart bbfk_server.py to serve it!")


if __name__ == "__main__":
    app = LevelEditorApp()
    app.mainloop()