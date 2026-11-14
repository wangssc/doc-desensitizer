# -*- coding: utf-8 -*-
"""
双击启动器（打包入口）。

- 不带参数双击：开 tkinter 窗口，选文件 → 点脱敏 → 出结果。
- 带参数运行：原样转发给 desensitize.main()，命令行参数与 `python desensitize.py` 完全一致。
- `--diag`：打印运行环境自检信息（是否 frozen / 模块来自哪里），供打包验收用。

本文件只做外壳，脱敏逻辑全部来自 desensitize.py，未改动其任何行为。
"""
import argparse
import contextlib
import os
import queue
import sys
import threading
import traceback


def _is_frozen():
    return bool(getattr(sys, "frozen", False))


def _attach_parent_console():
    """windowed 版 exe 没有控制台，命令行模式下挂到调用方的控制台上。"""
    if os.name != "nt" or not _is_frozen():
        return
    import ctypes
    try:
        if not ctypes.windll.kernel32.AttachConsole(-1):
            return
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
    except Exception:
        pass


def _diag():
    """验收用：证明 exe 是 onefile 且模块从包内加载，不依赖工作目录里的 .py。"""
    import desensitize
    meipass = getattr(sys, "_MEIPASS", "")
    modfile = os.path.abspath(desensitize.__file__)
    in_bundle = bool(meipass) and os.path.abspath(modfile).lower().startswith(
        os.path.abspath(meipass).lower())
    print("frozen            = %s" % _is_frozen())
    print("_MEIPASS          = %s" % (meipass or "(未设置)"))
    print("executable        = %s" % sys.executable)
    print("cwd               = %s" % os.getcwd())
    print("desensitize.__file__ = %s" % modfile)
    print("模块在打包体内     = %s" % in_bundle)
    print("工作目录里有同名模块 = %s" % os.path.exists(
        os.path.join(os.getcwd(), "desensitize.py")))
    ok = _is_frozen() and in_bundle
    print("RESULT = %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


def _ns(**kw):
    d = dict(target="", out=None, dict=None, aggressive=False,
             restore=None, map_password=None, images="keep")
    d.update(kw)
    return argparse.Namespace(**d)


class _QueueWriter:
    """把后台线程里的 print 输出送到 Tk 主线程。"""

    def __init__(self, q):
        self.q = q

    def write(self, s):
        if s:
            self.q.put(s)
        return len(s)

    def flush(self):
        pass


class _Done:
    """线程结束信号：Tk 只能在主线程碰，所以经队列回传。"""

    def __init__(self, code):
        self.code = code


class App:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.root = root
        self.q = queue.Queue()
        self.busy = False
        self.last_outdir = ""
        self._on_done = None

        root.title("客户资料本地脱敏工具" + ("（打包版）" if _is_frozen() else ""))
        root.geometry("820x600")
        root.minsize(720, 480)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=False, padx=8, pady=(8, 4))

        self.v_target = tk.StringVar()
        self.v_out = tk.StringVar()
        self.v_pwd = tk.StringVar()
        self.v_dict = tk.StringVar()
        self.v_mode = tk.StringVar(value="normal")
        self.v_images = tk.StringVar(value="keep")

        self.v_r_target = tk.StringVar()
        self.v_r_map = tk.StringVar()
        self.v_r_pwd = tk.StringVar()

        nb.add(self._build_scrub_tab(nb, ttk, tk), text="脱敏")
        nb.add(self._build_restore_tab(nb, ttk, tk), text="还原")

        logf = ttk.Frame(root)
        logf.pack(fill="both", expand=True, padx=8, pady=4)
        self.txt = tk.Text(logf, height=14, wrap="word", state="disabled")
        sb = ttk.Scrollbar(logf, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        self.txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        self.status = tk.StringVar(value="就绪")
        ttk.Label(bar, textvariable=self.status).pack(side="left")
        self.btn_open = ttk.Button(bar, text="打开输出目录", command=self._open_outdir,
                                   state="disabled")
        self.btn_open.pack(side="right")

        root.after(80, self._drain)

    # ---------------------------------------------------------------- 界面
    def _row(self, parent, ttk, tk, label, var, picker=None, show=None):
        f = ttk.Frame(parent)
        f.pack(fill="x", padx=8, pady=3)
        ttk.Label(f, text=label, width=12, anchor="e").pack(side="left")
        e = ttk.Entry(f, textvariable=var, show=show or "")
        e.pack(side="left", fill="x", expand=True, padx=4)
        if picker:
            ttk.Button(f, text="浏览…", width=8, command=picker).pack(side="left")
        return e

    def _build_scrub_tab(self, parent, ttk, tk):
        f = ttk.Frame(parent)
        self._row(f, ttk, tk, "待处理", self.v_target, self._pick_target)
        self._row(f, ttk, tk, "输出目录", self.v_out, self._pick_out)
        self._row(f, ttk, tk, "映射表口令", self.v_pwd, show="*")
        self._row(f, ttk, tk, "自定义词表", self.v_dict, self._pick_dict)

        opt = ttk.Frame(f)
        opt.pack(fill="x", padx=8, pady=3)
        ttk.Label(opt, text="模式", width=12, anchor="e").pack(side="left")
        ttk.Radiobutton(opt, text="普通", value="normal",
                        variable=self.v_mode).pack(side="left", padx=4)
        ttk.Radiobutton(opt, text="激进（疑似人名也换，误杀上升）", value="aggressive",
                        variable=self.v_mode).pack(side="left", padx=4)

        opt2 = ttk.Frame(f)
        opt2.pack(fill="x", padx=8, pady=3)
        ttk.Label(opt2, text="docx 图片", width=12, anchor="e").pack(side="left")
        ttk.Radiobutton(opt2, text="原样保留", value="keep",
                        variable=self.v_images).pack(side="left", padx=4)
        ttk.Radiobutton(opt2, text="整块删除（图里文字脱不到）", value="strip",
                        variable=self.v_images).pack(side="left", padx=4)

        act = ttk.Frame(f)
        act.pack(fill="x", padx=8, pady=(8, 4))
        self.btn_scrub = ttk.Button(act, text="开始脱敏", command=self._start_scrub)
        self.btn_scrub.pack(side="left")
        ttk.Label(act, text="  口令至少 6 位；映射表含原文，只能自己留着。",
                  foreground="#666").pack(side="left")
        return f

    def _build_restore_tab(self, parent, ttk, tk):
        f = ttk.Frame(parent)
        self._row(f, ttk, tk, "待还原", self.v_r_target, self._pick_r_target)
        self._row(f, ttk, tk, "映射表 json", self.v_r_map, self._pick_r_map)
        self._row(f, ttk, tk, "映射表口令", self.v_r_pwd, show="*")
        act = ttk.Frame(f)
        act.pack(fill="x", padx=8, pady=(8, 4))
        self.btn_restore = ttk.Button(act, text="开始还原", command=self._start_restore)
        self.btn_restore.pack(side="left")
        ttk.Label(act, text="  还原结果写在原文件同目录，文件名加“_还原”。",
                  foreground="#666").pack(side="left")
        return f

    # ---------------------------------------------------------------- 选择器
    def _pick_target(self):
        p = self.filedialog.askopenfilename(
            title="选择要脱敏的文件",
            filetypes=[("支持的文件", "*.txt *.md *.csv *.docx"), ("全部文件", "*.*")])
        if not p:
            p = self.filedialog.askdirectory(title="或选择整个目录")
        if p:
            self.v_target.set(p)

    def _pick_out(self):
        p = self.filedialog.askdirectory(title="选择输出目录")
        if p:
            self.v_out.set(p)

    def _pick_dict(self):
        p = self.filedialog.askopenfilename(
            title="选择自定义词表", filetypes=[("词表", "*.txt"), ("全部文件", "*.*")])
        if p:
            self.v_dict.set(p)

    def _pick_r_target(self):
        p = self.filedialog.askopenfilename(
            title="选择待还原文件",
            filetypes=[("支持的文件", "*.txt *.md *.csv *.docx"), ("全部文件", "*.*")])
        if not p:
            p = self.filedialog.askdirectory(title="或选择整个目录")
        if p:
            self.v_r_target.set(p)

    def _pick_r_map(self):
        p = self.filedialog.askopenfilename(
            title="选择映射表", filetypes=[("映射表", "*.json"), ("全部文件", "*.*")])
        if p:
            self.v_r_map.set(p)

    # ---------------------------------------------------------------- 执行
    def _log(self, s):
        self.txt.configure(state="normal")
        self.txt.insert("end", s)
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, _Done):
                    self._on_done(item.code)
                else:
                    self._log(item)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    def _set_busy(self, busy, text):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_scrub.configure(state=state)
        self.btn_restore.configure(state=state)
        self.status.set(text)

    def _start_scrub(self):
        if self.busy:
            return
        import desensitize
        target = self.v_target.get().strip()
        pwd = self.v_pwd.get().strip()
        if not target:
            self.messagebox.showwarning("缺少输入", "先选一个文件或目录。")
            return
        if not os.path.exists(target):
            self.messagebox.showwarning("路径不存在", target)
            return
        if len(pwd) < 6:
            self.messagebox.showwarning("口令不合规", "映射表口令至少 6 位。")
            return
        args = _ns(target=target,
                   out=self.v_out.get().strip() or None,
                   dict=self.v_dict.get().strip() or None,
                   aggressive=(self.v_mode.get() == "aggressive"),
                   map_password=pwd,
                   images=self.v_images.get())
        self._set_busy(True, "脱敏中…")
        self._log("\n=== 开始脱敏 ===\n")
        self._run_in_thread(desensitize.run_scrub, args, self._scrub_done)

    def _start_restore(self):
        if self.busy:
            return
        import desensitize
        target = self.v_r_target.get().strip()
        mapf = self.v_r_map.get().strip()
        pwd = self.v_r_pwd.get().strip()
        if not target or not mapf:
            self.messagebox.showwarning("缺少输入", "待还原文件和映射表都要选。")
            return
        args = _ns(target=target, restore=mapf, map_password=pwd or None)
        self._set_busy(True, "还原中…")
        self._log("\n=== 开始还原 ===\n")
        self._run_in_thread(desensitize.run_restore, args, self._restore_done)

    def _run_in_thread(self, fn, args, on_done):
        q = self.q
        writer = _QueueWriter(q)
        self._on_done = on_done

        def work():
            buf_out, buf_err = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = writer, writer
            try:
                code = fn(args)
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
            except Exception:
                q.put(traceback.format_exc())
                code = 1
            finally:
                sys.stdout, sys.stderr = buf_out, buf_err
            q.put(_Done(code))

        threading.Thread(target=work, daemon=True).start()

    def _scrub_done(self, code):
        self._set_busy(False, "脱敏完成" if code == 0 else "结束（退出码 %s）" % code)
        out = self.v_out.get().strip()
        if out:
            self.last_outdir = out
        elif self.v_target.get().strip():
            base = os.path.basename(os.path.abspath(self.v_target.get().strip()))
            self.last_outdir = os.path.join("out", "desens", base.rsplit(".", 1)[0])
        if self.last_outdir and os.path.isdir(self.last_outdir):
            self.btn_open.configure(state="normal")
        self._log("\n[完成] 退出码 %s\n" % code)

    def _restore_done(self, code):
        self._set_busy(False, "还原完成" if code == 0 else "结束（退出码 %s）" % code)
        self._log("\n[完成] 退出码 %s\n" % code)

    def _open_outdir(self):
        d = os.path.abspath(self.last_outdir)
        if os.path.isdir(d):
            os.startfile(d)


def run_gui():
    import tkinter as tk
    root = tk.Tk()
    try:
        from tkinter import ttk
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    App(root)
    root.mainloop()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--diag":
        return _diag()
    if argv:
        _attach_parent_console()
        import desensitize
        return desensitize.main()
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
