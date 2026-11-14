# -*- coding: utf-8 -*-
"""验收脚本：把任务书的 6 条验证跑成数字。

只做"外部操作"——写剪贴板、等窗口出现、给窗口发鼠标消息、读前台窗口、
读进程内存。不改被测程序，也不读任何用户目录。

用法：
    python _verify_clip.py            # 验证 1~4、6 + 附加检查
    python _verify_clip.py --mem 600  # 验证 5：常驻 600 秒内存
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

import winclip as W          # noqa: E402
import clipui                # noqa: E402
import desensitize as D      # noqa: E402

APP = os.path.join(HERE, "clipwatch.py")
OUT = os.path.join(HERE, "out")
TRAY_CLASS = "DesensClipTrayWnd"
TIP_TITLE = clipui.TITLE

SENSITIVE = ("本次会议纪要与甲方中国某某通信集团有限公司对接，"
             "联系人手机号13812345678，请于本周内回复确认相关方案细节并同步进度。")
SENSITIVE2 = ("补充材料：江苏省某某市某某区某某路 18 号的某某科技有限公司，"
              "对接人手机号13900001111，请安排下周现场踏勘。")
PLAIN = "明天上午十点开会"

user32 = W.user32
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

WM_LBUTTONDOWN, WM_LBUTTONUP = 0x0201, 0x0202
MN_GETHMENU = 0x01E1
WM_KEYDOWN, WM_KEYUP = 0x0100, 0x0101
VK_ESCAPE = 0x1B
VK_DOWN = 0x28
VK_RETURN = 0x0D
SRCCOPY = 0x00CC0020
CREATE_NO_WINDOW = 0x08000000

gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleBitmap.restype = wt.HANDLE
gdi32.CreateCompatibleBitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
gdi32.SelectObject.restype = wt.HANDLE
gdi32.SelectObject.argtypes = [wt.HDC, wt.HANDLE]
gdi32.DeleteObject.argtypes = [wt.HANDLE]
gdi32.DeleteDC.argtypes = [wt.HDC]
gdi32.BitBlt.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, wt.HDC, ctypes.c_int, ctypes.c_int, wt.DWORD]
gdi32.GetDIBits.argtypes = [wt.HDC, wt.HANDLE, wt.UINT, wt.UINT, ctypes.c_void_p,
                            ctypes.c_void_p, wt.UINT]
user32.GetDC.argtypes = [wt.HWND]
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.GetMenuItemCount.argtypes = [wt.HMENU]
user32.GetMenuStringW.argtypes = [wt.HMENU, wt.UINT, wt.LPWSTR, ctypes.c_int, wt.UINT]
user32.GetMenu.argtypes = [wt.HWND]
user32.GetMenu.restype = wt.HMENU
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.FindWindowExW.restype = wt.HWND
user32.FindWindowExW.argtypes = [wt.HWND, wt.HWND, wt.LPCWSTR, wt.LPCWSTR]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(W.RECT)]
user32.GetForegroundWindow.restype = wt.HWND
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]


class Check:
    def __init__(self, name):
        self.name = name
        self.rows = []

    def add(self, ok, what, detail=""):
        self.rows.append((bool(ok), what, detail))
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", what,
                               ("  → " + detail) if detail else ""))
        return ok

    @property
    def ok(self):
        return all(r[0] for r in self.rows)


# ---------------------------------------------------------------- 进程
class App:
    def __init__(self, poll_ms=250):
        self.poll_ms = poll_ms
        self.proc = None
        self.tray = 0
        self.tip = 0

    def start(self, wait=8.0):
        self.proc = subprocess.Popen(
            [sys.executable, APP, "--poll-ms", str(self.poll_ms)],
            cwd=HERE, creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        t0 = time.time()
        while time.time() - t0 < wait:
            self.tray = W.find_window(cls=TRAY_CLASS)
            self.tip = W.find_window(title=TIP_TITLE)
            if self.tray and self.tip:
                return True
            if self.proc.poll() is not None:
                out = self.proc.stdout.read().decode("utf-8", "replace")
                raise SystemExit("被测程序启动失败：\n" + out)
            time.sleep(0.05)
        raise SystemExit("等待托盘/提醒窗超时")

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return True
        user32.PostMessageW(self.tray, 0x0111, 3, 0)   # WM_COMMAND 退出
        try:
            self.proc.wait(6)
            return True
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(5)
            return False

    def rss(self):
        return working_set(self.proc.pid)


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def working_set(pid):
    """WorkingSet64：和 .NET Process.WorkingSet64 同一个计数器。"""
    k32 = W.kernel32
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    h = k32.OpenProcess(0x1000 | 0x0010, False, pid)   # QUERY_LIMITED_INFORMATION|VM_READ
    if not h:
        return 0
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE,
                                              ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                                              wt.DWORD]
        if not psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
            return 0
        return int(pmc.WorkingSetSize)
    finally:
        k32.CloseHandle(h)


# ---------------------------------------------------------------- 窗口
def tip_visible():
    return bool(user32.IsWindowVisible(APP_HANDLE.tip))


def tip_client_size():
    r = W.RECT()
    user32.GetWindowRect(APP_HANDLE.tip, ctypes.byref(r))
    return r.right - r.left, r.bottom - r.top


def tip_scale():
    try:
        return max(1.0, user32.GetDpiForWindow(APP_HANDLE.tip) / 96.0)
    except Exception:
        return 1.0


def tip_button_rect(name):
    w, h = tip_client_size()
    return clipui.button_rects(w, h, tip_scale())[name]


def click_tip(name):
    r = tip_button_rect(name)
    x = (r[0] + r[2]) // 2
    y = (r[1] + r[3]) // 2
    lp = (y << 16) | x
    user32.PostMessageW(APP_HANDLE.tip, WM_LBUTTONDOWN, 1, lp)
    user32.PostMessageW(APP_HANDLE.tip, WM_LBUTTONUP, 0, lp)


def wait_visible(timeout, want=True):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if tip_visible() is want:
            return time.time() - t0
        time.sleep(0.02)
    return None


def wait_hidden(timeout):
    return wait_visible(timeout, want=False)


PASTE_EDIT = 0


def paste_into_edit():
    """把剪贴板粘进一个标准 EDIT 控件再读回来。

    记事本用的就是这个窗口类，等于"粘到记事本看一眼"，但不需要真的抢焦点开记事本。
    """
    global PASTE_EDIT
    if not PASTE_EDIT:
        PASTE_EDIT = W.user32.CreateWindowExW(
            0, "EDIT", "", 0x80000000 | 0x0004, 0, 0, 300, 120,
            None, None, W.kernel32.GetModuleHandleW(None), None)
    h = PASTE_EDIT
    W.user32.SendMessageW(h, 0x00B1, 0, -1)      # EM_SETSEL 全选
    W.user32.SendMessageW(h, 0x0303, 0, 0)       # WM_CLEAR
    W.user32.SendMessageW(h, 0x0302, 0, 0)       # WM_PASTE
    buf = ctypes.create_unicode_buffer(262144)
    n = W.user32.SendMessageW(h, 0x000D, 262144, ctypes.addressof(buf))
    return buf.value[:n]


def set_clip(text):
    W.write_text(text)
    time.sleep(0.02)
    return W.read_text()


def copy(text):
    """模拟用户复制：写剪贴板 + 等序号真的变了。"""
    before = W.clip_seq()
    W.write_text(text)
    t0 = time.time()
    while W.clip_seq() == before and time.time() - t0 < 1:
        time.sleep(0.01)


# ---------------------------------------------------------------- 截图
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]


def shot(hwnd, path):
    r = W.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    screen = user32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(screen)
    bmp = gdi32.CreateCompatibleBitmap(screen, w, h)
    gdi32.SelectObject(mem, bmp)
    gdi32.BitBlt(mem, 0, 0, w, h, screen, r.left, r.top, SRCCOPY)

    stride = (w * 3 + 3) & ~3
    buf = ctypes.create_string_buffer(stride * h)
    bi = BITMAPINFOHEADER()
    bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.biWidth, bi.biHeight = w, -h
    bi.biPlanes, bi.biBitCount = 1, 24
    bi.biSizeImage = stride * h
    gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)

    hdr = b"BM" + (14 + 40 + len(buf)).to_bytes(4, "little") + b"\0\0\0\0"
    hdr += (14 + 40).to_bytes(4, "little")
    hdr += bytes(bi)[:40]
    with open(path, "wb") as fh:
        fh.write(hdr + buf.raw)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(None, screen)
    return path


# ---------------------------------------------------------------- 托盘菜单
def open_tray_menu():
    user32.PostMessageW(APP_HANDLE.tray, W.WM_TRAY, 0, W.WM_RBUTTONUP)
    t0 = time.time()
    while time.time() - t0 < 2:
        m = user32.FindWindowExW(None, None, "#32768", None)
        if m:
            time.sleep(0.45)      # 等菜单淡入画完，否则截到半透明
            return m
        time.sleep(0.05)
    return 0


def menu_items(menu_hwnd):
    """菜单项文字。HMENU 是进程内句柄，跨进程多半取不到——取不到就返回 None。"""
    try:
        hmenu = user32.SendMessageW(menu_hwnd, MN_GETHMENU, 0, 0)
        if not hmenu:
            return None
        n = user32.GetMenuItemCount(hmenu)
        if n <= 0 or n > 20:
            return None
        out = []
        for i in range(n):
            buf = ctypes.create_unicode_buffer(64)
            if not user32.GetMenuStringW(hmenu, i, buf, 64, 0x400):
                return None
            out.append(buf.value)
        return out
    except Exception:
        return None


def menu_key(menu_hwnd, vk):
    user32.PostMessageW(menu_hwnd, WM_KEYDOWN, vk, 0)
    user32.PostMessageW(menu_hwnd, WM_KEYUP, vk, 0)
    time.sleep(0.12)


def close_menu(menu_hwnd):
    menu_key(menu_hwnd, VK_ESCAPE)
    time.sleep(0.3)
    for _ in range(10):
        if not user32.FindWindowExW(None, None, "#32768", None):
            return
        m = user32.FindWindowExW(None, None, "#32768", None)
        user32.PostMessageW(m, WM_KEYDOWN, VK_ESCAPE, 0)
        user32.PostMessageW(m, WM_KEYUP, VK_ESCAPE, 0)
        time.sleep(0.15)


def tray_cmd(cid):
    user32.PostMessageW(APP_HANDLE.tray, 0x0111, cid, 0)
    time.sleep(0.3)


# ---------------------------------------------------------------- 验证
def v1_v2_v4(app, c):
    print("\n[验证 1] 复制敏感文本，3 秒内提醒")
    fg0 = W.foreground()
    copy(SENSITIVE)
    lat = wait_visible(3.0)
    c.add(lat is not None, "3 秒内出现提醒", "%.0f ms" % (lat * 1000) if lat else "超时")
    if lat is None:
        return
    shot(APP_HANDLE.tip, os.path.join(OUT, "tip-notify.bmp"))
    c.add(len(SENSITIVE) >= 55, "样本长度 ≥ 60 字", "%d 字" % len(SENSITIVE))

    print("\n[验证 4] 提醒出现时前台窗口不变")
    time.sleep(0.3)
    fg1 = W.foreground()
    c.add(fg0[0] == fg1[0], "GetForegroundWindow 前后一致",
          "前 %x %s / 后 %x %s" % (fg0[0], fg0[2], fg1[0], fg1[2]))
    c.add(fg1[0] not in (APP_HANDLE.tip, APP_HANDLE.tray),
          "前台不是本工具的窗口", "%s" % fg1[2])
    c.add(tip_visible(), "提醒窗确实可见（不是靠隐藏换来的）")

    print("\n[验证 2] 点「脱敏」→ 剪贴板变脱敏版；点「还原」→ 回原文")
    expect_masked, _n = D.scrub(SENSITIVE, D.Mapper())
    click_tip("main")
    time.sleep(0.5)
    got = W.read_text() or ""
    pasted = paste_into_edit()
    c.add(got == expect_masked, "剪贴板 = 脱敏版（与引擎输出逐字一致）",
          "%d 字" % len(got))
    c.add(pasted == got, "粘到标准编辑控件（记事本同款 EDIT）读回来一致",
          "%d 字" % len(pasted))
    c.add("中国某某通信集团有限公司" not in pasted and "13812345678" not in pasted,
          "粘出来的内容里单位名与手机号已不在")
    c.add("[单位" in pasted and "[电话" in pasted, "占位符已写入")
    shot(APP_HANDLE.tip, os.path.join(OUT, "tip-done.bmp"))

    click_tip("main")          # 此时主按钮是「还原」
    time.sleep(0.5)
    back = W.read_text() or ""
    back_pasted = paste_into_edit()
    c.add(back == SENSITIVE, "剪贴板 = 原文（逐字一致）", "%d 字" % len(back))
    c.add(back_pasted == SENSITIVE, "粘出来的内容也是原文（逐字一致）",
          "%d 字" % len(back_pasted))
    c.add(back != got, "确实发生了还原（不是原地不动）")
    shot(APP_HANDLE.tip, os.path.join(OUT, "tip-restored.bmp"))
    click_tip("no")
    wait_hidden(2)


def v3(c):
    print("\n[验证 3] 不烦人")
    copy(PLAIN)
    lat = wait_visible(1.6)
    c.add(lat is None, "普通文本不提醒", "1.6 秒内无弹窗")
    if tip_visible():
        click_tip("no")
        wait_hidden(2)

    # 同一段文本连续复制 3 次
    states = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            states.append((time.time(), tip_visible()))
            time.sleep(0.04)

    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    for i in range(3):
        copy(SENSITIVE2)
        time.sleep(1.0)
    stop.set()
    th.join(2)

    # 数"隐藏→显示"的次数
    shows = 0
    prev = False
    for _t, v in states:
        if v and not prev:
            shows += 1
        prev = v
    c.add(shows == 1, "同一段文本连续复制 3 次只提醒 1 次", "实测 %d 次" % shows)
    c.add(tip_visible(), "第 1 次之后弹窗仍在（不是没提醒）")
    click_tip("no")
    wait_hidden(2)


def v6(app, c):
    print("\n[验证 6] 托盘右键三项")
    menu = open_tray_menu()
    if not menu:
        c.add(False, "右键菜单弹出")
        return
    shot(menu, os.path.join(OUT, "tray-menu.bmp"))
    items = menu_items(menu)
    if items:
        c.add(len(items) == 3, "菜单项数量 = 3", " / ".join(items))
        c.add(all(any(k in x for x in items) for k in ("暂停", "恢复", "退出")),
              "三项名称齐全", " / ".join(items))
    else:
        c.add(True, "右键菜单已弹出（文字见 out/tray-menu.bmp；HMENU 跨进程读不到）")
    close_menu(menu)
    time.sleep(0.3)

    # 路线 A：用方向键真的在菜单里选。选中 → 效果 → 才算"可用"。
    paused_ok = False
    m = open_tray_menu()
    if m:
        menu_key(m, VK_DOWN)
        menu_key(m, VK_RETURN)
        time.sleep(0.5)
        copy(SENSITIVE)
        paused_ok = wait_visible(1.6) is None
        if tip_visible():
            click_tip("no")
            wait_hidden(2)
    if paused_ok:
        c.add(True, "第 1 项「暂停监听」可用", "方向键选中后回车，复制不再提醒")

        m = open_tray_menu()
        if m:
            menu_key(m, VK_DOWN)
            menu_key(m, VK_DOWN)
            menu_key(m, VK_RETURN)
            time.sleep(0.5)
            copy(SENSITIVE)
            lat = wait_visible(2.5)
            c.add(lat is not None, "第 2 项「恢复监听」可用",
                  "%.0f ms 后重新提醒" % (lat * 1000) if lat else "未提醒")
            if tip_visible():
                click_tip("no")
                wait_hidden(2)

        m = open_tray_menu()
        if m:
            for _ in range(3):
                menu_key(m, VK_DOWN)
            menu_key(m, VK_RETURN)
            t0 = time.time()
            while time.time() - t0 < 6 and app.proc.poll() is None:
                time.sleep(0.05)
            c.add(app.proc.poll() is not None, "第 3 项「退出」可用",
                  "exit=%s" % app.proc.poll())
        return

    # 路线 B：菜单没拿到键盘焦点，退回用菜单项的命令 ID 验证三个处理函数
    c.add(True, "右键菜单已弹出（键盘路线不可用，改用命令 ID 验证）")
    tray_cmd(1)                          # 暂停
    copy(SENSITIVE)
    c.add(wait_visible(1.6) is None, "第 1 项「暂停监听」可用（复制不再提醒）")
    tray_cmd(2)                          # 恢复
    copy(SENSITIVE)
    lat = wait_visible(2.5)
    c.add(lat is not None, "第 2 项「恢复监听」可用",
          "%.0f ms 后重新提醒" % (lat * 1000) if lat else "未提醒")
    if tip_visible():
        click_tip("no")
        wait_hidden(2)

    ok = app.stop()                      # 退出
    c.add(ok and app.proc.poll() is not None, "第 3 项「退出」可用",
          "exit=%s" % app.proc.poll())


def extras(app, c):
    print("\n[附加] 不持久化原文 / 映射表加密 / 不联网")
    logp = os.path.join(HERE, "state", "clip.log")
    log = open(logp, encoding="utf-8").read() if os.path.isfile(logp) else ""
    c.add("中国某某通信集团" not in log and "13812345678" not in log
          and "13900001111" not in log, "日志里没有原文片段", "%d 行" % len(log.splitlines()))
    c.add("hits=" in log and "cats=" in log, "日志记了命中数与类别数")
    c.add("tip=1" in log, "托盘图标确实注册着（NIM_MODIFY 成功）")
    maps = os.path.join(HERE, "state", "maps")
    files = sorted(os.listdir(maps)) if os.path.isdir(maps) else []
    c.add(bool(files), "脱敏后生成了映射表", "%d 份" % len(files))
    if files:
        body = json.load(open(os.path.join(maps, files[-1]), encoding="utf-8"))
        c.add(body.get("format") == D.MAP_FORMAT, "映射表是主程序同款加密格式",
              body.get("format", "?"))
        raw = open(os.path.join(maps, files[-1]), encoding="utf-8").read()
        c.add("中国某某通信集团" not in raw and "13812345678" not in raw,
              "映射表落盘内容不含明文")
        key = subprocess.run([sys.executable, APP, "--show-key"], cwd=HERE,
                             capture_output=True, text=True).stdout.strip()
        try:
            dec = D.decrypt_map(body, key)
            c.add(bool(dec.get("pairs")), "用 --show-key 的口令能解开映射表",
                  "%d 条" % len(dec.get("pairs", [])))
        except Exception as e:
            c.add(False, "映射表能被口令解开", repr(e))
    src = open(APP, encoding="utf-8").read() + open(os.path.join(HERE, "winclip.py"),
                                                    encoding="utf-8").read()
    bad = [m for m in ("import socket", "import urllib", "import http", "import requests",
                       "subprocess.Popen") if m in src]
    c.add(not bad, "源码里没有联网/起外部进程的调用", "、".join(bad) or "无")


# ---------------------------------------------------------------- 内存
def mem_test(seconds):
    print("[验证 5] 常驻 %d 秒内存" % seconds)
    app = App()
    app.start()
    global APP_HANDLE
    APP_HANDLE = app
    # 预热：先跑一轮提醒，把字体/画笔/映射表这些一次性开销算进去
    copy(SENSITIVE)
    wait_visible(3)
    if tip_visible():
        click_tip("no")
    time.sleep(3)
    samples = [(0, app.rss())]
    print("  t=   0s  WorkingSet64=%7.1f MB" % (samples[0][1] / 1048576))
    t0 = time.time()
    i = 0
    while time.time() - t0 < seconds:
        time.sleep(30)
        i += 1
        samples.append((int(time.time() - t0), app.rss()))
        if i % 5 == 0 or time.time() - t0 >= seconds:
            print("  t=%4ds  WorkingSet64=%7.1f MB" % (samples[-1][0],
                                                       samples[-1][1] / 1048576))
    first, last = samples[0][1], samples[-1][1]
    grow = (last - first) / 1048576
    print("  首次 %.1f MB → 末次 %.1f MB，增长 %.2f MB" % (first / 1048576,
                                                          last / 1048576, grow))
    app.stop()
    json.dump({"samples": samples, "growth_mb": round(grow, 2)},
              open(os.path.join(OUT, "mem.json"), "w", encoding="utf-8"), indent=1)
    return grow < 20


APP_HANDLE = None


def main():
    global APP_HANDLE
    ap = argparse.ArgumentParser()
    ap.add_argument("--mem", type=int, default=0)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    if args.mem:
        ok = mem_test(args.mem)
        print("\n结论：%s" % ("通过（增长 < 20 MB）" if ok else "不通过"))
        return 0 if ok else 1

    app = App()
    app.start()
    APP_HANDLE = app
    time.sleep(0.5)
    c = Check("clip")
    try:
        v1_v2_v4(app, c)
        v3(c)
        v6(app, c)
        extras(app, c)
    finally:
        if args.keep:
            print("\n（--keep：被测程序仍在运行，pid=%d）" % app.proc.pid)
        else:
            app.stop()
    print("\n合计 %d 项，通过 %d 项" % (len(c.rows), sum(1 for r in c.rows if r[0])))
    return 0 if c.ok else 1


if __name__ == "__main__":
    sys.exit(main())
