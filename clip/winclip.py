# -*- coding: utf-8 -*-
"""Win32 薄封装（只用标准库 ctypes）。

为什么不用 pystray / pywin32：
    pystray 没装，pywin32 也没装；本工具只需要托盘图标 + 一个剪贴板读取，
    用 ctypes 直接调 Shell_NotifyIcon / user32 的剪贴板 API 大约 300 行，
    比引入第三方依赖更容易审，也不会在别人机器上装不上。

这里只放"和 Windows 打交道"的代码，业务逻辑在 clipwatch.py。
"""
import ctypes
import ctypes.wintypes as wt
import os
import threading
import time

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

# ---------------------------------------------------------------- 常量
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040

GWLP_EXSTYLE = -20
WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOOLWINDOW = 0x00000080
SW_SHOWNOACTIVATE = 4
SW_HIDE = 0
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOACTIVATE = 0x0010
SWP_NOZORDER = 0x0004
HWND_TOPMOST = -1
HWND_MESSAGE = -3

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_TIMER = 0x0113
WM_NULL = 0x0000
WM_RBUTTONUP = 0x0205
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_CONTEXTMENU = 0x007B
WM_LBUTTONDOWN = 0x0201
WM_APP = 0x8000

IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
LR_DEFAULTSIZE = 0x0040
IDI_APPLICATION = 32512

NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETVERSION = 0, 1, 2, 4
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NOTIFYICON_VERSION_4 = 4

MF_STRING = 0x0000
MF_SEPARATOR = 0x0800
MF_CHECKED = 0x0008
MF_GRAYED = 0x0001
TPM_RIGHTBUTTON = 0x0002
TPM_BOTTOMALIGN = 0x0020
TPM_LEFTALIGN = 0x0000
SPI_GETWORKAREA = 0x0030
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT),
                ("uFlags", wt.UINT), ("uCallbackMessage", wt.UINT),
                ("hIcon", wt.HANDLE), ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD),
                ("szInfo", wt.WCHAR * 256), ("uTimeout", wt.UINT),
                ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wt.HANDLE)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE), ("hIcon", wt.HANDLE),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HANDLE),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]


class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG),
                ("right", wt.LONG), ("bottom", wt.LONG)]


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


# ---------------------------------------------------------------- 原型声明
# 64 位下不声明 restype 会把句柄截断成 int32，症状是"偶尔"读写剪贴板失败。
user32.GetClipboardData.restype = wt.HANDLE
user32.GetClipboardData.argtypes = [wt.UINT]
user32.SetClipboardData.restype = wt.HANDLE
user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
user32.OpenClipboard.argtypes = [wt.HWND]
user32.GetClipboardSequenceNumber.restype = wt.DWORD
user32.GetForegroundWindow.restype = wt.HWND
user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
user32.LoadImageW.restype = wt.HANDLE
user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT, ctypes.c_int,
                              ctypes.c_int, wt.UINT]
user32.LoadIconW.restype = wt.HANDLE
user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE,
                                   wt.LPVOID]
user32.CreatePopupMenu.restype = wt.HMENU
user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
user32.TrackPopupMenu.restype = ctypes.c_int
user32.TrackPopupMenu.argtypes = [wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, wt.HWND, ctypes.POINTER(RECT)]
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.SendMessageW.restype = LRESULT
user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.FindWindowW.restype = wt.HWND
user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.SetTimer.argtypes = [wt.HWND, ctypes.c_size_t, wt.UINT, wt.LPVOID]
shell32.Shell_NotifyIconW.restype = wt.BOOL
shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
user32.SystemParametersInfoW.argtypes = [wt.UINT, wt.UINT, wt.LPVOID, wt.UINT]
user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(RECT)]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wt.UINT]
user32.SetWindowTextW.argtypes = [wt.HWND, wt.LPCWSTR]
user32.MessageBoxW.restype = ctypes.c_int
user32.MessageBoxW.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT]
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.CloseClipboard.argtypes = []
user32.EmptyClipboard.argtypes = []
user32.IsClipboardFormatAvailable.argtypes = [wt.UINT]
user32.DestroyWindow.argtypes = [wt.HWND]
user32.DestroyMenu.argtypes = [wt.HMENU]
user32.DestroyIcon.argtypes = [wt.HANDLE]
user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterWindowMessageW.restype = wt.UINT
user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.restype = LRESULT
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.PostQuitMessage.argtypes = [ctypes.c_int]

kernel32.GlobalAlloc.restype = wt.HANDLE
kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalLock.argtypes = [wt.HANDLE]
kernel32.GlobalUnlock.argtypes = [wt.HANDLE]
kernel32.GlobalFree.argtypes = [wt.HANDLE]
kernel32.GetModuleHandleW.restype = wt.HMODULE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.LocalFree.restype = wt.HLOCAL
kernel32.LocalFree.argtypes = [wt.HLOCAL]

if ctypes.sizeof(ctypes.c_void_p) == 8:
    _get_long = user32.GetWindowLongPtrW
    _set_long = user32.SetWindowLongPtrW
else:  # pragma: no cover - 32 位解释器
    _get_long = user32.GetWindowLongW
    _set_long = user32.SetWindowLongW
_get_long.restype = ctypes.c_ssize_t
_get_long.argtypes = [wt.HWND, ctypes.c_int]
_set_long.restype = ctypes.c_ssize_t
_set_long.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_ssize_t]

crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wt.LPCWSTR,
                                     ctypes.POINTER(DATA_BLOB), wt.LPVOID,
                                     wt.LPVOID, wt.DWORD,
                                     ctypes.POINTER(DATA_BLOB)]
crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB),
                                       ctypes.POINTER(wt.LPWSTR),
                                       ctypes.POINTER(DATA_BLOB), wt.LPVOID,
                                       wt.LPVOID, wt.DWORD,
                                       ctypes.POINTER(DATA_BLOB)]


# ---------------------------------------------------------------- 剪贴板
def clip_seq():
    """剪贴板变更序号。比每次开剪贴板便宜得多，用来判断"有没有变"。"""
    return int(user32.GetClipboardSequenceNumber())


def _open_clipboard(retries=20, delay=0.02):
    for _ in range(retries):
        if user32.OpenClipboard(None):
            return True
        time.sleep(delay)
    return False


def read_text():
    """读剪贴板纯文本；没有文本返回 None。"""
    if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
        return None
    if not _open_clipboard():
        return None
    try:
        h = user32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return None
        p = kernel32.GlobalLock(h)
        if not p:
            return None
        try:
            return ctypes.wstring_at(p)
        finally:
            kernel32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()


def write_text(text):
    """写剪贴板纯文本。失败返回 False（剪贴板被别的程序锁住时会失败）。"""
    data = text.encode("utf-16-le") + b"\x00\x00"
    h = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data))
    if not h:
        return False
    p = kernel32.GlobalLock(h)
    if not p:
        kernel32.GlobalFree(h)
        return False
    try:
        ctypes.memmove(p, data, len(data))
    finally:
        kernel32.GlobalUnlock(h)

    if not _open_clipboard():
        kernel32.GlobalFree(h)
        return False
    try:
        if not user32.EmptyClipboard():
            return False
        if not user32.SetClipboardData(CF_UNICODETEXT, h):
            return False
        h = None  # 所有权已交给系统
        return True
    finally:
        user32.CloseClipboard()
        if h:
            kernel32.GlobalFree(h)


# ---------------------------------------------------------------- 窗口查询
def _win_text(hwnd):
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 2)
    user32.GetWindowTextW(hwnd, buf, n + 2)
    return buf.value


def _win_class(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def foreground():
    """当前前台窗口 (hwnd, 标题, 类名)。"""
    h = user32.GetForegroundWindow()
    if not h:
        return 0, "", ""
    return int(h), _win_text(h), _win_class(h)


def find_window(title=None, cls=None):
    h = user32.FindWindowW(cls, title)
    return int(h) if h else 0


def enum_children(hwnd):
    """枚举子窗口 [(hwnd, 类名, 文本)]，验收脚本按类名/文本找按钮用。"""
    out = []
    proto = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(child, _lp):
        out.append((int(child), _win_class(child), _win_text(child)))
        return True

    user32.EnumChildWindows.argtypes = [wt.HWND, proto, wt.LPARAM]
    user32.EnumChildWindows(int(hwnd), proto(cb), 0)
    return out


def click_child(hwnd):
    """给子窗口发一次左键按下+抬起。用 PostMessage，不动真实鼠标。"""
    lp = (5 << 16) | 5
    user32.PostMessageW(int(hwnd), WM_LBUTTONDOWN, 1, lp)
    user32.PostMessageW(int(hwnd), WM_LBUTTONUP, 0, lp)


def work_area():
    r = RECT()
    user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(r), 0)
    return r.left, r.top, r.right, r.bottom


def make_noactivate(hwnd):
    """加 WS_EX_NOACTIVATE：点它、显示它都不会把前台窗口抢走。"""
    ex = _get_long(int(hwnd), GWLP_EXSTYLE)
    _set_long(int(hwnd), GWLP_EXSTYLE, ex | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW)


def show_noactivate(hwnd):
    """显示但不激活，并置顶。"""
    user32.ShowWindow(int(hwnd), SW_SHOWNOACTIVATE)
    user32.SetWindowPos(int(hwnd), HWND_TOPMOST, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)


def hide_window(hwnd):
    user32.ShowWindow(int(hwnd), SW_HIDE)


# ---------------------------------------------------------------- DPAPI
def _blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(data):
    """用当前 Windows 用户的口令保护一段字节。换用户/换机器都解不开。"""
    bin_blob, keep = _blob(data)
    out = DATA_BLOB()
    ok = crypt32.CryptProtectData(ctypes.byref(bin_blob), "desens-clip",
                                  None, None, None, CRYPTPROTECT_UI_FORBIDDEN,
                                  ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData 失败")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_unprotect(data):
    bin_blob, keep = _blob(data)
    out = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(ctypes.byref(bin_blob), None, None, None, None,
                                    CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData 失败")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


# ---------------------------------------------------------------- 托盘
WM_TRAY = WM_APP + 1
TRAY_CLASS = "DesensClipTrayWnd"


class Tray:
    """托盘图标 + 右键菜单 + 定时器。

    消息循环跑在自己的线程里，主线程留给 tkinter。所有回调都在托盘线程执行，
    回调里只许做"置标志位 / 塞队列"这种短动作。
    """

    def __init__(self, icon_path, on_tick, on_pause, on_resume, on_exit,
                 tick_ms=250, tooltip="脱敏助手", setup=None):
        self.icon_path = icon_path
        self.on_tick = on_tick
        self.on_pause = on_pause
        self.on_resume = on_resume
        self.on_exit = on_exit
        self.setup = setup      # 在消息循环所在线程里执行一次，用来建同线程的 UI
        self.tick_ms = tick_ms
        self.tooltip = tooltip
        self.paused = False
        self.tip_ok = False      # NIM_MODIFY 成功才说明托盘图标真的在
        self.hwnd = 0
        self._ready = threading.Event()
        self._ok = False
        self.err = None
        self._thread = None
        self._proc = WNDPROC(self._wndproc)   # 必须留引用，否则回调被回收
        self._hicon = None
        self._nid = None
        self._taskbar_msg = 0

    # -- 对外
    def start(self, timeout=5.0):
        self._thread = threading.Thread(target=self._run, name="tray", daemon=True)
        self._thread.start()
        self._ready.wait(timeout)
        return self._ok

    def set_paused(self, paused):
        """只在托盘线程调用（菜单命令就是在那条线程派发的），直接改图标提示。"""
        self.paused = bool(paused)
        self._apply_tip()

    def stop(self):
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
        if self._thread:
            self._thread.join(2.0)

    # -- 内部
    def _run(self):
        try:
            self._create_window()
            self._add_icon()
            if self.setup:
                self.setup()
            user32.SetTimer(self.hwnd, 1, self.tick_ms, None)
            self._ok = True
            self._ready.set()
            msg = wt.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as e:  # 托盘线程挂了不能让主线程无声无息
            self.err = e
            print("[托盘] 线程异常：%r" % (e,))
            self._ready.set()
        finally:
            self._del_icon()

    def _create_window(self):
        hinst = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._proc
        wc.hInstance = hinst
        wc.lpszClassName = TRAY_CLASS
        if not user32.RegisterClassW(ctypes.byref(wc)):
            err = ctypes.get_last_error()
            if err != 1410:  # 类已注册
                raise OSError(err, "RegisterClassW 失败")
        # 用不可见的普通窗口而不是 message-only 窗口：
        # TrackPopupMenu 要求 owner 能被 SetForegroundWindow，message-only 做不到。
        self.hwnd = int(user32.CreateWindowExW(
            0, TRAY_CLASS, "DesensClipTray", 0x80000000,  # WS_POPUP
            0, 0, 0, 0, None, None, hinst, None))
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "CreateWindowExW 失败")
        self._taskbar_msg = user32.RegisterWindowMessageW("TaskbarCreated")

    def _add_icon(self):
        hicon = None
        if self.icon_path and os.path.isfile(self.icon_path):
            hicon = user32.LoadImageW(None, self.icon_path, IMAGE_ICON, 0, 0,
                                      LR_LOADFROMFILE | LR_DEFAULTSIZE)
        if not hicon:
            hicon = user32.LoadIconW(None, wt.LPCWSTR(IDI_APPLICATION))
        self._hicon = hicon
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = hicon
        nid.szTip = self._tip_text()
        if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            raise OSError(ctypes.get_last_error(), "Shell_NotifyIcon 添加失败")
        nid.uVersion = NOTIFYICON_VERSION_4
        shell32.Shell_NotifyIconW(NIM_SETVERSION, ctypes.byref(nid))
        self._nid = nid
        self.tip_ok = True

    def _del_icon(self):
        if self._nid is not None:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            self._nid = None
        if self._hicon:
            user32.DestroyIcon(self._hicon)
            self._hicon = None

    def _tip_text(self):
        return (self.tooltip + "（已暂停）") if self.paused else (self.tooltip + "（监听中）")

    def _apply_tip(self):
        if self._nid is None:
            self.tip_ok = False
            return
        self._nid.uFlags = NIF_TIP
        self._nid.szTip = self._tip_text()
        # NIM_MODIFY 只有在图标确实注册着的时候才返回真——顺带当"图标还在"的自检
        self.tip_ok = bool(shell32.Shell_NotifyIconW(NIM_MODIFY,
                                                    ctypes.byref(self._nid)))

    def _show_menu(self):
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        user32.AppendMenuW(menu, MF_STRING | (MF_CHECKED if self.paused else 0),
                           1, "暂停监听")
        user32.AppendMenuW(menu, MF_STRING | (0 if self.paused else MF_CHECKED),
                           2, "恢复监听")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING, 3, "退出")
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        # 不先抢前台，菜单点外面不会自动消失
        user32.SetForegroundWindow(self.hwnd)
        user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                              pt.x, pt.y, 0, self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(menu)

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                ev = int(lparam) & 0xFFFF
                if ev in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._show_menu()
                return 0
            if msg == WM_TIMER:
                if self.on_tick:
                    try:
                        self.on_tick()
                    except Exception as e:
                        print("[托盘] tick 异常：%r" % (e,))
                return 0
            if msg == WM_COMMAND:
                cid = int(wparam) & 0xFFFF
                if cid == 1 and self.on_pause:
                    self.on_pause()
                elif cid == 2 and self.on_resume:
                    self.on_resume()
                elif cid == 3 and self.on_exit:
                    self.on_exit()
                return 0
            if msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            if self._taskbar_msg and msg == self._taskbar_msg:
                # 资源管理器重启后托盘图标会消失，得重新加一次
                try:
                    self._add_icon()
                except Exception:
                    pass
                return 0
        except Exception as e:
            print("[托盘] WndProc 异常：%r" % (e,))
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
