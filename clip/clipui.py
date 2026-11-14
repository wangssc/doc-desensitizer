# -*- coding: utf-8 -*-
"""提醒卡片：纯 Win32 自绘小窗口（不用 tkinter）。

为什么不用 tkinter：
    tkinter 创建 Toplevel 时会调 SetForegroundWindow，哪怕窗口是 withdraw 的，
    前台也会被一个不可见窗口拿走——用户刚双击启动、紧接着敲的字就丢了。
    WS_EX_NOACTIVATE 只能在窗口创建后补，补不上那一次激活。
    这里用 CreateWindowExW 建窗时就带上 WS_EX_NOACTIVATE + WS_EX_TOOLWINDOW，
    显示用 SW_SHOWNOACTIVATE，从构造上不抢焦点。

按钮是自绘矩形 + WM_LBUTTONUP 命中测试，没有子窗口。
"""
import ctypes
import ctypes.wintypes as wt

import winclip as W

user32 = W.user32
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

LRESULT = W.LRESULT
WNDPROC = W.WNDPROC     # 复用 winclip 的回调类型，ctypes 对结构体字段要求类型完全一致

WM_PAINT = 0x000F
WM_LBUTTONUP = 0x0202
WM_TIMER = 0x0113
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_SETCURSOR = 0x0020

WS_POPUP = 0x80000000
WS_EX_TOPMOST = 0x00000008
CS_DBLCLKS = 0x0008
IDC_HAND = 32649
IDC_ARROW = 32512

DT_LEFT = 0x0000
DT_CENTER = 0x0001
DT_RIGHT = 0x0002
DT_VCENTER = 0x0004
DT_WORDBREAK = 0x0010
DT_SINGLELINE = 0x0020
DT_NOPREFIX = 0x0800
DT_CALCRECT = 0x0400
DT_END_ELLIPSIS = 0x8000

TRANSPARENT = 1
PS_SOLID = 0
FW_NORMAL = 400
FW_BOLD = 700
DEFAULT_CHARSET = 1
CLEARTYPE_QUALITY = 5
NULL_PEN = 8
NULL_BRUSH = 5

TIP_TIMER = 2
TITLE = "DesensClipTip"


class PAINTSTRUCT(ctypes.Structure):
    _fields_ = [("hdc", wt.HDC), ("fErase", wt.BOOL), ("rcPaint", W.RECT),
                ("fRestore", wt.BOOL), ("fIncUpdate", wt.BOOL),
                ("rgbReserved", ctypes.c_ubyte * 32)]


WNDCLASSW = W.WNDCLASSW


gdi32.CreateSolidBrush.restype = wt.HANDLE
gdi32.CreateSolidBrush.argtypes = [wt.DWORD]
gdi32.CreatePen.restype = wt.HANDLE
gdi32.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, wt.DWORD]
gdi32.CreateFontW.restype = wt.HANDLE
gdi32.CreateFontW.argtypes = [ctypes.c_int] * 5 + [wt.DWORD] * 8 + [wt.LPCWSTR]
gdi32.SelectObject.restype = wt.HANDLE
gdi32.SelectObject.argtypes = [wt.HDC, wt.HANDLE]
gdi32.DeleteObject.argtypes = [wt.HANDLE]
gdi32.SetTextColor.argtypes = [wt.HDC, wt.DWORD]
gdi32.SetBkMode.argtypes = [wt.HDC, ctypes.c_int]
user32.DrawTextW.argtypes = [wt.HDC, wt.LPCWSTR, ctypes.c_int,
                            ctypes.POINTER(W.RECT), wt.UINT]
gdi32.RoundRect.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int]
gdi32.CreateRoundRectRgn.restype = wt.HANDLE
gdi32.CreateRoundRectRgn.argtypes = [ctypes.c_int] * 6
user32.SetWindowRgn.argtypes = [wt.HWND, wt.HANDLE, wt.BOOL]
user32.SetWindowRgn.restype = ctypes.c_int
gdi32.GetStockObject.restype = wt.HANDLE
gdi32.GetStockObject.argtypes = [ctypes.c_int]
user32.BeginPaint.restype = wt.HDC
user32.BeginPaint.argtypes = [wt.HWND, ctypes.POINTER(PAINTSTRUCT)]
user32.EndPaint.argtypes = [wt.HWND, ctypes.POINTER(PAINTSTRUCT)]
user32.GetDC.restype = wt.HDC
user32.GetDC.argtypes = [wt.HWND]
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.FillRect.argtypes = [wt.HDC, ctypes.POINTER(W.RECT), wt.HANDLE]
user32.FrameRect.argtypes = [wt.HDC, ctypes.POINTER(W.RECT), wt.HANDLE]
user32.InvalidateRect.argtypes = [wt.HWND, ctypes.POINTER(W.RECT), wt.BOOL]
user32.UpdateWindow.argtypes = [wt.HWND]
user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wt.UINT]
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE,
                                   wt.LPVOID]
user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.SetTimer.argtypes = [wt.HWND, ctypes.c_size_t, wt.UINT, wt.LPVOID]
user32.KillTimer.argtypes = [wt.HWND, ctypes.c_size_t]
user32.DestroyWindow.argtypes = [wt.HWND]
user32.SetCursor.argtypes = [wt.HANDLE]
user32.LoadCursorW.restype = wt.HANDLE
user32.LoadCursorW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
user32.GetClientRect.argtypes = [wt.HWND, ctypes.POINTER(W.RECT)]
user32.ScreenToClient.argtypes = [wt.HWND, ctypes.POINTER(W.POINT)]
user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(W.RECT)]
try:
    user32.GetDpiForWindow.argtypes = [wt.HWND]
    user32.GetDpiForWindow.restype = wt.UINT
except AttributeError:      # Win7 之前没有这个 API
    pass


def _rgb(r, g, b):
    return r | (g << 8) | (b << 16)


COL_BG = _rgb(0xFF, 0xFF, 0xFF)
COL_BORDER = _rgb(0xD8, 0xDE, 0xE6)
COL_MUTED = _rgb(0x6B, 0x72, 0x80)
COL_TEXT = _rgb(0x11, 0x18, 0x27)
COL_OK = _rgb(0x04, 0x78, 0x57)
COL_WARN = _rgb(0xB4, 0x53, 0x09)
COL_PRIMARY = _rgb(0x2F, 0x6F, 0xEB)
COL_PRIMARY_TXT = _rgb(0xFF, 0xFF, 0xFF)
COL_SECOND = _rgb(0xF3, 0xF4, 0xF6)
COL_SECOND_TXT = _rgb(0x37, 0x41, 0x51)

FONT_FACE = "Microsoft YaHei UI"
FONT_PT = 12

WIDTH = 460          # 96 DPI 下的逻辑宽度
HEIGHT = 132         # 96 DPI 下的逻辑高度（固定，不随文字长短跳动）
PAD = 16             # 四边内边距
RADIUS = 12          # 卡片四角圆角半径
BTN_RADIUS = 6       # 按钮圆角半径
BTN_H = 28
BTN_MAIN_W = 88
BTN_NO_W = 72
CLOSE_W = 22
CLOSE_H = 22


def button_rects(width, height, scale=1.0):
    """按钮命中矩形（客户区坐标）。绘制和点击都用这一份，验收脚本也调它。"""
    s = scale
    pad = int(PAD * s)
    by = height - pad - int(BTN_H * s)
    main = (pad, by, pad + int(BTN_MAIN_W * s), by + int(BTN_H * s))
    no_l = main[2] + int(8 * s)
    no = (no_l, by, no_l + int(BTN_NO_W * s), by + int(BTN_H * s))
    x_top = pad - int(2 * s)
    x = (width - pad - int(CLOSE_W * s), x_top,
         width - pad, x_top + int(CLOSE_H * s))
    return {"main": main, "no": no, "x": x}


def _inside(rect, x, y):
    return rect[0] <= x < rect[2] and rect[1] <= y < rect[3]


class TipWindow:
    """一张卡片，创建一次，之后只改状态和位置。"""

    def __init__(self, hwnd_parent=None):
        self.hwnd = 0
        self.scale = 1.0
        self.state = "hidden"
        self.msg = ""
        self.sub = ""
        self.msg_color = COL_TEXT
        self.main_text = "脱敏"
        self.on_main = None
        self.on_close = None
        self.on_hide = None       # 卡片一消失就通知上层：内存里的原文可以丢了
        self._proc = WNDPROC(self._wndproc)
        self._fonts = {}
        self._brushes = {}
        self._pens = {}
        self._cursors = {}
        self._lh = {}
        self._body_top = int(PAD)
        self._msg_h = 0
        self._sub_h = 0
        self._title_h = 0
        self._create(hwnd_parent)

    # ------------------------------------------------------------ 建窗
    def _create(self, parent):
        hinst = W.kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.style = CS_DBLCLKS
        wc.lpfnWndProc = self._proc
        wc.hInstance = hinst
        wc.lpszClassName = "DesensClipTipWnd"
        if not user32.RegisterClassW(ctypes.byref(wc)):
            if ctypes.get_last_error() != 1410:
                raise OSError(ctypes.get_last_error(), "RegisterClassW 失败")
        ex = W.WS_EX_NOACTIVATE | W.WS_EX_TOOLWINDOW | WS_EX_TOPMOST
        self.hwnd = int(user32.CreateWindowExW(
            ex, "DesensClipTipWnd", TITLE, WS_POPUP,
            0, 0, WIDTH, HEIGHT, parent, None, hinst, None))
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "创建提醒窗口失败")
        try:
            self.scale = max(1.0, user32.GetDpiForWindow(self.hwnd) / 96.0)
        except Exception:
            self.scale = 1.0
        self._make_fonts()

    def _font(self, key, pt, weight=FW_NORMAL):
        if key not in self._fonts:
            px = int(round((pt or FONT_PT) * 96 / 72 * self.scale))
            self._fonts[key] = gdi32.CreateFontW(
                -px, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                CLEARTYPE_QUALITY, 0, FONT_FACE)
        return self._fonts[key]

    def _brush(self, color):
        if color not in self._brushes:
            self._brushes[color] = gdi32.CreateSolidBrush(color)
        return self._brushes[color]

    def _pen(self, color, width=1):
        key = (color, width)
        if key not in self._pens:
            self._pens[key] = gdi32.CreatePen(PS_SOLID, width, color)
        return self._pens[key]

    def _cursor(self, kind):
        if not self._cursors:
            self._cursors["hand"] = user32.LoadCursorW(None, wt.LPCWSTR(IDC_HAND))
            self._cursors["arrow"] = user32.LoadCursorW(None, wt.LPCWSTR(IDC_ARROW))
        return self._cursors[kind]

    def _make_fonts(self):
        # 统一 12pt，只有标题加粗，层级靠颜色和字重区分
        self._font("title", FONT_PT, FW_BOLD)
        self._font("msg", FONT_PT)
        self._font("sub", FONT_PT)
        self._font("btn", FONT_PT)
        for k in ("title", "msg", "sub", "btn"):
            self._lh[k] = self._measure("国Ag", k, 10000, single=True)

    # ------------------------------------------------------------ 对外
    def show(self, msg, sub, main_text=None, on_main=None, on_close=None,
             ok=False, ttl_ms=12000):
        self.state = "shown"
        self.msg = msg
        self.sub = sub
        self.msg_color = COL_OK if ok else COL_TEXT
        self.main_text = main_text or ""
        self.on_main = on_main
        self.on_close = on_close
        self._relayout()
        W.show_noactivate(self.hwnd)
        user32.InvalidateRect(self.hwnd, None, True)
        user32.UpdateWindow(self.hwnd)
        if ttl_ms:
            user32.SetTimer(self.hwnd, TIP_TIMER, ttl_ms, None)

    def hide(self):
        was = self.state
        self.state = "hidden"
        user32.KillTimer(self.hwnd, TIP_TIMER)
        W.hide_window(self.hwnd)
        if was != "hidden" and self.on_hide:
            self.on_hide()

    def destroy(self):
        if self.hwnd:
            user32.DestroyWindow(self.hwnd)
            self.hwnd = 0

    def rects(self):
        r = W.RECT()
        user32.GetWindowRect(self.hwnd, ctypes.byref(r))
        return button_rects(r.right - r.left, r.bottom - r.top, self.scale)

    # ------------------------------------------------------------ 布局
    def _measure(self, text, font_key, width, single=False):
        hdc = user32.GetDC(self.hwnd)
        try:
            old = gdi32.SelectObject(hdc, self._font(font_key, 0))
            r = W.RECT(0, 0, width, 0)
            flags = DT_LEFT | DT_NOPREFIX | DT_CALCRECT
            flags |= DT_SINGLELINE if single else DT_WORDBREAK
            user32.DrawTextW(hdc, text, -1, ctypes.byref(r), flags)
            gdi32.SelectObject(hdc, old)
            return max(1, r.bottom - r.top)
        finally:
            user32.ReleaseDC(self.hwnd, hdc)

    def _line_h(self, font_key):
        if not self._lh.get(font_key):
            self._lh[font_key] = self._measure("国Ag", font_key, 10000, single=True)
        return self._lh[font_key]

    def _round_corners(self, w, h):
        """整窗套圆角区域：四角透明，圆角半径 RADIUS。窗口没换，只是可见形状变了。"""
        r = int(RADIUS * self.scale)
        rgn = gdi32.CreateRoundRectRgn(0, 0, w + 1, h + 1, 2 * r, 2 * r)
        if not rgn:
            return
        if not user32.SetWindowRgn(self.hwnd, rgn, True):
            gdi32.DeleteObject(rgn)

    def _relayout(self):
        s = self.scale
        w = int(WIDTH * s)
        h = int(HEIGHT * s)          # 高度固定，文字长短不再改变窗口尺寸
        pad = int(PAD * s)
        lh_t = self._line_h("title")
        lh_m = self._line_h("msg")
        lh_s = self._line_h("sub")
        by = h - pad - int(BTN_H * s)          # 按钮行顶部
        body_top = pad + lh_t

        sub_h = lh_s if self.sub else 0
        avail = by - int(6 * s) - body_top
        msg_h = avail - sub_h if sub_h else avail
        if sub_h and msg_h < lh_m:             # 放不下就牺牲副标题，正文优先
            sub_h = 0
            msg_h = avail
        msg_h = max(lh_m, msg_h)

        self._body_top = body_top
        self._title_h = lh_t
        self._msg_h = msg_h
        self._sub_h = sub_h

        left, top_w, right, bottom = W.work_area()
        x = max(left + 8, right - w - int(18 * s))
        y = max(top_w + 8, bottom - h - int(18 * s))
        user32.SetWindowPos(self.hwnd, W.HWND_TOPMOST, x, y, w, h,
                            W.SWP_NOACTIVATE)
        self._round_corners(w, h)

    # ------------------------------------------------------------ 绘制
    def _paint(self, hdc):
        s = self.scale
        r = W.RECT()
        user32.GetClientRect(self.hwnd, ctypes.byref(r))
        w, h = r.right, r.bottom
        gdi32.SetBkMode(hdc, TRANSPARENT)

        # 背景：窗口已经被圆角区域裁过，直接填满就是圆角白底
        user32.FillRect(hdc, ctypes.byref(r), self._brush(COL_BG))
        self._frame_round(hdc, w, h)

        pad = int(PAD * s)
        rects = button_rects(w, h, s)

        # 标题（12pt 加粗）
        old = gdi32.SelectObject(hdc, self._font("title", 0))
        gdi32.SetTextColor(hdc, COL_MUTED)
        tr = W.RECT(pad, pad, w - pad - int(CLOSE_W * s) - int(4 * s),
                    pad + self._title_h)
        user32.DrawTextW(hdc, "脱敏助手", -1, ctypes.byref(tr),
                        DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX)
        gdi32.SelectObject(hdc, old)

        # 右上角关闭
        xr = W.RECT(*rects["x"])
        old = gdi32.SelectObject(hdc, self._font("title", 0))
        gdi32.SetTextColor(hdc, COL_MUTED)
        user32.DrawTextW(hdc, "×", -1, ctypes.byref(xr),
                        DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX)
        gdi32.SelectObject(hdc, old)

        y = self._body_top
        mr = W.RECT(pad, y, w - pad, y + self._msg_h)
        old = gdi32.SelectObject(hdc, self._font("msg", 0))
        gdi32.SetTextColor(hdc, self.msg_color)
        if self._sub_h:
            mflags = (DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS
                      | DT_NOPREFIX)
        else:
            mflags = DT_LEFT | DT_WORDBREAK | DT_NOPREFIX
        user32.DrawTextW(hdc, self.msg, -1, ctypes.byref(mr), mflags)
        gdi32.SelectObject(hdc, old)

        if self._sub_h:
            sy = y + self._msg_h
            sr = W.RECT(pad, sy, w - pad, sy + self._sub_h)
            old = gdi32.SelectObject(hdc, self._font("sub", 0))
            gdi32.SetTextColor(hdc, COL_MUTED)
            user32.DrawTextW(hdc, self.sub, -1, ctypes.byref(sr),
                            DT_LEFT | DT_SINGLELINE | DT_VCENTER
                            | DT_END_ELLIPSIS | DT_NOPREFIX)
            gdi32.SelectObject(hdc, old)

        null_pen = gdi32.GetStockObject(NULL_PEN)
        old_pen = gdi32.SelectObject(hdc, null_pen)
        old_font = gdi32.SelectObject(hdc, self._font("btn", 0))

        if self.main_text:
            self._button(hdc, rects["main"], self.main_text,
                         COL_PRIMARY, COL_PRIMARY_TXT)
        self._button(hdc, rects["no"], "关闭", COL_SECOND, COL_SECOND_TXT)

        gdi32.SelectObject(hdc, old_pen)
        gdi32.SelectObject(hdc, old_font)

    def _frame_round(self, hdc, w, h):
        """1px 圆角描边，跟着圆角区域走。"""
        s = self.scale
        old_pen = gdi32.SelectObject(hdc, self._pen(COL_BORDER, max(1, int(s))))
        old_br = gdi32.SelectObject(hdc, gdi32.GetStockObject(NULL_BRUSH))
        r = int(RADIUS * s)
        gdi32.RoundRect(hdc, 0, 0, w, h, 2 * r, 2 * r)
        gdi32.SelectObject(hdc, old_br)
        gdi32.SelectObject(hdc, old_pen)

    def _button(self, hdc, rect, text, bg, fg):
        old = gdi32.SelectObject(hdc, self._brush(bg))
        r = int(BTN_RADIUS * self.scale)
        gdi32.RoundRect(hdc, rect[0], rect[1], rect[2], rect[3], 2 * r, 2 * r)
        gdi32.SelectObject(hdc, old)
        gdi32.SetTextColor(hdc, fg)
        tr = W.RECT(rect[0], rect[1], rect[2], rect[3])
        user32.DrawTextW(hdc, text, -1, ctypes.byref(tr),
                        DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX)

    # ------------------------------------------------------------ 消息
    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_PAINT:
                ps = PAINTSTRUCT()
                hdc = user32.BeginPaint(hwnd, ctypes.byref(ps))
                try:
                    self._paint(hdc)
                finally:
                    user32.EndPaint(hwnd, ctypes.byref(ps))
                return 0
            if msg == WM_LBUTTONUP:
                x = ctypes.c_short(lparam & 0xFFFF).value
                y = ctypes.c_short((lparam >> 16) & 0xFFFF).value
                r = W.RECT()
                user32.GetClientRect(hwnd, ctypes.byref(r))
                rects = button_rects(r.right, r.bottom, self.scale)
                if _inside(rects["main"], x, y) and self.main_text and self.on_main:
                    self.on_main()
                elif _inside(rects["no"], x, y):
                    if self.on_close:
                        self.on_close()
                    else:
                        self.hide()
                elif _inside(rects["x"], x, y):
                    if self.on_close:
                        self.on_close()
                    else:
                        self.hide()
                return 0
            if msg == WM_TIMER and wparam == TIP_TIMER:
                self.hide()
                return 0
            if msg == WM_SETCURSOR:
                r = W.RECT()
                user32.GetClientRect(hwnd, ctypes.byref(r))
                rects = button_rects(r.right, r.bottom, self.scale)
                pt = W.POINT()
                user32.GetCursorPos(ctypes.byref(pt))
                user32.ScreenToClient(hwnd, ctypes.byref(pt))
                hand = any(_inside(rects[k], pt.x, pt.y) for k in ("main", "no", "x"))
                if hand:
                    user32.SetCursor(self._cursor("hand"))
                else:
                    user32.SetCursor(self._cursor("arrow"))
                return 1
            if msg == WM_CLOSE:
                self.hide()
                return 0
        except Exception as e:
            print("[提醒窗] 异常：%r" % (e,))
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
