# -*- coding: utf-8 -*-
"""剪贴板脱敏助手：常驻托盘，复制到敏感内容时轻轻提醒一次。

设计要点（对应任务书）：
  * 无主窗口，只有托盘图标；托盘消息循环 + 提醒窗都在同一个工作线程里，
    主线程只负责等待退出。
  * 剪贴板用 250ms 轮询 GetClipboardSequenceNumber，序号变了才去读，
    再用内容哈希去重——同一段文本连续复制只提醒一次。
  * 提醒窗建窗即带 WS_EX_NOACTIVATE，显示用 SW_SHOWNOACTIVATE，不抢前台焦点。
  * 脱敏/还原都调用 desensitize.py 的 collect/scrub/restore_text，不重写识别逻辑。
  * 映射表用 desensitize.encrypt_map 加密落盘（与主程序同一格式），
    口令由本机 DPAPI 保护；日志只记时间和计数，不记原文。
  * 不联网、不注册自启动、不读用户目录。

用法：
    pythonw clipwatch.py            # 常驻（无控制台）
    python  clipwatch.py --show-key # 打印映射表口令（还原时要用）
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, "frozen", False)            # 打包成 exe 后 __file__ 在临时目录里


def _find_repo(start):
    """向上找到含 desensitize.py 的目录（引擎在这里）。"""
    cur = os.path.abspath(start)
    for _ in range(5):
        if os.path.exists(os.path.join(cur, "desensitize.py")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.dirname(os.path.abspath(start))


REPO = _find_repo(HERE)
# 打包版把 state 放到用户目录，否则每次都落在 _MEIxxxx 临时目录、退出即丢
STATE = os.path.join(os.environ.get("LOCALAPPDATA") or HERE, "DesensClip", "state") if FROZEN \
    else os.path.join(REPO, "state")
MAPS = os.path.join(STATE, "maps")
LOG = os.path.join(STATE, "clip.log")
KEYFILE = os.path.join(STATE, "key.bin")
def _find_icon():
    cands = [os.path.join(REPO, "app.ico")]
    if FROZEN:
        cands.insert(0, os.path.join(getattr(sys, "_MEIPASS", HERE), "app.ico"))
    cands.append(os.path.join(HERE, "app.ico"))
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[0]


ICON = _find_icon()

sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import winclip as W                                    # noqa: E402
import clipui                                          # noqa: E402
import desensitize as D                                # noqa: E402

MAX_SCAN = 200_000      # 超过这个长度不扫，避免大段粘贴把工作线程卡住
KEEP_MAPS = 30          # 映射表最多留 30 份，多了删最旧
NOTIFY_TTL = 12_000     # 提醒窗口自动消失（毫秒）
ACTION_TTL = 30_000


# ---------------------------------------------------------------- 日志
def log(event, **fields):
    """只写时间 + 计数。任何情况下都不写被复制的原文。"""
    os.makedirs(STATE, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "%s\t%s" % (ts, event)
    for k in sorted(fields):
        line += "\t%s=%s" % (k, fields[k])
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- 口令
def load_key():
    """取映射表口令。首次生成随机口令，用 DPAPI 绑当前用户保存。

    映射表=原文全集，和脱敏件一起发出去等于没脱。所以映射表必须加密；
    而口令不能明文躺盘上，交给 Windows DPAPI（只有当前用户能解）。
    """
    os.makedirs(STATE, exist_ok=True)
    if os.path.isfile(KEYFILE):
        try:
            with open(KEYFILE, "rb") as fh:
                return W.dpapi_unprotect(fh.read()).decode("ascii")
        except (OSError, ValueError):
            pass
    key = hashlib.sha256(os.urandom(32)).hexdigest()[:40]
    try:
        blob = W.dpapi_protect(key.encode("ascii"))
        with open(KEYFILE, "wb") as fh:
            fh.write(blob)
    except OSError as e:
        # 没有 DPAPI 就只在内存里用：宁可不能落盘，也不能明文落盘
        print("[警告] 口令无法用 DPAPI 保护（%s），本次映射表不落盘。" % e)
        return None
    return key


# ---------------------------------------------------------------- 主程序
class ClipApp:
    def __init__(self, args):
        self.args = args
        self.paused = False
        self.stop = threading.Event()
        self.last_seq = 0
        self.last_hash = None
        self.self_hash = None
        self.self_pending = False   # self_hash 只吃一次：刚写进去的那次回读
        self.current = None       # 当前这一次命中（原文只在内存里）
        self.key = load_key()
        self.tip = None
        self.tray = None

    # -------------------------------------------------- 工作线程
    def _setup(self):
        """在托盘线程里建提醒窗，保证它和消息循环同线程。"""
        self.tip = clipui.TipWindow()
        self.tip.on_hide = self._drop_current

    def tick(self):
        if self.paused or self.stop.is_set():
            return
        seq = W.clip_seq()
        if seq == self.last_seq:
            return
        self.last_seq = seq
        text = W.read_text()
        if not text or len(text.strip()) < 4:
            return
        h = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        if h == self.last_hash:
            return
        self.last_hash = h
        if h == self.self_hash and self.self_pending:
            self.self_pending = False
            return                    # 自己刚写进去的那一次回读，别再提醒自己
        if len(text) > MAX_SCAN:
            log("skip", reason="too_long", chars=len(text))
            return

        ctx = D.DocContext(text)
        hits = D.collect(text, ctx=ctx)
        if not hits:
            return
        mapper = D.Mapper()
        masked, n = D.scrub(text, mapper, ctx=ctx)
        if n == 0 or masked == text:
            return
        cats = {}
        for _s, _e, cat, _raw in hits:
            cats[cat] = cats.get(cat, 0) + 1
        originals = [raw for (_c, raw) in mapper.forward.keys()]
        leaks = D.leak_scan(masked, originals)
        log("hit", hits=n, cats=len(cats), chars=len(text), leak=len(leaks))

        self.current = {"original": text, "masked": masked, "hits": hits,
                        "cats": cats, "mapper": mapper, "leaks": len(leaks),
                        "mapfile": None}
        detail = "、".join("%s %d" % (c, k) for c, k in
                           sorted(cats.items(), key=lambda x: (-x[1], x[0])))
        self.tip.show("命中 %d 处 · %d 类：%s" % (n, len(cats), detail),
                      "点「脱敏」把剪贴板换成脱敏版", main_text="脱敏",
                      on_main=self.do_desens, on_close=self.on_close_tip,
                      ttl_ms=NOTIFY_TTL)

    def on_pause(self):
        self.paused = True
        if self.tray:
            self.tray.set_paused(True)
        log("pause", tip=1 if self.tray and self.tray.tip_ok else 0)

    def on_resume(self):
        self.paused = False
        # 序号对齐到当前值：暂停期间复制的东西不翻旧账，
        # 恢复后再复制一次同样的内容仍然会提醒。
        self.last_seq = W.clip_seq()
        self.last_hash = None
        if self.tray:
            self.tray.set_paused(False)
        log("resume", tip=1 if self.tray and self.tray.tip_ok else 0)

    def on_exit(self):
        log("exit")
        self.stop.set()

    def on_close_tip(self):
        self.tip.hide()

    def _drop_current(self):
        """卡片消失了（关闭/超时/还原完），内存里的原文和映射一起丢掉。"""
        self.current = None

    # -------------------------------------------------- 动作
    def do_desens(self):
        p = self.current
        if not p:
            return
        if not W.write_text(p["masked"]):
            self.tip.show("替换失败", "剪贴板被别的程序占用，请稍后重试。",
                          main_text="重试", on_main=self.do_desens,
                          on_close=self.on_close_tip, ttl_ms=8000)
            log("desens", ok=0)
            return
        self.self_hash = hashlib.sha256(
            p["masked"].encode("utf-8", "surrogatepass")).hexdigest()
        self.self_pending = True
        p["mapfile"] = self._save_map(p["mapper"])
        log("desens", ok=1, hits=len(p["hits"]), cats=len(p["cats"]),
            leak=p["leaks"], map=1 if p["mapfile"] else 0)
        sub = ("原文只在本机映射表里（%s）" % os.path.basename(p["mapfile"])
               if p["mapfile"] else "原文只在内存里，退出即失")
        self.tip.show("已脱敏，剪贴板已替换（%d 处）" % len(p["hits"]), sub,
                      main_text="还原", on_main=self.do_restore,
                      on_close=self.on_close_tip, ok=True, ttl_ms=ACTION_TTL)

    def do_restore(self):
        p = self.current
        if not p:
            return
        pairs = [(ph, raw) for (_cat, raw), ph in p["mapper"].forward.items()]
        restored, n, unknown = D.restore_text(p["masked"], pairs)
        if restored != p["original"]:
            # 映射表对不上就退回内存里的原文：宁可给对的内容，也不能给半份
            log("restore", exact=0, n=n, unknown=len(unknown))
            restored = p["original"]
        else:
            log("restore", exact=1, n=n)
        if not W.write_text(restored):
            self.tip.show("还原失败", "剪贴板被别的程序占用，请稍后重试。",
                          main_text="重试", on_main=self.do_restore,
                          on_close=self.on_close_tip, ttl_ms=8000)
            return
        self.self_hash = hashlib.sha256(
            restored.encode("utf-8", "surrogatepass")).hexdigest()
        self.self_pending = True
        self.tip.show("已还原为原文", "可以重新粘贴可读版本了。",
                      on_close=self.on_close_tip, ok=True, ttl_ms=8000)

    def _save_map(self, mapper):
        if not self.key:
            return None
        try:
            os.makedirs(MAPS, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(MAPS, "clip-%s.json" % stamp)
            body = mapper.dump(self.key)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(body, fh, ensure_ascii=False)
            self._prune_maps()
            return path
        except OSError as e:
            log("map", ok=0, err=type(e).__name__)
            return None

    @staticmethod
    def _prune_maps():
        try:
            files = sorted(os.listdir(MAPS))
        except OSError:
            return
        for name in (files[:-KEEP_MAPS] if len(files) > KEEP_MAPS else []):
            try:
                os.remove(os.path.join(MAPS, name))
            except OSError:
                pass

    # -------------------------------------------------- 生命周期
    def run(self):
        self.tray = W.Tray(ICON, on_tick=self.tick, on_pause=self.on_pause,
                           on_resume=self.on_resume, on_exit=self.on_exit,
                           tick_ms=self.args.poll_ms, tooltip="脱敏助手",
                           setup=self._setup)
        if not self.tray.start():
            log("error", where="tray_start")
            W.user32.MessageBoxW(None,
                                 "托盘图标创建失败：%r\n程序无法在后台驻留，已退出。"
                                 % (self.tray.err,), "脱敏助手", 0x10)
            return 1
        self.last_seq = W.clip_seq()
        log("start", poll=self.args.poll_ms, key=1 if self.key else 0)
        try:
            while not self.stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.tray.stop()
            log("stop")
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="剪贴板脱敏助手（常驻托盘）")
    ap.add_argument("--poll-ms", type=int, default=250, help="剪贴板轮询间隔，默认 250")
    ap.add_argument("--show-key", action="store_true", help="打印映射表口令后退出")
    ap.add_argument("--once", action="store_true", help="只扫一次当前剪贴板，打印结果后退出")
    args = ap.parse_args(argv)

    if args.show_key:
        key = load_key()
        print(key or "（无：DPAPI 不可用）")
        return 0
    if args.once:
        text = W.read_text() or ""
        hits = D.collect(text)
        print("字符数 %d，命中 %d 处" % (len(text), len(hits)))
        for s, e, cat, raw in hits:
            print("  %s\t%s" % (cat, D.mask(raw)))
        return 0
    return ClipApp(args).run()


if __name__ == "__main__":
    sys.exit(main())
