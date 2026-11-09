# -*- coding: utf-8 -*-
"""
脱敏工具 · 本地网络界面服务端

只监听 127.0.0.1，不对外网开放，不上传任何数据。
启动后自动打开浏览器，界面里拖文件即可，不必敲命令。

用法：
    python desensitize_server.py
    或双击 启动脱敏工具.bat
"""
import base64
import datetime
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, parse_qs

# 控制台按 UTF-8 输出，配合 bat 里的 chcp 65001，中文提示不乱码
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---- 路径解析：源码运行 vs 打包成 exe ----
# 打包后 __file__ 指向 PyInstaller 的临时解压目录，既不能读 UI，也不能往里写输出。
if getattr(sys, "frozen", False):
    BUNDLE = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    HERE = os.path.dirname(os.path.abspath(sys.executable))
    OUTROOT = os.path.join(HERE, "out", "desens")
    # exe 可能放在 Program Files 这类不可写的位置，探测一次，不行就退到用户目录
    try:
        os.makedirs(OUTROOT, exist_ok=True)
        _probe = os.path.join(OUTROOT, ".write_probe")
        with open(_probe, "w", encoding="utf-8") as _f:
            _f.write("ok")
        os.remove(_probe)
    except Exception:
        OUTROOT = os.path.join(
            os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
            "DesensTool", "out", "desens",
        )
        os.makedirs(OUTROOT, exist_ok=True)
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
    BUNDLE = HERE
    # 输出放在本目录下的 out/desens，跟 exe 模式的规则一致：
    # 谁能复制走这个工具，谁就能连着输出目录一起复制走，不会散到上级去。
    OUTROOT = os.path.join(HERE, "out", "desens")

sys.path.insert(0, HERE)
import desensitize as D

UI_PATH = os.path.join(BUNDLE, "ui", "index.html")
LOCK = threading.Lock()
LAST = {"dir": None}
PORT = 8765


def decode_text(raw):
    for enc in ("utf-8", "utf-8-sig", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def docx_full_text(doc):
    parts = [p.text for p in doc.paragraphs]
    for tb in doc.tables:
        for row in tb.rows:
            for c in row.cells:
                parts.append(c.text)
    return "\n".join(parts)


def do_scrub(payload):
    """执行脱敏，返回结构化结果。"""
    files = payload.get("files") or []
    if not files:
        return {"ok": False, "error": "没有收到文件"}

    words = [w.strip() for w in (payload.get("words") or "").splitlines() if w.strip()]
    aggressive = bool(payload.get("aggressive"))
    # 图片是二进制，文本脱敏碰不到；勾了就整块删，不勾就原样留着并在报告里点名。
    images = "strip" if payload.get("stripImages") else "keep"
    # 映射表=原文全集。给了口令就加密，没给就是明文（报告里会写死这一条）。
    map_pwd = payload.get("mapPassword") or ""

    stamp = datetime.datetime.now().strftime("%m%d_%H%M%S")
    batch = "gui_" + stamp
    outdir = os.path.join(OUTROOT, batch)
    os.makedirs(outdir, exist_ok=True)
    LAST["dir"] = outdir
    # 原文只在系统临时目录里过一手，处理完立刻删掉：
    # out/desens 是准备拷走/外发的目录，里面绝不能躺着未脱敏的原件。
    srcdir = tempfile.mkdtemp(prefix="desens_src_")

    mapper = D.Mapper()
    stats = {"warn_no_run": []}
    results, risks = [], []
    total = 0

    try:
        for item in files:
            name = os.path.basename(item.get("name") or "unnamed")
            raw = base64.b64decode(item.get("data") or "")
            base, ext = os.path.splitext(name)
            src = os.path.join(srcdir, name)
            with open(src, "wb") as f:
                f.write(raw)

            try:
                if ext.lower() == ".docx":
                    dest = os.path.join(outdir, "%s_脱敏.docx" % base)
                    n, before, after = D.process_docx(
                        src, dest, mapper, words, aggressive, stats, images)
                else:
                    before = decode_text(raw)
                    new_text, n = D.scrub(before, mapper, words, aggressive)
                    after = new_text
                    dest = os.path.join(outdir, "%s_脱敏%s" % (base, ext or ".txt"))
                    with open(dest, "w", encoding="utf-8") as f:
                        f.write(new_text)
            except Exception as e:
                results.append({"name": name, "error": str(e)})
                continue

            for kind, line, frag in D.risk_scan(before, after):
                risks.append({"file": name, "kind": kind, "line": line, "frag": frag})

            total += n
            results.append({"name": name, "out": os.path.basename(dest),
                            "count": n, "size": len(raw)})
    finally:
        shutil.rmtree(srcdir, ignore_errors=True)

    mapfile = "映射表_%s.json" % stamp
    with open(os.path.join(outdir, mapfile), "w", encoding="utf-8") as f:
        json.dump(mapper.dump(map_pwd), f, ensure_ascii=False, indent=2)

    report = "脱敏报告_%s.md" % stamp
    with open(os.path.join(outdir, report), "w", encoding="utf-8") as f:
        f.write("# 脱敏报告\n\n生成时间：%s\n\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        f.write("## 一、处理结果\n\n| 原文件 | 脱敏文件 | 替换处数 |\n|---|---|---|\n")
        for r in results:
            if r.get("error"):
                f.write("| %s | 失败：%s | - |\n" % (r["name"], r["error"]))
            else:
                f.write("| %s | %s | %d |\n" % (r["name"], r["out"], r["count"]))
        f.write("\n## 二、各类别命中\n\n| 类别 | 数量 |\n|---|---|\n")
        for k, v in sorted(mapper.stat.items(), key=lambda x: -x[1]):
            f.write("| %s | %d |\n" % (k, v))
        f.write("\n## 三、映射表\n\n占位符与原文的对应关系见 `%s`，该文件含原文，严禁外发。%s\n"
                % (mapfile,
                   "已用口令加密，还原时要输同一个口令；口令丢了就没法还原。"
                   if map_pwd else "**本次未加密**——拿到它等于拿到原文。"))
        f.write("\n## 四、残留风险（需人工复核）\n\n")
        if risks:
            f.write("| 文件 | 风险类型 | 行号 | 遮蔽片段 |\n|---|---|---|---|\n")
            for r in risks[:200]:
                f.write("| %s | %s | %d | `%s` |\n" % (r["file"], r["kind"], r["line"], r["frag"]))
        else:
            f.write("未发现明显残留。\n")
        f.write("\n> 遮蔽片段保留首尾字符以便定位，中间以 * 代替，不代表片段全文安全。\n")

    high = [r for r in risks if D.is_high(r["kind"])]
    media_out = [{"file": os.path.basename(p), "name": n.rsplit("/", 1)[-1],
                  "size": s, "mode": m}
                 for p, items, m in stats.get("media", []) for n, s in items]
    return {"ok": True, "dir": outdir, "batch": batch, "total": total, "files": results,
            "stat": mapper.stat, "risks": risks[:200], "riskTotal": len(risks),
            "high": len(high), "mapfile": mapfile, "report": report,
            "media": media_out, "encrypted": bool(map_pwd),
            "code": 2 if high else 0}


def do_restore(payload):
    name = os.path.basename(payload.get("name") or "file")
    raw = base64.b64decode(payload.get("data") or "")
    # 新协议传整份映射表（可能是密文），口令在服务端解；老协议传 pairs，照旧兼容。
    mapdata = payload.get("map")
    try:
        if mapdata is not None:
            if isinstance(mapdata, str):
                mapdata = json.loads(mapdata)
            if D.is_encrypted(mapdata):
                mapdata = D.decrypt_map(mapdata, payload.get("mapPassword") or "")
            pairs = mapdata.get("pairs") or []
        else:
            pairs = payload.get("pairs") or []
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    pairs = sorted(((p["placeholder"], p["original"]) for p in pairs),
                   key=lambda x: -len(x[0]))
    base, ext = os.path.splitext(name)
    stamp = datetime.datetime.now().strftime("%m%d_%H%M%S")
    batch = "restore_" + stamp
    outdir = os.path.join(OUTROOT, batch)
    os.makedirs(outdir, exist_ok=True)
    LAST["dir"] = outdir

    if ext.lower() == ".docx":
        tmp = os.path.join(outdir, "_tmp.docx")
        with open(tmp, "wb") as f:
            f.write(raw)
        dest = os.path.join(outdir, "%s_还原.docx" % base)
        D.docx_restore_file(tmp, dest, pairs)
        try:
            os.remove(tmp)
        except OSError:
            pass
    else:
        text = decode_text(raw)
        for ph, orig in pairs:
            text = text.replace(ph, orig)
        dest = os.path.join(outdir, "%s_还原%s" % (base, ext or ".txt"))
        with open(dest, "w", encoding="utf-8") as f:
            f.write(text)

    return {"ok": True, "out": os.path.basename(dest), "dir": outdir, "batch": batch}


class Handler(BaseHTTPRequestHandler):
    server_version = "DesensitizeUI/1.0"

    def log_message(self, fmt, *args):
        pass  # 静默，避免刷屏

    # ---------------------------------------------------------- 工具
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _local_ok(self):
        """只接受本机来源，挡住其他网页的跨站调用和 DNS rebinding。"""
        # Host 必须是回环：rebinding 攻击时 Host 会是攻击者域名
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            return False
        origin = self.headers.get("Origin") or ""
        if not origin:
            return True
        return ("127.0.0.1" in origin) or ("localhost" in origin)

    # ---------------------------------------------------------- GET
    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        if path in ("/", "/index.html"):
            try:
                with open(UI_PATH, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, "界面文件缺失：%s" % e, "text/plain; charset=utf-8")
            return

        if path == "/api/ping":
            self._json({"app": "desens", "port": PORT, "pid": os.getpid()})
            return

        if path == "/api/config":
            # 前端启动时读一次，阈值和超时线不在页面里写死。
            # engine_version 是给以后对账用的：引擎再提速一次就改这个字符串，
            # 说明书里的用时参考和实测数字才能对上"跑的是哪一版"。
            self._json({
                "engine_version": "2026-11-08-perf1",
                "warn_mb": 5,            # 超过就提示建议拆分
                "max_free_mb": 5,        # 超过这个值要弹一次确认才放宽超时
                "timeout_base_s": 120,   # 阈值以下的默认超时
                "timeout_per_mb_s": 12,  # 超时线 = max(base, MB * per_mb)
            })
            return

        if path == "/dl":
            qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            fname = (qs.get("f") or [""])[0]
            batch = (qs.get("d") or [""])[0]
            # 批次目录必须显式给出，且只能是 OUTROOT 下一层。
            # 原来那套「该目录没有就到所有批次里按文件名找最新的一份」，
            # 会把 A 批次的下载请求悄悄解析成 B 批次的同名文件。
            if (not batch or batch != os.path.basename(batch)
                    or batch in (".", "..") or "/" in batch or "\\" in batch):
                self._send(400, "bad batch", "text/plain; charset=utf-8")
                return
            base = os.path.basename(fname)
            if not base or base != fname:
                self._send(400, "bad name", "text/plain; charset=utf-8")
                return
            target = os.path.join(OUTROOT, batch, base)
            if not os.path.isfile(target):
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            with open(target, "rb") as f:
                data = f.read()
            name = os.path.basename(target)
            disp = "attachment; filename*=UTF-8''" + "".join(
                "%%%02X" % b for b in name.encode("utf-8"))
            self._send(200, data, "application/octet-stream",
                       {"Content-Disposition": disp})
            return

        self._send(404, "not found", "text/plain; charset=utf-8")

    # ---------------------------------------------------------- POST
    def do_POST(self):
        if not self._local_ok():
            self._json({"ok": False, "error": "非本机来源，已拒绝"}, 403)
            return
        path = self.path.split("?")[0]
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except Exception as e:
            self._json({"ok": False, "error": "请求解析失败：%s" % e}, 400)
            return

        try:
            with LOCK:
                if path == "/api/scrub":
                    self._json(do_scrub(payload))
                elif path == "/api/restore":
                    self._json(do_restore(payload))
                elif path == "/api/opendir":
                    d = LAST.get("dir")
                    if d and os.path.isdir(d):
                        try:
                            os.startfile(d)
                        except Exception:
                            pass
                        self._json({"ok": True})
                    else:
                        self._json({"ok": False, "error": "还没有生成目录"})
                else:
                    self._json({"ok": False, "error": "未知接口"}, 404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._json({"ok": False, "error": str(e)}, 500)


def pick_port(start=8765):
    for p in range(start, start + 20):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            s.close()
    return start


# 本机回环请求绝不走系统代理。很多机器设了 HTTP_PROXY 却没设 NO_PROXY，
# urllib 会把 127.0.0.1 也塞给代理，导致"检测已有实例"永远失败。
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _local_get(url, timeout=1.0):
    with _LOCAL_OPENER.open(url, timeout=timeout) as r:
        return r.read()


def _listening(port, timeout=0.08):
    """快速判断端口是否有进程在监听。connect_ex 对空闲端口立即返回，不耗超时。"""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def find_running(start=8765, span=20):
    """已有本工具实例在跑就返回其端口，避免重复双击开出一堆服务和标签页。"""
    for p in range(start, start + span):
        if not _listening(p):
            continue
        try:
            d = json.loads(_local_get("http://127.0.0.1:%d/api/ping" % p).decode("utf-8"))
            if d.get("app") == "desens":
                return p
        except Exception:
            continue
    return None


def main():
    global PORT
    base_port = int(os.environ.get("DESENS_PORT", "8765"))

    # 本机地址不进代理，避免系统代理劫走回环请求
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
    os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

    # 不能靠 bind 失败来判断端口被占：Windows 的 SO_REUSEADDR 允许重复绑定，
    # 第二个实例会"成功"占住同一端口。必须先主动探测。
    if _listening(base_port):
        running = find_running(base_port)
        if running:
            url = "http://127.0.0.1:%d/" % running
            print("=" * 56)
            print("  工具已经在运行，不再重复启动。")
            print("  地址：%s" % url)
            print("  如果浏览器没有自动打开，手动复制上面的地址。")
            print("=" * 56)
            if not os.environ.get("DESENS_NO_BROWSER"):
                webbrowser.open(url)
                time.sleep(2.0)
            return
        # 端口被别的程序占着，换一个
        PORT = pick_port(base_port)
    else:
        PORT = base_port

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = "http://127.0.0.1:%d/" % PORT
    print("=" * 56)
    print("  客户资料脱敏工具已启动（本地运行，不联网）")
    print("  地址：%s" % url)
    print("  关闭本窗口即退出工具")
    print("=" * 56)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start() if not os.environ.get("DESENS_NO_BROWSER") else None
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
