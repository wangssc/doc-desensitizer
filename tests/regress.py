# -*- coding: utf-8 -*-
"""回归测试：脱敏工具的十项关键行为。改完代码跑这一条，全 PASS 才算没改坏。

    python tests/regress.py

自带样本，不依赖任何本地遗留文件；跑完把中间产物留在 tests/_tmp/ 下（已在 .gitignore 里）。
"""
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "desensitize.py")
TMP = os.path.join(ROOT, "tests", "_tmp")
PW = "123456"
results = []

SAMPLE = """某市政务云平台密码应用安全性评估报告

建设单位：某某市大数据管理局
承建单位：新华三技术有限公司
联系人：张建国
电话：13812345678
身份证：110101199003074512
地址：浙江省杭州市西湖区文三路 88 号 3 号楼 501 室
数据库：科来网络技术股份有限公司
网关：瑞数信息技术（上海）有限公司
终端防护：北京天空卫士网络安全技术有限公司
服务器 IP：10.20.30.41
"""

ADDR = """办公地址一：浙江省杭州市西湖区文三路 88 号 3 号楼 501 室
办公地址二：江苏省南京市鼓楼区中山北路 12 号第二办公楼 7 层
"""

FP = """联系人信息表见附件。
评估人员安排如下。
联系人高标准要求。
密评人员：王强、李明、周涛
"""


def sh(*args):
    return subprocess.run([sys.executable, ENGINE] + list(args),
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def run(src, out):
    os.makedirs(out, exist_ok=True)
    return sh(src, "-o", out, "--map-password", PW)


def read_first(d, suffix):
    for f in sorted(os.listdir(d)):
        if f.endswith(suffix):
            return os.path.join(d, f)
    return None


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("[PASS] " if ok else "[FAIL] ") + name + ("  " + detail if detail else ""))


def main():
    os.makedirs(TMP, exist_ok=True)
    src = os.path.join(TMP, "sample.txt")
    with open(src, "w", encoding="utf-8", newline="") as f:
        f.write(SAMPLE)

    # 1 纯文本：该遮的全遮
    out = os.path.join(TMP, "t1")
    r = run(src, out)
    txt = open(read_first(out, "_脱敏.txt"), encoding="utf-8").read()
    bad = ["新华三", "科来", "瑞数", "天空卫士", "张建国", "13812345678",
           "110101199003074512", "某某市大数据管理局", "文三路"]
    left = [b for b in bad if b in txt]
    check("纯文本零残留", not left, "残留=" + ",".join(left) if left else "")

    # 2 还原：与原文逐字一致
    mapf = read_first(out, ".json")
    rest = os.path.join(TMP, "r1")
    os.makedirs(rest, exist_ok=True)
    sh(read_first(out, "_脱敏.txt"), "--restore", mapf, "-o", rest, "--map-password", PW)
    restored = open(read_first(rest, ".txt"), encoding="utf-8", newline="").read()
    same = hashlib.sha256(restored.encode()).hexdigest() == \
        hashlib.sha256(SAMPLE.encode()).hexdigest()
    check("还原逐字一致", same)

    # 3 地址：门牌后面的楼/室/层一起遮
    af = os.path.join(TMP, "addr.txt")
    with open(af, "w", encoding="utf-8") as f:
        f.write(ADDR)
    ao = os.path.join(TMP, "a1")
    run(af, ao)
    at = open(read_first(ao, "_脱敏.txt"), encoding="utf-8").read()
    left3 = [w for w in ("号楼", "室", "层", "办公楼", "单元") if w in at]
    check("地址尾链无残留", not left3, "残留=" + ",".join(left3) if left3 else "")

    # 4/5 docx：页脚页眉都遮，格式不坏
    from docx import Document
    from docx.shared import Pt, RGBColor

    df = os.path.join(TMP, "fmt.docx")
    d = Document()
    d.add_paragraph().add_run("建设单位：").bold = True
    run_ = d.paragraphs[0].add_run("某某市大数据管理局")
    run_.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)
    tb = d.add_table(rows=1, cols=2)
    tb.style = "Table Grid"
    tb.cell(0, 0).text = "联系人"
    tb.cell(0, 1).text = "张建国"
    d.sections[0].header.paragraphs[0].text = "内部资料 · 某某市大数据管理局"
    d.sections[0].footer.paragraphs[0].text = "第 1 页 · 张建国"
    d.save(df)

    do = os.path.join(TMP, "d1")
    run(df, do)
    d2 = Document(read_first(do, ".docx"))
    check("docx 页脚已遮", "张建国" not in d2.sections[0].footer.paragraphs[0].text,
          repr(d2.sections[0].footer.paragraphs[0].text))
    check("docx 页眉已遮", "某某市大数据管理局" not in d2.sections[0].header.paragraphs[0].text)
    colors = [str(x.font.color.rgb) for p in d2.paragraphs for x in p.runs
              if x.font.color and x.font.color.rgb]
    check("docx 颜色保留", "C00000" in colors, str(colors))

    # 6 段落一多，人名照样遮（曾经的缺陷：20 段以上人名全漏）
    for n in (5, 20, 60):
        p = os.path.join(TMP, "n%d.docx" % n)
        dd = Document()
        for i in range(n):
            dd.add_paragraph("第%d段：联系人张建国，电话13812345678。" % i)
        dd.save(p)
        o = os.path.join(TMP, "n%d-out" % n)
        run(p, o)
        d5 = Document(read_first(o, ".docx"))
        left5 = sum(1 for x in d5.paragraphs if "张建国" in x.text)
        check("多段落人名已遮(%d 段)" % n, left5 == 0, "残留段数=%d" % left5)

    # 7 不误杀
    ff = os.path.join(TMP, "fp.txt")
    with open(ff, "w", encoding="utf-8") as f:
        f.write(FP)
    fo = os.path.join(TMP, "fp-out")
    run(ff, fo)
    ft = open(read_first(fo, "_脱敏.txt"), encoding="utf-8").read()
    fp_bad = [w for w in ("联系人信息表", "评估人员安排", "高标准要求") if w not in ft]
    check("常见词未误杀", not fp_bad, "误杀=" + ",".join(fp_bad) if fp_bad else "")

    total = len(results)
    passed = sum(1 for _, ok in results if ok)
    print("\n合计 %d 项，通过 %d 项" % (total, passed))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
