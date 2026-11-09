# -*- coding: utf-8 -*-
"""
客户资料本地脱敏工具（纯本地运行，不联网、不上传）

用途：把客户方案/资料里的可识别信息替换成统一占位符，使文本可以安全外发，
      同时保留方案撰写所需的全部技术颗粒度（数据量、架构、算法、指标）。

用法：
    # 1) 处理单个文件或整个目录
    python desensitize.py 客户端资料.docx
    python desensitize.py 客户端资料/ -o out/desens

    # 2) 用自定义词表补充（最可靠的方式，每行一个词）
    python desensitize.py 资料.docx --dict 敏感词表.txt

    # 3) 还原（把占位符换回原文，仅在本地用）
    python desensitize.py 脱敏版.docx --restore out/desens/映射表_xxx.json

    # 4) 映射表加密（映射表=原文全集，和脱敏件一起发出去等于没脱）
    python desensitize.py 资料.docx --map-password 自定口令
    python desensitize.py 脱敏版.docx --restore 映射表_xxx.json --map-password 自定口令

输出：
    脱敏文件 + 映射表_<时间>.json（含原文，严禁外发）+ 脱敏报告.md（不含原文）

退出码：0 正常；2 有高风险残留（提示人工复核）
"""
import argparse
import base64
import bisect
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import unicodedata

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------- 基础工具

# 占位符类别清单只在这里维护一份，三处正则（识别/还原/回检）都用它拼。
PH_CATS = ("单位|机关|人员|系统|未分类|邮编|IP|域名|型号|电话|邮箱|证件号|编号|路径|账号"
           "|组织|自定义|厂商|产品|日期|地址|机房")

PLACEHOLDER_RE = re.compile(r"\[(" + PH_CATS + r")\d*\]")


class Mapper:
    """保证同一原文实体全文映射到同一占位符，编号自增。"""

    def __init__(self):
        self.forward = {}   # (类别, 原文) -> 占位符
        self.backward = {}  # 占位符 -> 原文
        self.counter = {}
        self.stat = {}
        self.alias = {}     # (类别, 原文) -> (类别, 规范名)：同一实体的另一种写法
        self.force = {}     # 原文 -> 类别：表格「物理位置」列整格按地址脱，不按机房

    def link(self, cat, raw, canon):
        """把 raw 并入 canon 的编号：表格「物理环境名称」和「物理位置」是同一个机房。"""
        canon = self.alias.get((cat, canon), (cat, canon))[1]
        if raw == canon or (cat, raw) in self.forward:
            return False
        self.alias[(cat, raw)] = (cat, canon)
        return True

    def get(self, cat, raw):
        cat = self.force.get(raw.strip(), cat)
        cat, raw = self.alias.get((cat, raw), (cat, raw))
        key = (cat, raw)
        if key in self.forward:
            return self.forward[key]
        self.counter[cat] = self.counter.get(cat, 0) + 1
        ph = "[%s%d]" % (cat, self.counter[cat])
        self.forward[key] = ph
        self.backward[ph] = raw
        self.stat[cat] = self.stat.get(cat, 0) + 1
        return ph

    def dump(self, password=None):
        """password 非空则加密。映射表=原文全集，明文落盘的代价是全盘皆输。"""
        # 别名不单独占编号：pairs 只留规范名，别名记在 aliases 里备查。
        pairs = [{"category": c, "placeholder": p, "original": o}
                 for (c, o), p in self.forward.items()]
        aliases = [{"placeholder": self.forward[k], "original": raw}
                   for (c, raw), k in self.alias.items() if k in self.forward]
        body = {
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
            "note": "此文件包含原文，仅限本地保存，严禁外发。",
            "pairs": pairs,
        }
        if aliases:
            body["aliases"] = aliases
        return encrypt_map(body, password) if password else body


# ---------------------------------------------------------------- 映射表加密
# 标准库里没有 AES，所以用 PBKDF2-HMAC-SHA256 派生两把密钥，
# 一把用 HMAC-SHA256 作计数器生成密钥流异或（等价 CTR 模式），另一把做
# 加密后校验。这挡的是"误把映射表当附件发出去"这一类事故，不是抗定向破解。
MAP_FORMAT = "desens-map-v2"
MAP_ITER = 200000


def _keystream(key, nonce, n):
    buf = bytearray()
    ctr = 0
    while len(buf) < n:
        buf += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(buf[:n])


def _derive(password, salt):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, MAP_ITER, 64)
    return dk[:32], dk[32:]


def encrypt_map(body, password):
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _derive(password, salt)
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(raw, _keystream(enc_key, nonce, len(raw))))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return {"format": MAP_FORMAT, "kdf": "pbkdf2-hmac-sha256", "iterations": MAP_ITER,
            "cipher": "hmac-sha256-ctr", "salt": b64(salt), "nonce": b64(nonce),
            "tag": b64(tag), "data": b64(ct)}


def is_encrypted(data):
    return isinstance(data, dict) and data.get("format") == MAP_FORMAT


def decrypt_map(data, password):
    """口令错/文件被改过都抛 ValueError，绝不返回半份原文。"""
    if not password:
        raise ValueError("映射表已加密，需要输入口令")
    salt = base64.b64decode(data.get("salt") or "")
    nonce = base64.b64decode(data.get("nonce") or "")
    ct = base64.b64decode(data.get("data") or "")
    tag = base64.b64decode(data.get("tag") or "")
    enc_key, mac_key = _derive(password, salt)
    if not hmac.compare_digest(tag, hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("口令不对，或映射表已被改动")
    raw = bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct))))
    return json.loads(raw.decode("utf-8"))


def load_map(path, password=None):
    """读映射表；老版本明文 JSON 照常读，不要求口令。"""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return decrypt_map(data, password) if is_encrypted(data) else data


# ---------------------------------------------------------------- 反向还原（文本）
# 用户从 AI 那边复制回来的文本里，占位符常被加空格：[人员 1]、[ 人员1 ]、[人员1 ]。
# 只认「去掉空白后与映射表完全一致」的，认不出就原样留着并报出来。
# 换错名字比留着占位符危险得多——绝不猜。
RE_BRACKET_TOKEN = re.compile(r"[\[［]\s*([^\[\]［］\n]{1,40}?)\s*[\]］]")
# 长得像本工具占位符（类别 + 可选编号）的，才值得报「不认识」；
# 普通方括号内容（[注]、[1]）不该进 unknown 列表。
RE_PH_LIKE = re.compile(r"(?:" + PH_CATS + r")\d*", re.I)


def _norm_ph(s):
    return re.sub(r"\s+", "", s)


def restore_text(text, pairs, unknown=None):
    """占位符 → 原文，容错空白。返回 (新文本, 替换处数, 未知占位符列表)。

    pairs 为 [(占位符, 原文)]。只替换映射表里确切存在的条目；
    不认识的括号内容原样保留，并记进 unknown。一次扫描完成，不会把
    替换结果再当占位符替换一遍（原文里带方括号也不会被二次污染）。
    """
    table = {_norm_ph(ph).strip("[]［］"): orig for ph, orig in pairs}
    unk = unknown if unknown is not None else []
    seen = set(unk)
    n = 0

    def repl(m):
        nonlocal n
        key = _norm_ph(m.group(1))
        if key in table:
            n += 1
            return table[key]
        if RE_PH_LIKE.fullmatch(key):
            tok = "[%s]" % key
            if tok not in seen:
                seen.add(tok)
                unk.append(tok)
        return m.group(0)

    return RE_BRACKET_TOKEN.sub(repl, text), n, unk


def leak_scan(text, originals, min_len=2):
    """在脱敏后的文本里搜映射表的真值。返回 [(真值, 出现次数)]，按次数降序。

    这是「脱敏漏了」的最后一道闸：引擎没识别出来的真名会原样留在文本里。
    用一条合并正则扫一遍，避免「几百个真值 × 几十万字」的重复全文搜索。
    """
    vals = [v for v in dict.fromkeys(originals) if v and len(v) >= min_len]
    if not vals or not text:
        return []
    vals.sort(key=len, reverse=True)
    canon = {}
    for v in vals:
        canon.setdefault(v.lower(), v)
    rx = re.compile("|".join(re.escape(v) for v in vals), re.I)
    cnt = {}
    for m in rx.finditer(text):
        k = m.group(0).lower()
        cnt[k] = cnt.get(k, 0) + 1
    return sorted(((canon.get(k, k), c) for k, c in cnt.items()),
                  key=lambda x: (-x[1], -len(x[0])))


# ---------------------------------------------------------------- 文档级上下文
# 识别规则是逐段落的，但有两件事只有看完整篇才判断得准：
#   1) 高频词不是人名。"符合""应用""安全"在整份报告里出现几十上百次，
#      再像的名字形状也不是人名。整篇词频是最省事、也最不容易误伤的闸门。
#   2) 反复出现的长串是同一个实体。系统全名在报告里出现 38 次，
#      只在第一次没认出来，后面 37 次就会拆成"前半截占位符 + 后半截原文"。
# 所以先把整篇扫一遍，得到「词频表 + 长实体词典」，再逐段替换。

CJK_RUN = re.compile(r"[\u4e00-\u9fa5]{2,}")
# 长实体的结尾词。只认多字后缀 + 局/厅/委 这三个不会当普通字用的单字，
# 不再把 所/社/站/厂/院 这类高频单字当机构结尾（"岗位所需""智慧人社""站点证书"
# 全是被它们咬出来的）。
LEX_SUFFIX = re.compile(
    r"(?:管理委员会|股份有限公司|有限责任公司|有限公司|研究院|研究所|设计院|事务所|"
    r"分公司|子公司|总公司|管理局|委员会|办公室|分行|支行|信用社|农商行|"
    r"系统|平台|中心|公司|集团|银行|医院|学院|大学|中学|小学|学校|机场|车站|"
    r"厅|局|委)")
# 长实体左边允许裁掉的虚词/连接词（"经过国家密码管理局"→"国家密码管理局"）
LEX_TRIM = set("的了在由向对与和及或为是该本我你他她它这那有所把被将等使同从到给于至"
               "依据按照根据经过受委托确保提供面向部署通过包括以及关于位于属于作为成为"
               "构成形成实现采用使用具备满足达到涉及包含涵盖针对结合支持承载进行开展完成")
# 长实体必须是"地名开头"或"强机构后缀结尾"。否则"安全门禁系统""保证信息系统"
# 这种整篇出现十几次的通用短语都会被当成系统名整体换掉。
PLACE_PREFIX = re.compile(r"^[\u4e00-\u9fa5]{2,4}(?:省|市|区|县|自治区)")
STRONG_TAIL = re.compile(
    r"(?:股份有限公司|有限责任公司|有限公司|公司|集团|银行|医院|大学|学院|研究院|"
    r"研究所|设计院|事务所|管理局|管理委员会|委员会|办公室|分行|支行|信用社|"
    r"农商行|监狱|机场|车站)$")
LEX_BAD_HEAD = ("项目", "工作", "管理", "业务", "应用", "信息", "服务", "安全", "密码",
                "网络", "数据", "系统", "平台", "技术", "运营", "建设", "实施", "方案",
                "相关", "本次", "所有", "全部", "部分", "各类", "通用", "目标", "当前")
RE_POSTCODE_CTX = re.compile(r"(?:邮政编码|邮编|地址)[\s:：]{0,6}([0-8]\d{5})(?!\d)")


def _classify_entity(name):
    """实体名 → 占位符类别。不再有"自定义"这个兜底。"""
    if re.search(r"(?:机房|数据中心|灾备中心)$", name):
        return "机房"
    if re.search(r"(?:系统|平台|云|项目|工程)$", name):
        return "系统"
    if re.search(r"(?:公司|集团|银行|医院|学校|学院|大学|研究院|研究所|设计院|事务所|"
                 r"中心|管理局|管理委员会|委员会|办公室|分行|支行|信用社|农商行|"
                 r"厅|局|委|院|所|协会|学会|基金会|商会|联合会|机场|车站|监狱)$", name):
        return "单位"
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-—_/\.]{2,}", name):
        return "型号"
    return "未分类"


def _mostly_heading(term, text):
    """这个长串是不是主要在当"整行标题"用（目录项 / 章节名）。"""
    total = head = 0
    for ln in text.splitlines():
        if term not in ln:
            continue
        total += ln.count(term)
        body = RE_TOC_LEADER.sub("", RE_HEADING_NUM.sub("", ln).strip()).strip()
        if body == term:
            head += 1
    return total > 0 and head * 2 >= total


class DocContext:
    """整篇文档的词频表、长实体词典、邮编集合。"""

    def __init__(self, text=""):
        self.counts = {}      # 2~4 字中文词频
        self.lexicon = []     # [(term, cat)]
        self.postcodes = set()
        if text:
            self._build(text)

    def count(self, term):
        return self.counts.get(term, 0)

    def _build(self, text):
        counts = self.counts
        for run in CJK_RUN.finditer(text):
            s = run.group(0)
            for size in (2, 3, 4):
                for i in range(len(s) - size + 1):
                    g = s[i:i + size]
                    counts[g] = counts.get(g, 0) + 1

        # 长实体：在一个中文串里，从串首（或裁掉虚词后）到后缀词结尾的整段。
        # 只有整篇出现 >= 3 次的才算实体——一次性的短语更可能是句子，不是名字。
        freq = {}
        for run in CJK_RUN.finditer(text):
            s = run.group(0)
            for m in LEX_SUFFIX.finditer(s):
                end = m.end()
                starts = {0}
                for k in range(1, 5):
                    if k < end and s[k - 1] in LEX_TRIM:
                        starts.add(k)
                for st in starts:
                    term = s[st:end]
                    if not (6 <= len(term) <= 40) or term in freq:
                        continue
                    place = bool(PLACE_PREFIX.match(term))
                    if not place:
                        # 系统/平台/中心 这类通用结尾，必须有地名前缀才算实体
                        if term.endswith(("系统", "平台", "中心")):
                            continue
                        if not STRONG_TAIL.search(term):
                            continue
                        if term.startswith(LEX_BAD_HEAD):
                            continue
                    c = text.count(term)
                    if c >= 3:
                        freq[term] = c
        kept = []
        for t in sorted(freq, key=len, reverse=True):
            if any(t != k and t in k for k in kept):
                continue
            # 整篇反复出现、但每次都是"整行标题"的长串，是章节名不是实体。
            # 目录里同一标题出现两三次，旧版会把它当长实体整体换成 [未分类N]。
            if _mostly_heading(t, text):
                continue
            kept.append(t)
        self.lexicon = [(t, _classify_entity(t)) for t in kept]

        for m in RE_POSTCODE_CTX.finditer(text):
            self.postcodes.add(m.group(1))


# ---------------------------------------------------------------- 识别规则

# 机构后缀（按长度降序，保证最长匹配优先）。
# 只保留多字后缀和"局/厅/委"这三个不会当普通字用的单字。
# 旧版把 所/社/站/厂/院 也当后缀，结果"岗位所""智慧人社""站点证书""密码设备厂"
# 全被咬成机构名，再被切成"前半截占位符 + 后半截原文"——这是拆分错误的根。
ORG_TAILS = [
    "卫生健康委员会", "疾病预防控制中心", "医疗保障局", "市场监督管理局",
    "股份有限公司", "有限责任公司", "有限公司", "集团", "公司",
    "人民医院", "中医院", "妇幼保健院", "卫生院", "儿童医院", "肿瘤医院",
    "精神卫生中心", "医疗集团", "急救中心", "血液中心", "检验中心", "影像中心",
    "医科大学", "大学", "学院", "中学", "小学", "幼儿园",
    "研究院", "研究所", "设计院", "勘察院", "测绘院",
    "银行", "支行", "分行", "信用社", "农商行",
    "管理局", "管理委员会", "委员会", "办公室", "指挥部", "项目办",
    "监狱", "戒毒所", "看守所", "机场", "车站", "港务局",
    "供电公司", "发电厂", "水务集团", "燃气公司", "热力公司",
    "药房", "药店", "制药", "生物科技", "医疗器械", "医学检验",
    "事务所", "协会", "学会", "基金会", "商会", "联合会",
    "医院", "中心", "厅", "局",
]
ORG_TAIL_RE = re.compile("|".join(re.escape(t) for t in dict.fromkeys(ORG_TAILS)))

# 左向回溯到此字符即停止。数字和门牌字也停：否则
# "…路1036号S02楼浪潮云计算中心" 会把整条地址并进机构名。
ORG_STOP = set(
    "的了在由向对与及或为是该本我你他她它这那有所把被将等把被使同从到给受于"
    "与并而且但则即就都也还又再很更最太不没无"
    "0123456789０１２３４５６７８９号楼座层室"
    "，。；：、！？（）()[]{}<>《》\"'`\n\t\r 　·—…/"
)
# 注意："和" 不在上面——"山东省人力资源和社会保障厅" 里的"和"是名字的一部分。

# 回溯时遇到这些连接词就停：它们左边一定不是机构名的一部分。
# 这是"经过国家密码管理局""依据山东省医疗保障局""委托道普信息技术有限公司"
# 被整串吞掉的原因——回溯不能无限向左，得在动词/介词处切断。
ORG_CONNECT = ("委托", "依据", "经过", "按照", "根据", "负责", "确保", "提供", "面向",
               "部署", "通过", "包括", "以及", "关于", "位于", "属于", "作为", "成为",
               "构成", "形成", "实现", "采用", "使用", "具备", "满足", "达到", "涉及",
               "包含", "涵盖", "针对", "结合", "支持", "承载", "进行", "开展", "完成",
               "组织", "要求", "规定", "明确", "提出")
# 回溯时遇到这些词就停：它们左边一定不是机构名的一部分。
ORG_HARD_STOP = ("政务外网", "大厦", "大楼", "广场", "机房", "楼宇", "园区")
# 名字开头可以裁掉的虚字。年月日号第 是必须的：回溯会从"局"一路吃到
# "2017年4月国家密码管理局"的"月"，替换后就变成"2017年4[单位1]颁发"。
ORG_TRIM_HEAD = set("的了在由向对与和及或为是该本各全单同按共约近达超占两三其此这那"
                    "年月日号第")
# 单字介词：回溯会把紧贴实体左侧的介词一起吞进来（"经山东省大数据局批准"）。
# 只有去掉介词后仍是"省/市/区/县 + 机构"的形态才右移一位；
# "经济开发区"这类真名以"经济/经营"开头，不在其列。
PREP_ONE = set("经由据向对在为被将把")
PREP_FALSE = ("经济", "经营", "经验", "经管")
RE_ADMIN_HEAD = re.compile(r"[\u4e00-\u9fa5]{2,3}(?:省|自治区|市|区|县)")
# 以这些词开头的机构名一定是通用说法（"项目全局""项目管理委员会"）
ORG_BAD_START = ("项目", "工作", "相关", "本次", "全部", "所有", "部分", "各类",
                 "其他", "目标", "当前", "通用", "统一", "上述", "以下")

# 本身就是通用说法、无识别性的机构串
ORG_BLACK = {
    "本院", "我院", "该院", "外院", "贵院", "院", "医院", "综合医院", "专科医院",
    "三级医院", "二级医院", "一级医院", "基层医院", "定点医院", "公立医院",
    "民营医院", "社区医院", "乡镇卫生院", "互联网医院", "线上医院", "智慧医院",
    "网络医院", "儿童医院", "中医医院", "人民医院", "中心医院", "妇幼保健院",
    "第三方机构", "测评机构", "评估机构", "建设单位", "使用单位", "运维单位",
    "管理机构", "监管部门", "主管部门", "密码管理部门", "公安机关", "行业主管部门",
    "该中心", "数据中心", "云服务商", "云服务提供商", "服务商", "厂商", "供应商",
    "有限公司", "股份有限公司", "集团公司", "总公司", "分公司", "子公司",
    "本项目", "本系统", "本方案", "本院信息科", "信息中心", "网络中心",
    "业务系统", "应用系统", "操作系统", "信息系统", "管理系统", "服务平台",
    "支撑平台", "数据平台", "网络平台", "业务平台", "应用平台", "基础平台",
    "密码平台", "云平台", "短信平台", "消息中心", "该系统", "各系统", "子系统",
    "密码系统", "安全系统", "监控系统", "审计系统", "认证系统", "授权系统",
    "管理系统", "办公系统", "门户系统", "网站系统", "平台系统", "中心平台",
}
# "核心/业务/应用 + 系统"这类"通用修饰词 + 后缀"整体不算实体。
ORG_GENERIC_HEAD = set(
    "业务 应用 操作 信息 管理 服务 支撑 数据 网络 统一 基础 密码 云 该 本 各 子 大 中 小 新 老 "
    "主 备 安全 防护 存储 传输 交换 接入 核心 汇聚 终端 移动 互联 办公 生产 测试 开发 运维 "
    "监控 审计 认证 授权 访问 通信 计算 资源 虚拟 容灾 备份 应急 智能 数字 电子 政务 公共 "
    "综合 行业 企业 个人 客户 用户 后台 前台 前端 中台 消息 短信 邮件 支付 结算 财务 人事 "
    "档案 门户 网站 发布 采集 分析 展示 调度 控制 前置 中间 接口 协议 标准 规范 指南 要求 "
    "方案 报告 制度 流程 体系 平台 系统 中心 两级 三级 二级 一级 同一 不同 相关 所有 全部 "
    "费用 消息 短信 模板 审批 统计 监控 工作台 首页 模块 功能 业务 数据 项目管理".split())

# 复姓（用于姓名识别）
# 只用《百家姓》前 300 个姓。旧版把整本百家姓（含"通/关/国/别/重/指/产/密/客/口/科"）
# 都当姓，于是"通过""关键""国产""别设""重要""指标""口令""科员"全被判成人名。
SURNAME = (
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐"
    "费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄"
    "和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁"
    "杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍"
    "虞万支柯昝管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石崔吉钮龚"
    "程嵇邢滑裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富巫乌焦巴弓"
    "牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景詹束龙"
    "叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴胥能苍双闻"
    "莘党翟谭贡劳逄姬申扶堵冉宰郦雍郤璩桑桂濮牛寿通边扈燕冀郏浦尚农温"
    "别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘匡"
    "国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简饶空曾"
    "毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公"
)
# 上表是《百家姓》前 300 位；"通/关/国"排在第 300 位之后，这里显式截断，
# 保证它们不会被当成姓氏（"通过""关键""国产"是最常见的三个误判）。
SURNAME = SURNAME[:300]
COMPOUND_SURNAME = ["欧阳", "司马", "上官", "诸葛", "东方", "独孤", "皇甫", "尉迟",
                    "公孙", "慕容", "长孙", "宇文", "司徒", "夏侯", "令狐", "钟离"]

# 职务/称谓锚点（前后出现时，旁边的 2-3 字视为人名）。
# 去掉了"客户/患者/病人/医生/医师/护士长/老师/同学/先生/女士"——
# 它们是通用名词，不是职务锚点。"客户端后访问"里的"端后"就是这么来的。
ROLE_WORDS = ("责任人", "负责人", "联系人", "编制人", "编写人", "审核人", "审定人",
              "批准人", "签名人", "操作人", "经办人", "承办人", "接收人", "移交人",
              "监交人", "主任", "院长", "副院长",
              "科长", "处长", "局长", "经理", "项目经理", "工程师",
              "管理员", "安全管理员", "密钥管理员", "审计员",
              "姓名", "患者姓名", "户名", "开户人", "持证人", "签字人", "签发人")

# 以姓开头但并非人名的常见词（避免"项目负责人"被当成"项"姓+"目"）
NOT_NAME = {
    "项目", "本院", "该院", "全院", "外院", "科室", "医院", "系统", "信息", "安全",
    "操作", "管理", "维护", "值班", "交接", "负责", "签字", "审核", "批准", "编制",
    "设备", "网络", "数据", "业务", "服务", "平台", "机房", "云商", "厂商", "供应商",
    "密码", "密钥", "证书", "日志", "主机", "数据库", "影像", "报告", "终端", "用户",
    "本次", "所有", "全部", "相关", "以上", "以下", "上述", "附表", "附件", "表格",
}

# 任何情况下都不当人名/实体替换的词。分三类：
#   1) 评估结论与表头（"评估结果"列只可能是这几个值）
#   2) 技术动词/名词
#   3) 职务与通用称谓
# 这一层是硬闸门，不依赖上下文判断——它们在任何位置都不是敏感信息。
NEVER_ENTITY = frozenset((
    # 结论词（评估结果列的闭集）
    "通过", "未通过", "符合", "基本符合", "不符合", "部分符合", "不适用",
    "有效", "无效", "部分符合", "未评估", "已评估",
    # 表头词
    "标准要求", "指标要求", "指标说明", "测评方法", "预期结果", "适用对象",
    # 数量与程度词
    "重要", "一般", "关键", "主要", "次要", "较高", "较低", "高", "中", "低",
    # 技术动词/名词
    "解密", "加密", "签名", "验签", "部署", "集成", "配置", "调试", "架设", "运维",
    "审计", "鉴别", "存储", "传输", "校验", "初始化", "轮换", "销毁", "归档", "备份",
    "解释", "应用", "安装", "成功", "失败", "登录", "认证", "授权", "访问", "连接",
    "通信", "计算", "处理", "保护", "管理", "维护", "运行", "使用", "采用", "支持",
    "实现", "国产", "国密", "站点", "客户", "用户", "终端", "后台", "前端", "接口",
    "口令", "账户", "账号", "密码", "密钥", "证书", "系统", "平台", "中心", "单位",
    # 职务/通用称谓
    "科员", "主任", "处长", "局长", "经理", "工程师", "管理员", "审计员", "操作员",
    "技术员", "负责人", "联系人", "审核人", "批准人", "编制人", "责任人", "用户",
    # 常见双字通用词（激进模式会在"金额 100022"这类位置把它们当人名）
    "金额", "数量", "单价", "总价", "合计", "小计", "时间", "日期", "方式", "情况",
    "内容", "数据", "信息", "功能", "模块", "接口", "设备", "网络", "服务", "技术",
    "业务", "流程", "制度", "方案", "报告", "指标", "要求", "结果", "结论", "建议",
    "意见", "范围", "对象", "层面", "章节", "表格", "附件", "附录", "单独", "全部",
    "部分", "相关", "本次", "目前", "当前", "一般", "主要", "其他", "所有", "以上",
    "以下", "上述", "如下", "包括", "以及", "并且", "但是", "因此", "由于", "如果",
))
# 3 字候选的末字若命中这里，说明更像「姓+名+动词/方位」，不是名字
NOT_NAME_CHARS = set(
    "的了是在和与及或为由向对该本各全单同按分共约近达超占"
    "提补说认表示指出讲问答需要应当可能会将已未不没无有"
    "这那其此我你他她它们个些种次项条款章节段句字位名组类批期年月日时分秒"
    "后前时员长师工性度化法制用设备端台面里外上下左右区域层网库表文图数")
# 名字里不可能出现的词（"应符合""指标要求"这类短句会被激进模式切成 3 字候选）
NAME_BAD_SUB = ("符合", "要求", "通过", "重要", "指标", "口令", "系统", "平台",
                "证书", "密码", "密钥", "管理", "使用", "采用", "实现", "保证",
                "保护", "进行", "提供", "支持", "部署", "配置", "审计", "鉴别",
                "存储", "传输", "签名", "加密", "解密", "应用", "安装", "登录")

# "××市""某区"这类已是占位形态，不重复处理
RE_PLACEHOLDERISH = re.compile(r"(?:[×xX某]{1,4}|\*{1,4})(?:省|市|区|县|镇|路|街|大道|医院|公司|局|院)")

# 标准/规范号白名单前缀（绝不能脱敏）
STD_PREFIX = (r"(?:ISO/IEC|ISO|IEC|IEEE|RFC|ANSI|NIST|ITU|"
              r"GB|GM|GA|CM|WS|YY|YD|SJ|JR)")

# 真实文档里标准号的分隔符经常是全角（GB／T 37092、GM／T 0016），
# 空格也常是　。旧写法只认半角 / 和空格，于是整条标准号漏过保护，
# 里面的 "T 37092" 被型号规则吃掉，输出成 "GB／[型号1]"。
# 末尾必须是"非字母非数字"：只挡字母时，"GM2024CERT0001234" 里的 "GM202"
# 仍会被认成标准号，并把它整串证书编号从命中列表里挤掉。
RE_STD = re.compile(
    STD_PREFIX + r"[ \u3000]*[／/_]?[ \u3000]*[Tt]?[ \u3000]*[0-9０-９]"
    r"[0-9０-９.\-—–:：／/_]*(?![A-Za-z0-9])", re.I)
RE_IDCARD = re.compile(r"(?<![0-9])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9])")
RE_MOBILE = re.compile(r"(?<![0-9])1[3-9]\d{9}(?![0-9])")
RE_TEL = re.compile(r"(?<![0-9])0\d{2,3}[- ]?\d{7,8}(?:[-转]\d{1,5})?(?![0-9])")
RE_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:/\d{1,2})?(?![\d.])")
RE_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])")
RE_MAC = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_DOMAIN = re.compile(
    r"(?<![@\w\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|cn|net|org|edu|gov|mil|int|biz|info|local|lan|internal|corp|cloud|top|xyz"
    r"|io|ai|app|dev|tech|site|store|shop|co|me|tv|cc|vip|pro|online|work|link|live"
    r"|fun|space|website|host|zone|asia|hk|tw|jp|kr|sg|us|uk|de|fr|ru)(?![\w\-])", re.I)
RE_URL = re.compile(r"https?://[^\s，。；、）)\"'<>]+", re.I)
# 必须允许路径里出现空格（"C:\Program Files\App\bin\server.exe"），
# 旧写法 [^\s...] 会在第一个空格处截断，把剩余部分原样留在文档里。
RE_WINPATH = re.compile(r"[A-Za-z]:\\(?:[^\\\r\n，。；：、！？（）【】《》\"'<>|]|\\){2,}")
# Linux/macOS 路径。前面排除 / 和 : 是为了不咬进 http:// 的协议头。
RE_UNIXPATH = re.compile(r"(?<![\w:/.])/(?:[\w.\-]+/){2,}[\w.\-]+")
RE_ACCOUNT = re.compile(r"(?:账号|帐号|用户名|登录名|account|user\s*name)\s*[:：=]?\s*([A-Za-z][A-Za-z0-9_.\-]{2,31})(?![A-Za-z0-9])", re.I)
# 编号类：靠锚点取整体，避免被型号规则切碎
RE_ID_ANCHOR = re.compile(
    r"(?:工号|病案号|住院号|门诊号|序列号|流水号|单号|合同编号|项目编号|招标编号|"
    r"证书编号|证书序列号|备案号|受理号|批号|档案号|资产编号|设备编号|订单号)"
    r"\s*[:：=]?\s*([A-Za-z0-9][A-Za-z0-9\-—_/.]{3,40})"
)
# 公文文号：×卫规〔2024〕87 号 / 〔2024〕第 87 号
RE_DOCNO = re.compile(r"[\u4e00-\u9fa5×xX]{0,8}〔\s*\d{4}\s*〕\s*第?\s*\d{1,5}\s*号")
# 门牌地址：××路 168 号。
# 名字部分不能含"路/街/巷"——否则 "南市高新区舜华路街道新泺大街2008号" 会从
# "南市"一路吃到"大街2008号"，把 "济南市" 切掉前两字，这正是拆分错误的来源。
RE_STREET = re.compile(
    r"(?:(?!路|街|巷|道|省|市|区|县)[\u4e00-\u9fa5]){2,12}"
    r"(?:路|街|大道|大街|巷|胡同|里弄)\s*\d{1,5}\s*(?:号|号楼|栋|座|层|室)?")
# 楼宇名：技术文本里"大厦/广场/大楼"几乎不会作为通用词出现，单独认是安全的。
# 只认这三类，不碰"中心/园区"，避免误伤"数据中心""园区网"。
RE_BUILDING = re.compile(r"[\u4e00-\u9fa5]{2,12}(?:大厦|广场|大楼)")
# 地址尾部："B座3层""12层1203室"，跟在大厦/门牌后面时一并吃掉
RE_ADDR_TAIL = re.compile(r"(?:[A-Za-z]\s*)?\d{0,3}\s*座(?:\s*\d{1,3}\s*层)?"
                          r"|(?<![0-9])\d{1,3}\s*层(?:\s*\d{1,4}\s*室)?"
                          r"|(?<![0-9])\d{1,4}\s*室")
# 链式行政区划：省+市、市+区/县。只认连续两级，避免"服务器区""三个区域"被误伤
RE_ADMIN_CHAIN = re.compile(
    r"[\u4e00-\u9fa5]{2,3}(?:省|自治区)[\u4e00-\u9fa5]{2,4}(?:市|州|盟)(?:[\u4e00-\u9fa5]{2,4}(?:区|县|市))?"
    r"|[\u4e00-\u9fa5]{2,4}(?:市)[\u4e00-\u9fa5]{2,4}(?:区|县|市)"
)
# 楼宇名规则定义见上（RE_BUILDING / RE_ADDR_TAIL）
ADMIN_BAD_HEAD = ("服务", "管理", "防护", "存储", "缓冲", "办公", "功能", "业务", "生产",
                  "测试", "开发", "接入", "核心", "汇聚", "安全", "隔离", "设备", "机柜",
                  "区域", "专", "园", "校", "病", "社", "辖", "该", "本", "各", "分",
                  "片", "新", "老", "东", "西", "南", "北", "中", "内", "外", "位", "地",
                  "受", "保", "密", "公", "私", "云", "网", "数", "机", "主", "备",
                  "两", "三", "四", "五", "六", "七", "八", "九", "十", "几", "多", "每",
                  "单", "全", "同", "整", "划", "按", "分")
# 链式匹配时允许从头部裁掉的虚词（裁完仍能构成完整地名）
ADMIN_TRIM = set("位于地处坐建属在至于至从到的和与及为是由向对该本各全单同按分共约近达超占两三")
ADMIN_BAD_WHOLE = {"小区", "社区", "园区", "校区", "辖区", "地区", "本市", "该市", "全县",
                   "各区", "省市", "市县", "城区", "郊区", "山区", "市区", "县城", "乡镇",
                   "区域", "专区", "市区"}

# 品牌 + 型号词（GE Revolution CT / Siemens MAGNETOM Vida）
RE_BRAND_MODEL = re.compile(    r"(?:%s)\s+([A-Z][A-Za-z0-9]{2,}(?:[ -][A-Z0-9][A-Za-z0-9\-]*){0,2})"
    % "|".join(re.escape(b) for b in ("GE Healthcare", "GE", "Siemens Healthineers",
                                      "Siemens", "Philips", "Canon", "Toshiba", "Hitachi",
                                      "Fujifilm", "Mindray", "United Imaging", "Neusoft",
                                      "Carestream", "HUAWEI", "华为", "H3C", "Cisco", "思科"))
)
BRAND_MODEL_OK_WORD = {"SSL", "TLS", "VPN", "CT", "MR", "DR", "US", "IPSec", "HTTP",
                       "HTTPS", "API", "KMS", "HSM", "CA", "TSA", "PACS", "HIS", "LIS"}

# 品牌（保留品牌、脱型号；品牌+型号连续出现时整体处理）
BRANDS = ("华为", "HUAWEI", "H3C", "华三", "新华三", "思科", "Cisco", "锐捷", "Ruijie",
          "中兴", "ZTE", "深信服", "Sangfor", "天融信", "TopSec", "绿盟", "NSFOCUS",
          "启明星辰", "Venustech", "奇安信", "安恒", "迪普", "迈普", "山石", "飞塔",
          "Fortinet", "Palo Alto", "F5", "A10", "CheckPoint", "戴尔", "Dell", "惠普",
          "HPE", "联想", "Lenovo", "浪潮", "Inspur", "曙光", "Sugon", "IBM", "Oracle",
          "微软", "Microsoft", "阿里云", "腾讯云", "华为云", "天翼云", "移动云", "联通云",
          "GE", "GE Healthcare", "Siemens", "Siemens Healthineers", "Philips",
          "Canon", "Toshiba", "Hitachi", "Fujifilm", "柯尼卡", "迈瑞", "Mindray",
          "联影", "United Imaging", "东软", "Neusoft", "锐珂", "Carestream", "万东")
RE_BRAND = re.compile("|".join(re.escape(b) for b in BRANDS), re.I)
RE_MODEL = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]{1,6}[- ]?\d{2,5}[A-Za-z0-9\-]{0,12})(?![A-Za-z0-9])")
RE_MODEL_EXCLUDE = re.compile(r"^(?:SM[2349]|GM|GB|IPV[46]|SHA|AES|RSA|ECC|TLCP|TLS|SSL|IPSec|HMAC|CBC|CTR|GCM|PKCS|VLAN|MTU|QOS|RAID|SSD|HDD|NTP|SNMP|SSH|HTTP|HTTPS|FTP|SMTP|DNS|DHCP|LDAP|API|CPU|GPU|RAM|USB|KVM|RAID[0-9]|IPV4|OSPF|BGP|MPLS|VPN|WAF|IDS|IPS|HIS|PACS|LIS|EMR|CA|KMS|HSM|TCM|TPM)", re.I)

# 长型号：真实产品名比 RE_MODEL 假设的长得多。
#   OceanStor Pacific 9520（产品线 + 系列 + 编号，中间有空格）
#   AntiDDoS1905-N / AntiDDoS1908（字母串 8 位，超过旧规则的 6 位上限）
#   ViGapV6.5-3500HWG（带小数点版本号）
#   DAS-RAS-100（多段连字符）
# 四条都要求"字母 + 数字混排"，纯英文缩写不会被咬进来。
RE_MODEL_LONG = re.compile(
    r"(?<![A-Za-z0-9])("
    r"[A-Z][a-z]+[A-Z][A-Za-z0-9]{1,12}(?:[ ][A-Z][A-Za-z]{1,12}){0,2}[ ]\d{3,5}(?:[-–][A-Za-z0-9]{1,8})?"
    r"|[A-Za-z][A-Za-z]{1,11}\d{2,5}(?:[-–][A-Za-z0-9]{1,10})*"
    r"|[A-Za-z]{2,12}\d+\.\d+(?:[-–][A-Za-z0-9]{1,10})*"
    r"|[A-Za-z]{2,12}(?:[-_][A-Za-z0-9]{1,12}){2,}"
    r")(?![A-Za-z0-9])")
# 型号开头的技术缩写：这些不是产品型号，是协议/算法/版本
MODEL_TECH_HEAD = frozenset((
    "TLS", "SSL", "SM", "SHA", "AES", "RSA", "ECC", "TLCP", "IPV", "HTTP", "HTTPS",
    "SSH", "HMAC", "PKCS", "RAID", "GB", "GM", "CM", "ISO", "IEC", "USB", "API",
    "CPU", "GPU", "V", "DDR", "PCI", "PCIE", "SATA", "NVME", "IDE", "SCSI"))
# "OB数据库"这类：产品代号 + 数据库，整体按产品记
RE_DB_PRODUCT = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9]{1,5}数据库")

# 保留不改的常见技术串
KEEP = re.compile(r"^(?:SM[2349]|HIS|PACS|LIS|EMR|CA|KMS|HSM|TLS|SSL|IPSec|TLCP|VPN|WAF|API|CPU|USB|AES|RSA|SHA|MD5|CBC|CTR|GCM|RAM|SSD|HDD|IOPS|GB|TB|MB|KB|Mbps|Gbps|NFS|CIFS|SMB|FTP|SFTP|SNMP|NTP|SYSLOG|BIG-IP|RAID|VLAN|NAC|OCSP|CRL|TSA|RA|DICOM|HL7|OFD|PDF)$", re.I)

# ---------------------------------------------------------------- 保护白名单
# 这些词在真实资料里高频出现，形状上又容易撞进识别规则（"解""符""通""关""全"
# 都是姓，激进模式会把"解密""符合""通过""关键""全局"当人名）。命中白名单即不替换。
# 但只在**独立成词**时生效：前后必须是行首/行尾/空白/标点。
# 所以"重要客户张三"里的"重要"不是独立成词，不会把"客户张三"整串放过。
WHITELIST_WORDS = frozenset((
    # 结论词
    "通过", "未通过", "符合", "基本符合", "不符合", "部分符合", "不适用",
    # 表头词
    "标准要求", "指标说明", "测评方法", "预期结果", "适用对象",
    # 数量与程度词
    "1", "2", "3", "重要", "一般", "关键", "主要", "次要",
    # 常见技术词
    "解密", "加密", "部署", "集成", "站点证书", "如下", "全局", "采用", "分设",
    "配置", "运行", "维护",
))
WHITELIST_BOUND = set(
    " \t\r\n\u3000，。；：、！？（）()［］[]【】{}<>《》〈〉“”‘’\"'`·—…-_,.;:!?/\\|"
)

# ---------------------------------------------------------------- 厂商与产品
# 已知厂商 / 产品单独分类：它们是"谁家的东西"，不是客户自己的单位名。
# 用户口径：公开厂商也脱。密评材料里出现具体厂商名可反推项目，
# 而且方案里已经有 [厂商N] 这一类，不脱就与它不一致。
VENDORS = ("深信服", "浪潮", "华为", "新华三", "华三", "天融信", "奇安信", "启明星辰",
           "绿盟", "安恒", "四川虹信", "虹信", "三未信安", "光电安辰", "伟思",
           "吉大正元", "卫士通", "中电科", "格尔软件", "数字认证", "江南天安",
           "三零卫士", "得安信息", "海泰方圆", "信安世纪", "江南信安")
PRODUCTS = ("统信 UOS", "PolarDB", "OceanBase", "GaussDB", "TiDB", "达梦", "麒麟", "渔翁")

RE_VENDOR = re.compile(
    "|".join(re.escape(v) for v in sorted(VENDORS, key=len, reverse=True)) + r"(?!云)")
RE_PRODUCT = re.compile(
    r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])"
    % "|".join(re.escape(p).replace(r"\ ", r"\s*")
               for p in sorted(PRODUCTS, key=len, reverse=True)), re.I)

# ---------------------------------------------------------------- 日期（条件替换）
RE_DATE = re.compile(
    r"(?<!\d)(?:19|20)\d{2}(?:年\d{1,2}月\d{1,2}日|\.\d{1,2}\.\d{1,2}|-\d{1,2}-\d{1,2})(?![\d.])")
RE_DATE_PARTS = re.compile(
    r"(\d{4})年(\d{1,2})月(\d{1,2})日|(\d{4})\.(\d{1,2})\.(\d{1,2})|(\d{4})-(\d{1,2})-(\d{1,2})")
# 主语是这些的日期属于技术事实：证书有效期、上线时间、版本发布时间、标准年份。
# 换成占位符读者就没法判断方案对不对，所以一律保留。
TECH_SUBJECT_WORDS = ("系统", "证书", "版本", "标准", "密码模块")
# 能把日期定位到某个人/某份合同的词。出现这些词，即使句子里没直接写人名单位，
# 也算"能定位到个人或单位"。
PERSONAL_DATE_WORDS = ("签订", "签署", "订立", "出生", "生于", "入职", "入司",
                       "投标", "开标", "毕业", "离职", "退休", "聘任", "任命", "签发",
                       "有效期")

# 邮编：6 位，首位 0-8（9 开头不是有效邮编）
RE_POSTCODE = re.compile(r"(?<!\d)[0-8]\d{5}(?!\d)")



def _org_core(name):
    """去掉结尾的机构后缀，返回修饰部分。用于判断是不是"通用词 + 后缀"。"""
    m = ORG_TAIL_RE.search(name)
    return name[:m.start()] if m else name


def _ok_org(name):
    core = name.strip()
    if len(core) < 3 or len(core) > 40:
        return False
    # 3 字只放行"××局/厅/委"（医保局、财政厅），"费用中心"这类不放
    if len(core) == 3 and not core.endswith(("局", "厅", "委")):
        return False
    if core in ORG_BLACK:
        return False
    # 全是通用词组合（如"该医院""三级医院""业务系统""短信平台"）
    if core.lstrip("该本我你他其此这那各全单同") in ORG_BLACK:
        return False
    if core.startswith(ORG_BAD_START):
        return False
    if not _org_core(core):
        return False
    if _org_core(core) in ORG_GENERIC_HEAD:
        return False
    if re.fullmatch(r"[一二三四五六七八九十第次级]*(?:医院|中心|局|委|厅)", core):
        return False
    # 以"的"开头等异常
    if core[0] in "的了在和与及或为是":
        return False
    return True


def find_orgs(text):
    """最长匹配：从后缀向左一直回溯到标点/连接词，不再截断到 12 字。

    旧版两个问题：
      1) 回溯上限 12 字，长系统名只认到一半（"山东省医疗保障局…消息中心"）；
      2) 遇到"委托/依据/经过"不停，把两个机构连成一个（"疗保障局委托道普…公司"）。
    现在回溯到连接词就停，再裁掉开头的虚字，剩下的才是机构名。
    """
    out = []
    for m in ORG_TAIL_RE.finditer(text):
        end = m.end()
        s = m.start()
        limit = max(0, s - 40)
        while s > limit:
            ch = text[s - 1]
            # 括号里的地名是公司名的一部分（"高维密码测评技术(山东)有限公司"）。
            # ORG_STOP 里有括号，这里必须先放行，否则整串只剩"有限公司"四个字。
            if ch in "()（）":
                s -= 1
                continue
            # 数字/符号/序号圈码一律停（"②政务外网医保局"）
            if not ("\u4e00" <= ch <= "\u9fa5" or "A" <= ch <= "Z" or "a" <= ch <= "z"):
                break
            if ch in ORG_STOP:
                break
            two = text[s - 2:s]
            four = text[max(0, s - 4):s]
            if two in ORG_CONNECT or two in ORG_HARD_STOP or four in ORG_HARD_STOP:
                break
            s -= 1
        while s < end - 3 and (text[s] in ORG_TRIM_HEAD or text[s] in "()（）"):
            s += 1
        # "经山东省大数据局"：回溯不停在单字介词上，起点右移一位把介词留给正文。
        # 只认"介词 + 行政区划/国家机构"的形态——"为民服务中心"这种真名不动。
        if s < end - 3 and text[s] in PREP_ONE and text[s:s + 2] not in PREP_FALSE:
            rest = text[s + 1:end]
            if RE_ADMIN_HEAD.match(rest) or rest.startswith(("国家", "中国")):
                s += 1
        name = text[s:end].strip()
        if _ok_org(name):
            out.append((s, end, "单位", name))
    return out


_ROLE_ALT = "|".join(re.escape(r) for r in ROLE_WORDS)

# 「××人员」「成员」「参与人」这类表头不在职务表里，但报告里就是拿它当姓名标签用
# （"密评人员：王强、李明"）。它们只走「表头 + 冒号/换行 + 姓名」这一条路，
# 不参与「姓名 + 职务」，也不允许省略冒号——否则"人员安排"会被读成"安"姓"排"。
LIST_ROLE_WORDS = ("人员", "成员", "参与人", "评审人", "评估人", "参评人", "密评人")
_LABEL_ALT = "|".join(re.escape(r) for r in
                      sorted(LIST_ROLE_WORDS, key=len, reverse=True))

# 人名列表的分隔符：顿号、中英文逗号、斜杠、空格。
# 不含换行——跨行续名会把上一行表头接到下一段的第一个词上。
NAME_SEP = r"[、，,/／ \u3000\t]"
# 姓名后面必须是分隔符/标点/行尾，否则 greedy 的 {2,3} 会把"王强负责"吃成"王强负"。
NAME_END = r"(?=[、，,/／\s，。；！？：（）()【】]|$)"
RE_NAME_TOKEN = re.compile(r"([\u4e00-\u9fa5]{2,3})" + NAME_END)
RE_NAME_SEP_RUN = re.compile(NAME_SEP + "+")

RE_PERSON_AFTER_ROLE = re.compile(
    r"(?:%s)\s*[:：]?\s*([\u4e00-\u9fa5]{2,3})%s" % (_ROLE_ALT, NAME_END))
# 表头型标签：冒号是必需的，"人员安排""成员单位"这类词组才不会被切开
RE_PERSON_LABEL_COLON = re.compile(
    r"(?:%s)\s*[:：]\s*([\u4e00-\u9fa5]{2,3})%s" % (_LABEL_ALT, NAME_END))
# 换行式（"密评人员\n王强、李明"）：姓名后面必须紧跟列表分隔符或标点/行尾。
# 只要求"后面是空白"的话，"密评人员\n高标准要求"会把"高标准"当成人名。
RE_PERSON_LABEL_LINE = re.compile(
    r"(?:%s)[ \u3000\t]*\r?\n[ \u3000\t]*([\u4e00-\u9fa5]{2,3})"
    r"(?=[、，,/／。；！？：（）()【】]|$)" % _LABEL_ALT)
# 左边界必须不是汉字："分别设置密钥管理员"里的"别设"、"均通过用户名"里的"通过用"
# 都是从这里被切出来的。加了 (?<![\u4e00-\u9fa5]) 后，"分/均" 会挡住整个候选。
RE_PERSON_BEFORE_ROLE = re.compile(
    r"(?<![\u4e00-\u9fa5])([\u4e00-\u9fa5]{2,3})(?:%s)" % _ROLE_ALT)
# 激进模式：孤立的 2-3 字中文串，首字是姓才考虑。
# 后断言刻意收紧到「标点 / 空白 / 行尾 / 人名后常跟的动词」——
# 放宽到"后面任意汉字"会把「安装路径」「全部虚构」「测试样本」这类技术词大把误杀，
# 那比漏脱更糟：文本被改坏就看不懂了。
NAME_VERBS = ("提出|表示|指出|认为|补充|强调|要求|负责|介绍|说明|建议|同意|"
              "决定|安排|汇报|报告|回复|答复|确认|签字|审核|批准|编制|操作|"
              "使用|维护|主持|参加|出席|发言|询问|回答")
RE_LOOSE_NAME = re.compile(
    r"(?:^|[，。；：、！？\s（()【】])([\u4e00-\u9fa5]{2,3})"
    r"(?=[，。；：、！？\s（()）【】]|$|(?:%s))" % NAME_VERBS,
    re.M)


# 激进模式下以这些字开头的候选一定是动词/介词，不是姓（"经双方协商"里的"经双方"）
LOOSE_BAD_HEAD = set("经据按依对向在由从至为是该本其此这那各全同共并且与和及或")


def _is_name(nm, ctx=None):
    """姓氏白名单 + 词边界 + 整篇词频，三重约束。"""
    if not (2 <= len(nm) <= 3):
        return False
    if nm in NOT_NAME or nm in NEVER_ENTITY:
        return False
    if nm[0] not in SURNAME and nm[:2] not in COMPOUND_SURNAME:
        return False
    if nm[-1] in NOT_NAME_CHARS:
        return False
    if any(w in nm for w in NAME_BAD_SUB):
        return False
    # 整篇出现 10 次以上的词不可能是人名（"符合""应用""安全""关键"都远超）
    if ctx is not None and ctx.count(nm) >= 10:
        return False
    return True


def _scan_name_list(text, pos, ctx):
    """从 pos 起按「分隔符 + 姓名」续扫，遇到第一个不像姓名的词就停。

    分隔符比姓名本身更可靠：一旦某个 token 不是人名，后面就不再是名单。
    "联系人：张三，职务：技术负责人" 里的"职务"必须挡住，
    否则"技术负责人"会被当成下一个名字。
    """
    out = []
    while True:
        sep = RE_NAME_SEP_RUN.match(text, pos)
        if not sep:
            break
        m = RE_NAME_TOKEN.match(text, sep.end())
        if not m:
            break
        nm = m.group(1)
        if not _is_name(nm, ctx):
            break
        out.append((m.start(1), m.end(1), "人员", nm))
        pos = m.end(1)
    return out


def find_persons(text, loose=False, ctx=None):
    """只在上下文明确时判定人名，避免把'密码机''服务器'误杀。

    loose=True（--aggressive）时额外扫"孤立的 2-3 字中文串"，
    靠 首字是姓氏 + 整篇词频 + NEVER_ENTITY 三重限制。
    """
    out = []
    # 形态一：职务 + 可选冒号/空格 + 姓名；后面跟顿号/逗号/斜杠/空格时继续取下一个
    for rx in (RE_PERSON_AFTER_ROLE, RE_PERSON_LABEL_COLON, RE_PERSON_LABEL_LINE):
        for m in rx.finditer(text):
            nm = m.group(1)
            if _is_name(nm, ctx):
                out.append((m.start(1), m.end(1), "人员", nm))
                out.extend(_scan_name_list(text, m.end(1), ctx))
    # 形态二：姓名 + 职务（张主任、李工程师）
    for m in RE_PERSON_BEFORE_ROLE.finditer(text):
        nm = m.group(1)
        if _is_name(nm, ctx):
            out.append((m.start(1), m.end(1), "人员", nm))
    # 形态三（仅激进模式）：孤立人名
    if loose:
        for m in RE_LOOSE_NAME.finditer(text):
            nm = m.group(1)
            if PLACEHOLDER_RE.search(nm) or nm[0] in LOOSE_BAD_HEAD:
                continue
            if len(nm) == 3 and nm[2] in NOT_NAME_CHARS:
                nm = nm[:2]
            if _is_name(nm, ctx):
                s = m.start(1)
                out.append((s, s + len(nm), "人员", nm))
    return out


def _dedupe_spans(spans):
    """局部去重叠：长优先。地址段先自己理干净，再谈合并。"""
    taken, kept = [], []
    for s, e in sorted(spans, key=lambda x: (-(x[1] - x[0]), x[0])):
        i = bisect.bisect_left(taken, (s, e))
        if i > 0 and taken[i - 1][1] > s:
            continue
        if i < len(taken) and taken[i][0] < e:
            continue
        taken.insert(i, (s, e))
        kept.append((s, e))
    return sorted(kept)


ADDR_GLUE = set("省市区县镇乡村路街巷大道号栋座层室楼院厦场园")


def _addr_glue(gap):
    """两段地址之间的间隙算不算"同一地址的残段"。

    "山东省济南市高新区" + "舜华路街道" + "新泺大街2008号" 是同一个地址：
    中间的"舜华路街道"整段都是路名，必须并进去，否则会出现
    "山东省济[地址1]南市…" 这种把市名切开的占位符。
    """
    if len(gap) <= 8 and all(ch in ADDR_GLUE or ch.isspace() for ch in gap):
        return True
    if gap.endswith("街道") and len(gap) <= 10 and gap[-3] in "路街":
        return True
    return False

def _merge_address_spans(text, spans):
    """把紧邻的地址段拼成一整段，并把紧贴的邮编并进来。

    "北京市朝阳区" + "建国路88号" + " 100022" 必须是一个 [地址1]，
    否则会得到"北京市[地址1]区"这种换一半留一半的结果——那比不换更糟。
    段与段之间允许夹最多 8 个地址类字符（"舜华路街道"这种纯路名残段），
    但"、"和"，"分隔的两处地址不合并。
    """
    merged = []
    for s, e in sorted(spans):
        if merged:
            gap = text[merged[-1][1]:s]
            if s >= merged[-1][1] and _addr_glue(gap):
                merged[-1] = (merged[-1][0], e)
                continue
        merged.append((s, e))
    out = []
    for s, e in merged:
        # "B座3层"这类楼栋信息紧跟其后，一起吃掉，否则地址后面挂半截
        m = RE_ADDR_TAIL.match(text, e)
        if m and m.end() > e:
            e = m.end()
        m = RE_POSTCODE.match(text, e)
        if not m and e < len(text) and text[e] in " \u3000":
            m = RE_POSTCODE.match(text, e + 1)
        out.append((s, m.end() if m else e))
    return out


def find_addresses(text):
    """地址、链式行政区划、公文文号。已呈占位形态（××市/某区）的跳过。

    设计取舍：只脱"省+市""市+区县""路名+门牌"这类连续结构，
    不对单独的"X市""X区"做猜测式替换。原因是一次误伤会改坏技术语义
    （如"划分三个区域"被替换成"[地址]域"），代价高于漏脱一处裸地名。
    裸地名由报告第四节列出，用 --dict 精确补。

    相邻的地址段（行政区划 + 街道门牌 + 邮编）在这里就并成一个整体，
    交给上层一次替换。半截地址（只有"朝阳区"）本来就不命中，保持不动。
    """
    out = []
    addr = []
    ph = [m.span() for m in RE_PLACEHOLDERISH.finditer(text)]

    def blocked(s, e):
        return any(s < pe and e > ps for ps, pe in ph)

    for m in RE_STREET.finditer(text):
        s, e = m.span()
        if not blocked(s, e):
            addr.append((s, e))
    for m in RE_ADMIN_CHAIN.finditer(text):
        s, e = m.span()
        g = m.group(0)
        cut = 0
        while cut < 4 and len(g) > 5 and g[0] in ADMIN_TRIM:
            g = g[1:]
            cut += 1
        s += cut
        if len(g) < 5 or g in ADMIN_BAD_WHOLE or any(g.startswith(h) for h in ADMIN_BAD_HEAD):
            continue
        if not blocked(s, e):
            addr.append((s, e))
    for m in RE_DOCNO.finditer(text):
        out.append((m.start(), m.end(), "编号", m.group(0)))
    for m in RE_BUILDING.finditer(text):
        g = m.group(0)
        cut = 0
        # 左边常黏上前一个地址的"号"（"…2008号银荷大厦"），一并裁掉
        while cut < 6 and len(g) > 4 and (g[0] in ADMIN_TRIM or g[0] in "号栋座层室"):
            g = g[1:]
            cut += 1
        s = m.start() + cut
        if len(g) < 4 or g in ADMIN_BAD_WHOLE:
            continue
        if not blocked(s, m.end()):
            addr.append((s, m.end()))
    for s, e in _merge_address_spans(text, _dedupe_spans(addr)):
        out.append((s, e, "地址", text[s:e]))
    return out


def find_vendors_products(text):
    """已知厂商 / 产品名。厂商不并进单位——"深信服"是[厂商1]，不是[单位1]。"""
    out = []
    for m in RE_VENDOR.finditer(text):
        out.append((m.start(), m.end(), "厂商", m.group(0)))
    for m in RE_PRODUCT.finditer(text):
        out.append((m.start(), m.end(), "产品", m.group(0)))
    for m in RE_DB_PRODUCT.finditer(text):
        out.append((m.start(), m.end(), "产品", m.group(0)))
    return out


def _clause_span(text, pos):
    """分句：技术主语的判断按逗号级分句做。

    "2024年6月1日签订合同，证书有效期至2027年6月1日" 里前半句的主语是合同，
    不能因为后半句有"证书"就把签订日也放过。
    """
    s = pos
    while s > 0 and text[s - 1] not in "，,；;。！？：:\n\r":
        s -= 1
    e = pos
    while e < len(text) and text[e] not in "，,；;。！？：:\n\r":
        e += 1
    return s, e


def find_dates(text):
    """只换能定位到某个自然人的日期，技术时间点一律保留。

    口径（2026-11 定）：报告日期、评估周期、证书有效期、人员考试/资格时间
    全部保留；只有出生、入职、签订、身份证有效期这类能定位到人的才换。
    旧版只要"句子里出现过单位名"就换日期，于是
    "方案评估时间为2026年9月9日至2026年9月24日" 整句被判成敏感——
    单位识别越准，误换的日期反而越多。现在只看日期所在分句里有没有定位词。
    """
    out = []
    for m in RE_DATE.finditer(text):
        parts = RE_DATE_PARTS.match(m.group(0))
        if not parts:
            continue
        nums = [int(x) for x in parts.groups() if x is not None]
        if len(nums) != 3:
            continue
        _, mon, day = nums
        if not (1 <= mon <= 12 and 1 <= day <= 31):
            continue
        s, e = m.span()
        cs, ce = _clause_span(text, s)
        if any(w in text[cs:ce] for w in TECH_SUBJECT_WORDS):
            continue
        if not any(w in text[cs:ce] for w in PERSONAL_DATE_WORDS):
            continue
        out.append((s, e, "日期", m.group(0)))
    return out


def filter_whitelist(text, hits):
    """结论词/技术词/职务词一律不换。自定义词表是用户明确要换的，不受白名单影响。"""
    out = []
    for h in hits:
        s, e, cat, raw = h
        if cat == "自定义":
            out.append(h)
            continue
        if cat in ENTITY_CATS:
            # 硬闸门：评估结果闭集与技术词，出现在任何位置都不换
            if raw in NEVER_ENTITY:
                continue
            if raw in WHITELIST_WORDS and _standalone(text, s, e):
                continue
        out.append(h)
    return out


ENTITY_CATS = {"人员", "单位", "系统", "未分类", "地址", "型号", "厂商", "产品", "机房"}


def _standalone(text, s, e):
    left = s <= 0 or text[s - 1].isspace() or text[s - 1] in WHITELIST_BOUND
    right = e >= len(text) or text[e].isspace() or text[e] in WHITELIST_BOUND
    return left and right


def _reclassify_vendor_orgs(hits):
    """单位名里含已知厂商/产品时，整串按厂商/产品记。

    "深信服科技股份有限公司"如果按单位走，用户看到的还是 [单位1]，
    等于第 2 条改进没落地。整串换成 [厂商1]，类别和信息都不含糊。
    """
    marks = sorted((h[0], h[1], h[2]) for h in hits if h[2] in ("厂商", "产品"))
    if not marks:
        return hits
    # 二分定位后再顺序扫：单位名都很短，落在里面的标记通常 0-1 个。
    # 旧写法对每个单位遍历全部标记，几万字文档会退化成 O(n²)。
    starts = [m[0] for m in marks]
    out = []
    for s, e, cat, raw in hits:
        if cat == "单位":
            i = bisect.bisect_left(starts, s)
            while i < len(marks) and marks[i][0] < e:
                vs, ve, vc = marks[i]
                if ve <= e:
                    cat = vc
                    break
                i += 1
        out.append((s, e, cat, raw))
    return out



def find_ids(text):
    """工号、病案号、序列号等带锚点的编号。"""
    out = []
    for m in RE_ID_ANCHOR.finditer(text):
        out.append((m.start(1), m.end(1), "编号", m.group(1)))
    return out


def find_brand_models(text):
    """品牌后紧跟的英文产品名，如 GE Revolution CT、Siemens MAGNETOM Vida。"""
    out = []
    for m in RE_BRAND_MODEL.finditer(text):
        tok = m.group(1).strip()
        first = tok.split()[0].split("-")[0]
        if first in BRAND_MODEL_OK_WORD or KEEP.match(first):
            continue
        if len(first) < 4:
            continue
        out.append((m.start(1), m.end(1), "型号", tok))
    return out


def find_models(text):
    out = []
    for rx in (RE_MODEL, RE_MODEL_LONG):
        for m in rx.finditer(text):
            tok = m.group(0)
            if RE_MODEL_EXCLUDE.match(tok) or KEEP.match(tok):
                continue
            if re.match(r"^[A-Za-z]{0,3}\d{1,3}$", tok):  # 纯数字或极短，跳过
                continue
            head = re.match(r"[A-Za-z]+", tok)
            if head and head.group(0).upper() in MODEL_TECH_HEAD:
                continue
            if re.search(r"[A-Za-z]", tok) and re.search(r"\d", tok) and len(tok) >= 4:
                out.append((m.start(), m.end(), "型号", tok))
    return out


def find_custom(text, words):
    """用户词表。不再落到"自定义"：按后缀归到 单位/系统/型号，否则 未分类。"""
    out = []
    for w in words:
        w = w.strip()
        if not w:
            continue
        cat = _classify_entity(w)
        start = 0
        while True:
            i = text.find(w, start)
            if i < 0:
                break
            out.append((i, i + len(w), cat, w))
            start = i + len(w)
    return out


def find_lexicon(text, ctx):
    """整篇反复出现的长实体（系统全名等），整体替换，不留给后续规则二次拆分。"""
    out = []
    if not ctx:
        return out
    for term, cat in ctx.lexicon:
        start = 0
        while True:
            i = text.find(term, start)
            if i < 0:
                break
            out.append((i, i + len(term), cat, term))
            start = i + len(term)
    return out


# 云平台名：省市前缀 + 政务云/云平台。单独认，避免和"部署于云平台"混淆。
RE_CLOUD = re.compile(
    r"[\u4e00-\u9fa5]{2,4}(?:省|市|区|县)[\u4e00-\u9fa5]{0,8}(?:政务云|云平台|专有云)"
    r"(?:[（(][^）)\n]{0,12}[）)])?")


# 云平台名前面常黏着动词的残字（"系统部署在山东省政务云" → "署在山东省政务云"）。
# 这些字一定不属于地名，逐字裁掉。
CLOUD_TRIM_HEAD = set("在由于到向和与及为是的了署部统将把被对从经据按依")


def find_clouds(text):
    """云平台名。前面常黏着"部署在/通过/调用"这类动词，按省/市后缀把左边裁掉。"""
    out = []
    for m in RE_CLOUD.finditer(text):
        g, s, cut = m.group(0), m.start(), 0
        for suf in ("省", "市", "区", "县"):
            i = g.find(suf)
            if i >= 0:
                cut = max(0, i - 2)
                break
        # 起点必须落在"地名首字"上：裁掉动词残字，否则会吞掉"部署在"的"署在"
        while cut < len(g) - 4 and g[cut] in CLOUD_TRIM_HEAD:
            cut += 1
        name = g[cut:]
        head = name.split("政务云")[0].split("云平台")[0].split("专有云")[0]
        # "网络区域包括云平台" 这类句子形状的，前面一定有连接词
        if any(w in head for w in ORG_CONNECT):
            continue
        out.append((s + cut, m.end(), "系统", name))
    return out


# ---------------------------------------------------------------- 项目名 / 机房
# 项目名/系统名/平台名：政务方案里出现最多、也最需要脱的一类。
# 两条路：① "项目名称："这类标签后面整段取值，精确；② 地名开头 + 强后缀。
RE_PROJECT_LABEL = re.compile(
    r"(?:项目名称|系统名称|平台名称|工程名称|项目名|系统名|平台名)\s*[:：]\s*"
    r"([^\s，。；：、！？\n]{4,60})")
RE_PROJECT_GEN = re.compile(
    r"(?<![\u4e00-\u9fa5A-Za-z0-9])"
    r"[\u4e00-\u9fa5]{2,4}(?:省|市|区|县|州|盟)"
    r"[\u4e00-\u9fa5“”\"'‘’A-Za-z0-9\-]{2,30}?"
    r"(?:一体化平台|一体化系统|云平台|网站|项目|工程)")
PROJ_TAIL = ("一体化平台", "一体化系统", "云平台", "平台", "系统", "项目", "工程",
             "网站", "云")
PROJ_BAD_HEAD = ("本项目", "该项目", "本系统", "该系统", "本工程", "该工程", "此项",
                 "上述", "以下", "相关", "全部", "所有", "本次")


def _ok_project(name, labeled=False):
    name = name.strip().strip("“”\"'‘’《》 ")
    if not (4 <= len(name) <= 60):
        return False
    if name.startswith(PROJ_BAD_HEAD):
        return False
    tail = next((t for t in PROJ_TAIL if name.endswith(t)), None)
    if not tail:
        return False
    core = name[:-len(tail)]
    if len(core) < (2 if labeled else 3):
        return False
    if core in ORG_GENERIC_HEAD or core in ORG_BLACK:
        return False
    # 名字里必须有一个像样的专名：地名开头、带引号，或（标签取值时）够长。
    # 不靠"够长"兜底，否则"本单位门户网站"这类通用说法也会被当成名字。
    if not (PLACE_PREFIX.match(name) or "“" in name or '"' in name
            or (labeled and len(core) >= 4)):
        return False
    return True


def find_projects(text):
    out = []
    for m in RE_PROJECT_LABEL.finditer(text):
        val = m.group(1).strip()
        if _ok_project(val, labeled=True):
            s = m.start(1) + m.group(1).find(val)
            out.append((s, s + len(val), "系统", val))
    for m in RE_PROJECT_GEN.finditer(text):
        val = m.group(0)
        if _ok_project(val):
            out.append((m.start(), m.end(), "系统", val))
    return out


# 机房 / 数据中心 / 灾备中心：最能定位物理资产的一类信息。
# 整段（含"中国移动(山东济南)"这类前缀和"B2-101""10层"这类位置）一起换。
IDC_TAIL = re.compile(r"(?:数据中心|灾备中心|云计算中心|机房)")
RE_IDC_TAIL_PART = re.compile(
    r"\s*(?:[A-Za-z]?\d{1,3}[-－]\d{1,4}|[A-Za-z]\d{1,3}|\d{1,3}\s*层|\d{1,3}\s*楼)")
IDC_GENERIC_HEAD = {
    "本", "该", "中心", "生产", "备用", "灾备", "核心", "主机", "托管", "自建", "云",
    "模块", "测试", "办公", "计算", "网络", "通信", "设备", "动力", "空调", "电池",
    "配电", "监控", "信息", "数据", "屏蔽", "涉密", "非涉密", "新建", "原有", "现有",
    "各", "全", "主", "备", "灾", "容灾", "业务", "系统", "服务", "基础", "统一"}
# 句子里描述"机房怎么建"的词，出现在头部说明回溯咬进了句子，不是名字
IDC_BAD_SUB = ("方案", "系统", "项目", "工程", "本次", "部署", "建设", "改造", "扩容",
               "迁移", "采用", "使用", "通过", "利用", "依托", "新建", "规划", "设计",
               "相关", "全部", "所有", "上述", "以下", "本期", "该")


def _ok_idc(name):
    if not (4 <= len(name) <= 40):
        return False
    head = IDC_TAIL.sub("", name).strip("()（） ")
    if len(head) < 3:
        return False
    if head in IDC_GENERIC_HEAD or head.startswith(("本", "该", "上述", "以下", "相关")):
        return False
    if any(w in head for w in IDC_BAD_SUB):
        return False
    if not re.search(r"[\u4e00-\u9fa5]", head):
        return False
    return True


def find_idcs(text):
    out = []
    for m in IDC_TAIL.finditer(text):
        end, s = m.end(), m.start()
        limit = max(0, s - 40)
        while s > limit:
            ch = text[s - 1]
            # 括号、连字符、数字都是机房名的一部分（"(山东济南)"、"B2-101"）
            if ch in "()（）-－_.·" or ch.isdigit():
                s -= 1
                continue
            if not ("\u4e00" <= ch <= "\u9fa5" or "A" <= ch <= "Z" or "a" <= ch <= "z"):
                break
            if ch in ORG_STOP:
                break
            if text[s - 2:s] in ORG_CONNECT:
                break
            s -= 1
        while s < end - 2 and (text[s] in ORG_TRIM_HEAD or text[s] in "()（）"):
            s += 1
        e2 = end
        mm = RE_IDC_TAIL_PART.match(text, e2)
        if mm:
            e2 = mm.end()
        name = text[s:e2].strip()
        if _ok_idc(name):
            out.append((s, e2, "机房", name))
    return out


# 纯文本表格：一行内用两个以上空格/制表符分格。
CELL_SEP = re.compile(r"[ \t\u3000]{2,}")

# 「物理环境名称 | 物理位置」表里两格是两个不同的东西：一个机房名，一个它的位置。
# v5 让两格共用一个 [机房N]，脱敏后看着没问题，还原时位置整段被换成机房名——丢字段。
# 现在位置列按地址脱（[地址N]），名称列仍是 [机房N]，还原逐字回得来。
POSITION_HEADERS = ("物理位置", "地址", "所在地", "位置")


def _table_cells(line):
    """按 2+ 空格分格，返回每格的 (相对起点, 相对终点)。"""
    spans, pos = [], 0
    for part in CELL_SEP.split(line):
        i = line.find(part, pos)
        if i < 0:
            i = pos
        spans.append((i, i + len(part)))
        pos = i + len(part)
    return spans


def _mark_position_cells(text, mapper):
    """表格「物理位置」列里的机房命中改记地址。返回改记数。

    表头单元格都很短，靠这个把表头行和数据行分开；数据行不参与列判定。
    """
    n, cols = 0, None
    for m in re.finditer(r"[^\n]+", text):
        line = m.group(0)
        if not CELL_SEP.search(line):
            cols = None
            continue
        cells = [text[m.start() + a:m.start() + b].strip() for a, b in _table_cells(line)]
        head = {i for i, c in enumerate(cells) if any(k in c for k in POSITION_HEADERS)}
        if head and len(cells) >= 2 and all(len(c) <= 12 for c in cells):
            cols = head
            continue
        if not cols:
            continue
        for i in cols:
            if i >= len(cells):
                continue
            for _s, _e, cat, raw in find_idcs(cells[i]):
                if cat == "机房":
                    mapper.force[raw] = "地址"
                    n += 1
    return n


# 固定电话：7-8 位本地号（不带区号）。只有紧跟"电话/传真"这类标签才换——
# 裸的 8 位数字在方案里更可能是容量、编号或金额。
RE_TEL_LOCAL = re.compile(
    r"(?:电话|传真|座机|联系电话|办公电话|联系方式|热线|tel)\s*[:：]?\s*"
    r"([0-9０-９]{7,8}(?:[-－转][0-9]{1,5})?)(?![0-9])", re.I)


def find_local_tel(text):
    out = []
    for m in RE_TEL_LOCAL.finditer(text):
        out.append((m.start(1), m.end(1), "电话", m.group(1)))
    return out


# 方案名：整篇反复出现的《…密码应用方案》。识别不出别的类别，按未分类走，
# 但绝不能只换前半截、把"…密码应用方案"留在原地。
RE_PLAN_TITLE = re.compile(r"《([^《》\n]{4,80})》")
PLAN_BAD = ("制定", "编制", "评审", "评估", "审查", "完善", "修订", "提交", "落实",
            "执行", "采用", "要求", "检查", "更新", "修改", "一个", "该", "本")


def find_plans(text):
    out = []
    for m in RE_PLAN_TITLE.finditer(text):
        inner = m.group(1)
        if not re.search(r"密码应用方案(?:v?\d+(?:\.\d+)*)?$", inner):
            continue
        if RE_STD.search(inner):
            continue
        # 书名号里如果前半截就是项目名，只换项目名，让"…密码应用方案"留在原处，
        # 这样与正文里的 [系统N] 共用同一编号；认不出项目名才整条按未分类走。
        pre = re.match(r"^(.{4,60}?)(密码应用方案(?:v?\d+(?:\.\d+)*)?)$", inner)
        if pre and _ok_project(pre.group(1).strip(), labeled=True):
            s = m.start(1) + inner.find(pre.group(1).strip())
            out.append((s, s + len(pre.group(1).strip()), "系统", pre.group(1).strip()))
        else:
            out.append((m.start(1), m.end(1), "未分类", inner))
    st = text.strip()
    # 整段就是一个方案标题时，不能把标题当实体换掉：标题里的项目名按 [系统N] 换，
    # "密码应用方案"是文档类型，留着读者才知道这是份什么材料。
    # 旧版整条换成 [未分类1]，于是同一个项目在标题和正文各有一个编号。
    mt = re.match(r"^(.{4,60}?)(密码应用方案(?:v?\d+(?:\.\d+)*)?)$", st)
    if mt and "《" not in st and not any(w in st for w in PLAN_BAD):
        prefix = mt.group(1).strip()
        if _ok_project(prefix, labeled=True):
            s = text.find(prefix)
            out.append((s, s + len(prefix), "系统", prefix))
    # 系统名称单元格：整段就是一个以省市开头、以"系统/平台"结尾的名字
    if (st.endswith(("系统", "平台")) and 6 <= len(st) <= 60
            and PLACE_PREFIX.match(st) and not any(w in st for w in PLAN_BAD)):
        s = text.find(st)
        out.append((s, s + len(st), "系统", st))
    return out


def find_postcodes(text, ctx=None):
    """6 位数字，只有上下文出现"邮编/邮政编码/地址"才换。

    表格里"邮政编码"和"250014"通常分处两个单元格，单段落看不到上下文，
    所以整篇扫描时先把锚点旁的邮编收进 ctx.postcodes，逐段替换时按值命中。
    """
    known = ctx.postcodes if ctx is not None else set()
    out = []
    for m in RE_POSTCODE.finditer(text):
        v = m.group(0)
        if v in known:
            out.append((m.start(), m.end(), "邮编", v))
            continue
        left = text[max(0, m.start() - 12):m.start()]
        if any(w in left for w in ("邮编", "邮政编码", "地址")):
            out.append((m.start(), m.end(), "邮编", v))
    return out


# 文档自身标识：抬头/页眉/页脚的"编号"行，形态为 字母-XXX-字母 或 字母-XXX/数字。
# 这是报告模板的一部分，不是敏感信息，替换了读者反而认不出是哪份报告。
RE_DOCID_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-—_/\.]{4,40}")
RE_DOCID_A = re.compile(r"[A-Za-z][A-Za-z0-9]{1,5}-[A-Za-z0-9][A-Za-z0-9\-]{0,30}-[A-Za-z]{2,6}")
RE_DOCID_B = re.compile(r"[A-Za-z][A-Za-z0-9]{1,5}-[A-Za-z0-9\-]{0,20}/\d{1,3}")


def _doc_id_spans(text, strict=False):
    """strict=True 用于页眉/页脚：那里只有编号本身，没有"编号"二字可依赖。"""
    spans = []
    pos = 0
    for line in text.splitlines(True):
        if strict or "编号" in line:
            for m in RE_DOCID_TOKEN.finditer(line):
                tok = m.group(0).rstrip(".")
                if RE_DOCID_A.fullmatch(tok) or RE_DOCID_B.fullmatch(tok):
                    spans.append((pos + m.start(), pos + m.start() + len(tok)))
        pos += len(line)
    return spans


# ---------------------------------------------------------------- 主替换逻辑

# 章节标题/目录行："1.2. 国家政策法规要求 …… 5"、"第三章 密码应用方案"。
# 这些是文档结构，不是实体。只挡"整条标题就是一个实体"的情况——
# 标题里嵌着的真实名字（"3.2 山东省政务云平台部署"）照旧要脱。
RE_HEADING_NUM = re.compile(
    r"^[ \t\u3000]*(?:\d+(?:\.\d+)*[.、．]?|[一二三四五六七八九十]+[、.．]"
    r"|第[一二三四五六七八九十百]+[章节])\s*")
RE_TOC_LEADER = re.compile(r"[.．·…\s]{2,}\d{1,4}\s*$")


def _heading_title_spans(text):
    """返回每个标题行的「标题正文」区间（去掉编号、点线和页码）。"""
    spans = []
    pos = 0
    for line in text.splitlines(True):
        m = RE_HEADING_NUM.match(line)
        if m:
            raw = line.rstrip("\r\n")
            body = raw[m.end():]
            bm = RE_TOC_LEADER.search(body)
            if bm:
                body = body[:bm.start()]
            body = body.strip()
            if body:
                s = pos + m.end() + (len(raw[m.end():]) - len(raw[m.end():].lstrip()))
                spans.append((s, s + len(body)))
        pos += len(line)
    return spans


# 报告编号：Z2T-D2607-076-DSM-13-RPT / RM-D2607-076/2
# 整串当实体脱掉，不让 AI 看到里面的机构缩写自己编占位符
RE_REPORT_ID = re.compile(
    r"(?<![A-Za-z0-9_/-])"
    r"[A-Z][A-Z0-9]{1,5}(?:-[A-Za-z0-9]{1,12}){2,}"
    r"(?:-RPT|/[0-9]{1,4})?"
    r"(?![A-Za-z0-9_/-])"
)
# 标准号/算法名前缀：命中这些就不是报告编号（按前缀匹配，PBKDF2 也归 PBKDF）
REPORT_ID_SKIP_PREFIX = ("GB", "GM", "GA", "ISO", "IEC", "IEEE", "RFC", "SM",
                         "HMAC", "SHA", "PBKDF", "AES", "RSA", "ECC", "ZUC",
                         "TLS", "SSL", "DES", "MD5", "CRC")


def find_report_ids(text):
    """报告编号整串识别。标准号（GB/T、GM/T）与纯数字日期一律排除。"""
    out = []
    for m in RE_REPORT_ID.finditer(text):
        raw = m.group(0)
        segs = raw.split("-")
        # 整串必须至少含一个纯字母段（机构代码）和一个数字字符
        if not any(ch.isdigit() for ch in raw):
            continue
        if not any(s.isalpha() and 2 <= len(s) <= 6 for s in segs):
            continue
        head = segs[0].upper()
        if any(head.startswith(p) for p in REPORT_ID_SKIP_PREFIX):
            continue
        # 纯数字段占比过高 → 日期或版本号，不是编号
        num = sum(1 for s in segs if s.isdigit())
        if num >= len(segs) - 1:
            continue
        out.append((m.start(), m.end(), "编号", raw))
    return out


def collect(text, custom_words=(), aggressive=False, ctx=None, strict_docid=False):
    """返回命中列表 [(start, end, cat, raw)]，已按优先级处理重叠。"""
    hits = []
    hits += find_report_ids(text)
    hits += find_lexicon(text, ctx)
    hits += find_custom(text, custom_words)
    hits += find_plans(text)
    hits += find_projects(text)
    hits += find_orgs(text)
    hits += find_clouds(text)
    hits += find_idcs(text)
    hits += find_persons(text, loose=aggressive, ctx=ctx)
    hits += find_vendors_products(text)
    # 日期只看自身分句里有没有"出生/入职/签订"这类定位词
    hits += find_dates(text)
    hits += find_addresses(text)
    hits += find_ids(text)
    hits += find_postcodes(text, ctx)
    hits += find_local_tel(text)

    for rx, cat in ((RE_IDCARD, "证件号"), (RE_MOBILE, "电话"), (RE_EMAIL, "邮箱"),
                    (RE_IPV6, "IP"), (RE_IPV4, "IP"), (RE_MAC, "IP"),
                    (RE_TEL, "电话")):
        for m in rx.finditer(text):
            hits.append((m.start(), m.end(), cat, m.group(0)))

    for m in RE_URL.finditer(text):
        hits.append((m.start(), m.end(), "域名", m.group(0)))
    for m in RE_DOMAIN.finditer(text):
        hits.append((m.start(), m.end(), "域名", m.group(0)))
    for m in RE_WINPATH.finditer(text):
        hits.append((m.start(), m.end(), "路径", m.group(0)))
    for m in RE_UNIXPATH.finditer(text):
        hits.append((m.start(), m.end(), "路径", m.group(0)))
    for m in RE_ACCOUNT.finditer(text):
        hits.append((m.start(1), m.end(1), "账号", m.group(1)))
    hits += find_models(text)
    hits += find_brand_models(text)

    # 厂商/产品优先于单位：含厂商名的整串单位名改记厂商，别让 [单位1] 盖掉它
    hits = _reclassify_vendor_orgs(hits)
    # 白名单只挡独立成词的那一个词，不影响它前后的真实实体
    hits = filter_whitelist(text, hits)

    # 2026-11-10 反转：报告编号里含机构代码（Z2T）和项目号，属于敏感信息。
    # 旧规则把它保护起来，结果 AI 看到后自己编了 [机构代码]/[序号] 占位符，
    # 映射表里没有这两条，还原必然失败。现在整串脱成 [编号N]，由 find_report_ids 负责。
    # （_doc_id_spans 保留但不再调用）

    # 标准号保护：任何与标准号重叠的命中一律丢弃。
    # 用二分而不是内层遍历——几万个命中 × 几百个标准号会直接卡死。
    std_spans = sorted(m.span() for m in RE_STD.finditer(text))
    if std_spans:
        std_starts = [s for s, _ in std_spans]
        kept = []
        for h in hits:
            s, e = h[0], h[1]
            i = bisect.bisect_left(std_starts, e)
            # 区间互不重叠，只需检查插入点前一个是否越过 s
            if i > 0:
                ss, se = std_spans[i - 1]
                if se > s and ss < e:
                    continue
            kept.append(h)
        hits = kept

    # 标题/目录保护：章节标题被当成"未分类实体"整条换掉，是目录变成
    # "[未分类2] [未分类3]"的原因。这里只挡这一类——
    # 标题里如果是真实单位/系统名（"3.2 山东省政务云平台部署"），照旧要脱。
    for ts, te in _heading_title_spans(text):
        if te - ts < 4:
            continue
        hits = [h for h in hits
                if h[2] != "未分类"
                or not (h[0] >= ts and h[1] <= te and (h[1] - h[0]) >= 0.9 * (te - ts))]

    # 去重叠：长优先，其次类别优先级。
    # taken 按 start 升序且互不重叠，插入点前后各查一次即可，O(n log n)。
    prio = {"未分类": 0, "自定义": 0, "证件号": 1, "日期": 2, "编号": 3, "电话": 4,
            "邮箱": 5, "域名": 6, "IP": 7, "账号": 8, "路径": 9, "邮编": 10,
            "机房": 11, "厂商": 12, "产品": 13, "地址": 14, "系统": 15, "单位": 16,
            "人员": 17, "型号": 18}
    hits.sort(key=lambda h: (-(h[1] - h[0]), prio.get(h[2], 99)))
    taken = []
    chosen = []
    for s, e, cat, raw in hits:
        i = bisect.bisect_left(taken, (s, e))
        if i > 0 and taken[i - 1][1] > s:
            continue
        if i < len(taken) and taken[i][0] < e:
            continue
        taken.insert(i, (s, e))
        chosen.append((s, e, cat, raw))
    chosen.sort()
    # 同一原文实体全文只允许一个占位符：类别也统一，
    # 否则 (类别, 原文) 会各生成一个编号（"国家密码管理局"出现 [单位3] 和 [单位13]）。
    best = {}
    for s, e, cat, raw in chosen:
        k = raw.strip()
        if k not in best or RAW_CAT_PRIO.get(cat, 99) < RAW_CAT_PRIO.get(best[k], 99):
            best[k] = cat
    chosen = [(s, e, best[raw.strip()], raw) for s, e, cat, raw in chosen]
    return _merge_adjacent_hits(text, chosen)


# 同一个原文在不同规则下可能落到不同类别，归一化时按这个顺序取一个
RAW_CAT_PRIO = {"机房": 0, "厂商": 1, "产品": 2, "证件号": 3, "电话": 4, "邮箱": 5,
                "域名": 6, "IP": 7, "账号": 8, "路径": 9, "邮编": 10, "编号": 11,
                "日期": 12, "人员": 13, "单位": 14, "系统": 15, "型号": 16,
                "地址": 17, "未分类": 18}


MERGE_CATS = {"单位", "系统", "未分类", "地址"}


def _merge_adjacent_hits(text, chosen):
    """相邻的同类实体合成一个。占位符右边紧跟同类实体残片 = 上一轮拆开了。"""
    out = []
    for s, e, cat, raw in chosen:
        if out:
            ps, pe, pc, praw = out[-1]
            gap = text[pe:s]
            if (pe <= s and len(gap) <= 1 and not gap.strip()
                    and pc in MERGE_CATS and cat in MERGE_CATS):
                out[-1] = (ps, e, pc, praw + gap + raw)
                continue
        out.append((s, e, cat, raw))
    return out


def scrub(text, mapper, custom_words=(), aggressive=False, ctx=None, strict_docid=False):
    if ctx is None:
        ctx = DocContext(text)
    chosen = collect(text, custom_words=custom_words, aggressive=aggressive,
                     ctx=ctx, strict_docid=strict_docid)
    if not chosen:
        return text, 0
    # 先定好表格位置列的类别，再动手替换：位置列是 [地址N]，名称列才是 [机房N]。
    _mark_position_cells(text, mapper)
    buf = []
    last = 0
    for s, e, cat, raw in chosen:
        buf.append(text[last:s])
        buf.append(mapper.get(cat, raw))
        last = e
    buf.append(text[last:])
    return "".join(buf), len(chosen)


# ---------------------------------------------------------------- 残留风险扫描

HIGH_RISK = [
    ("疑似机构名（未命中后缀规则）", re.compile(r"[\u4e00-\u9fa5]{2,8}(?:分院|院区|校区|园区|分部|分公司|办事处|分中心)")),
    # 单位后缀表里没有"平台"，"××市××云平台"这类名字整串漏脱且用户毫无察觉。
    # 不改进识别规则（会误伤"云平台""数据平台"这类通用词），只把它摆到残留清单里：
    # 前面挂省市区的平台名，几乎只能是具体的单位/系统名。
    ("疑似平台类单位名（后缀表未覆盖，需加词表）",
     re.compile(r"[\u4e00-\u9fa5]{2,3}(?:省|市|区|县)[\u4e00-\u9fa5]{2,10}平台")),
    ("疑似地名残留", re.compile(r"[\u4e00-\u9fa5]{2,6}(?:省|市|县|镇|乡|街道)|[\u4e00-\u9fa5]{2,6}(?:路|街|大道)\s*\d")),
    ("疑似英文缩写实体", re.compile(r"(?<![A-Za-z])(?:[A-Z]{3,8})(?![A-Za-z])")),
    ("疑似长数字编号", re.compile(r"(?<!\d)\d{6,}(?!\d)")),
    ("疑似型号残留", re.compile(r"(?<![A-Za-z0-9])[A-Z]{2,6}[-_]?\d{3,5}[A-Za-z0-9\-]{0,8}(?![A-Za-z0-9])")),
    ("疑似路径残留", re.compile(r"[A-Za-z]:\\\S{2,}|(?<![\w:/])/(?:[\w.\-]+/){2,}[\w.\-]+")),
    ("疑似人名（误报较多，需人工确认）",
     re.compile(r"(?<=[，。；、\s（(])([" + SURNAME[:120] + r"])[\u4e00-\u9fa5]{1,2}(?=[，。；、\s）)，。])")),
]

# 这几类漏一条就够出事，报告里要置顶，退出码也按它们算
HIGH_PREFIXES = ("疑似机构名", "疑似地名", "疑似平台类单位名")


def is_high(kind):
    return kind.startswith(HIGH_PREFIXES)


def mask(frag):
    """遮蔽片段：保留首尾，中间打星。单字符必须整体遮蔽，否则等于原文外泄。"""
    if not frag:
        return ""
    if len(frag) == 1:
        return "*"
    if len(frag) == 2:
        return frag[0] + "*"
    return frag[0] + "*" * (len(frag) - 2) + frag[-1]


def unclassified_rows(mapper):
    """报告用：列出 [未分类N] 及遮蔽片段，让人工确认它到底是什么。

    取消"自定义"兜底后，识别不出类别的实体会落到这里。报告不含原文，
    只给占位符编号 + 首尾字符，足够人工回映射表里对。
    """
    rows = []
    for (cat, raw), ph in mapper.forward.items():
        if cat == "未分类":
            num = re.sub(r"\D", "", ph) or "0"
            rows.append((int(num), ph, mask(raw)))
    return [(ph, frag) for _, ph, frag in sorted(rows)]


def risk_scan(orig, desens):
    """在脱敏后的文本上扫残留；返回 [(类别, 行号, 遮蔽片段)]"""
    out = []
    lines = desens.splitlines()
    for name, rx in HIGH_RISK:
        for idx, line in enumerate(lines, 1):
            for m in rx.finditer(line):
                frag = m.group(0)
                if name.startswith("疑似平台类"):
                    # 规则会把前面的虚词一起咬进来（"在" + 地名 + "省"），
                    # 裁掉之后遮蔽片段才定得住位
                    while len(frag) > 4 and frag[0] in ADMIN_TRIM:
                        frag = frag[1:]
                if PLACEHOLDER_RE.search(frag):
                    continue
                if RE_STD.match(frag) or KEEP.match(frag):
                    continue
                if RE_MODEL_EXCLUDE.match(frag):
                    continue
                if name.startswith("疑似地名"):
                    if frag in ADMIN_BAD_WHOLE or any(frag.startswith(h) for h in ADMIN_BAD_HEAD):
                        continue
                if name.startswith("疑似人名"):
                    if frag in NOT_NAME:
                        continue
                if name.startswith("疑似英文缩写"):
                    if frag in ("GB", "GM", "WS", "API", "CPU", "USB", "TLS", "SSL",
                                "VPN", "WAF", "IDS", "IPS", "HIS", "PACS", "LIS",
                                "EMR", "KMS", "HSM", "TCM", "TPM", "AES", "RSA",
                                "SHA", "MD5", "CTR", "CBC", "GCM", "NTP", "SSH",
                                "TCP", "UDP", "DNS", "DHCP", "LDAP", "SQL", "RAID",
                                "SSD", "HDD", "NAC", "VLAN", "QOS", "MTU", "MAC",
                                "CA", "RA", "TSA", "OCSP", "CRL", "XM"):
                        continue
                out.append((name, idx, mask(frag)))
    return out


# ---------------------------------------------------------------- 可读性回检（机械检查）
# 不判断"通顺"——那需要语言模型。只做三条正则能做的事，命中就报，
# 不阻断流程，交给人工看。宁可不报，也不猜。

RE_PH_TOKEN = re.compile(r"\[(?:" + PH_CATS + r")\d+\]")

# 占位符左边紧贴这些字，说明占位符落在句法位置上，不是被塞进词中间：
# 介词/连词/助词，以及日期单位（"2020年9月[单位2]发布"）。
PH_LEFT_FUNC = set("在由于向对与和及或是为的了到从将把被经据按依就也都还并且等各本该其此这那以用"
                   "年月日时点期号届次第")
# 占位符右边紧跟这些，说明后面是谓词/助词/量词，不是名字被切掉的残片。
PH_RIGHT_FUNC = set("的了着过是在于和与及或等个台套次项条名位为将把被由对向")
# 名字被切掉的后半截：占位符后面还挂着一长串机构后缀。
ORG_TAIL_FRAG = ("有限", "股份", "集团", "控股", "公司", "事务所", "研究院", "设计院")


def _is_cjk(ch):
    return "\u4e00" <= ch <= "\u9fff"


def _cjk_run(text, i, step, limit=12):
    """从 i 起（step=±1）连续汉字的个数，最多数 limit 个。"""
    n = 0
    while 0 <= i < len(text) and n < limit and _is_cjk(text[i]):
        n += 1
        i += step
    return n


def readability_scan(text):
    """只报真拆开的两类形态，返回 [(问题, 行号, 片段)]。

    1. 占位符夹在两个汉字中间，且紧贴的汉字合计不到 3 个（深[单位1]服、国[单位1]局）
    2. 占位符后面还挂着一长串机构名残片（[单位1]科技股份有限 + 公司）
    紧邻标点/空白/行首行尾/数字、以及"由[单位1]负责""[单位2]颁发"这类句法位置，
    都是正常替换，不再报——上一版把它们全算成误伤，第七节噪音比信号多。
    """
    out = []
    toks = list(RE_PH_TOKEN.finditer(text))
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line_of(pos):
        return bisect.bisect_right(line_starts, pos)

    for i, m in enumerate(toks):
        s, e = m.span()
        left = text[s - 1] if s > 0 else ""
        right = text[e] if e < len(text) else ""
        lc, rc = _is_cjk(left), _is_cjk(right)
        # 1) 两边都是汉字、合计不到 3 字，且不是虚词/日期单位托着的
        if lc and rc and left not in PH_LEFT_FUNC and right not in PH_RIGHT_FUNC:
            if _cjk_run(text, s - 1, -1) + _cjk_run(text, e, 1) < 3:
                out.append(("占位符被拆在词中间", line_of(s), left + m.group(0) + right))
                continue
        # 2) 占位符把机构名切成两半，后半截还留在正文里
        if rc:
            j = e
            while j < len(text) and j - e < 12 and _is_cjk(text[j]):
                j += 1
            frag = text[e:j]
            if len(frag) >= 4 and frag.endswith(ORG_TAIL_FRAG):
                out.append(("占位符切断了机构名", line_of(s), m.group(0) + frag))
                continue
        # 3) 两个占位符完全贴在一起（中间连空格都没有）
        if i + 1 < len(toks) and toks[i + 1].start() == e:
            out.append(("连续占位符无间隔", line_of(s),
                        m.group(0) + toks[i + 1].group(0)))
    return out



# ---------------------------------------------------------------- 文件处理

def read_txt(path):
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read(), enc
        except UnicodeDecodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(), "utf-8(replace)"


PERSON_HEADERS = ("负责人", "责任人", "联系人", "姓名", "签名人", "经办人", "编制人",
                  "审核人", "批准人", "操作人", "管理员", "工程师", "项目经理",
                  "患者姓名", "持证人", "签发人", "监交人", "移交人")


# ---------------- docx 读写：只用标准库 zipfile+re，不依赖 python-docx ----------------
# docx 就是 zip 包里的 XML。文本存在 <w:t> 里，一个段落常被拆成多个 run，
# 所以按段落整体取文本 → 替换 → 塞回第一个 <w:t>，其余清空。
# 这与 python-docx 的做法一致，不引入第三方依赖，任何 Python 3 都能直接跑。

RE_PART = re.compile(r"^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$")
RE_PARA = re.compile(r"<w:p\b[^>]*?(?:/>|>.*?</w:p>)", re.S)
RE_T = re.compile(r"(<w:t(?:\s[^>]*)?>)(.*?)(</w:t>)", re.S)
RE_T_SELF = re.compile(r"<w:t(\s[^>]*)?/>")
RE_TBL = re.compile(r"<w:tbl>.*?</w:tbl>", re.S)
RE_TR = re.compile(r"<w:tr\b[^>]*>.*?</w:tr>", re.S)
RE_TC = re.compile(r"<w:tc\b[^>]*>.*?</w:tc>", re.S)
# 图片：正文里是 <w:drawing>（新式）或 <w:pict>（VML 老式）。
# 图片一进 docx 就是二进制，文本替换碰不到，只能整块删或原样留着。
RE_DRAWING = re.compile(r"<w:drawing\b.*?</w:drawing>", re.S)
RE_PICT = re.compile(r"<w:pict\b.*?</w:pict>", re.S)
RE_MEDIA = re.compile(r"^word/media/")

SURNAME_ONLY = re.compile(r"[\u4e00-\u9fa5\u00b7]{2,4}")

# ---------------- docx 元数据 / 批注 / 修订清理 ----------------
# 这些内容在 Word 界面里看不见，但文件一发给对方就跟着出去了：
# 作者、最后修改人、公司、批注里的真名、修订记录里被删掉的原句。
# 必须和正文脱敏在同一次读写里做——单独放一个按钮，用户一定会忘。

# core.xml 里要清空的字段。Office 写出来的前缀就是 dc:/cp:，不会变。
CORE_CLEAR = ("dc:creator", "cp:lastModifiedBy", "dc:title", "dc:subject",
              "dc:description", "cp:keywords", "cp:category", "cp:lastPrinted")
# app.xml 是默认命名空间，标签没有前缀。
APP_CLEAR = ("Company", "Manager", "Template")

# 整份删除的部件。删了必须同时摘掉 [Content_Types].xml 和 *.rels 里的引用，
# 否则 Word 打开就报"文件已损坏"。
RE_DROP_PART = re.compile(
    r"^(?:docProps/custom\.xml|word/comments\.xml|word/commentsExtended\.xml|"
    r"word/commentsIds\.xml|word/commentsExtensible\.xml|word/people\.xml|"
    r"word/_rels/comments(?:Extended|Ids|Extensible)?\.xml\.rels|"
    r"word/_rels/people\.xml\.rels)$")
# 正文里指向批注的锚点，批注删了它们也得删。
RE_COMMENT_REF = re.compile(r"<w:comment(?:RangeStart|RangeEnd|Reference)\b[^>]*/>")
RE_VANISH = re.compile(r"<w:vanish\b[^>]*?/>|<w:vanish\b[^>]*>\s*</w:vanish>")
RE_FALSE_VAL = re.compile(r'w:val\s*=\s*"(?:0|false|off)"', re.I)


def _clear_fields(xml, names):
    """把这些属性元素整个删掉（Word 里就是空白），返回 (新 xml, 真正清掉的字段名)。

    成对标签和自闭合两种写法都认，同一字段出现多次就全删——留着空元素不但没用，
    还能拼出 <Manager/></Manager> 这种坏 XML（真实文档里 <Manager/> 很常见）。
    """
    cleared = []

    for name in names:
        pat = re.compile(r"<%s\b[^>]*?/>|<%s\b[^>]*>(.*?)</%s>"
                         % (re.escape(name), re.escape(name), re.escape(name)), re.S)

        def drop(m, _n=name):
            if m.group(1) and m.group(1).strip():
                cleared.append(_n)
            return ""

        xml = pat.sub(drop, xml)
    return xml, cleared


def _unref_part(xml, part):
    """把一个被删掉的部件从 [Content_Types].xml / *.rels 里摘干净。"""
    xml = re.sub(r'<Override\b[^>]*PartName="/%s"[^>]*/>' % re.escape(part), "", xml)
    base = part.rsplit("/", 1)[-1]
    xml = re.sub(r'<Relationship\b[^>]*Target="(?:[^"]*/)?%s"[^>]*/>'
                 % re.escape(base), "", xml)
    return xml


def _accept_revisions(xml):
    """接受全部修订：插入/移入的内容留下，删除/移走的内容丢掉，格式变更记录整块删。

    返回 (新 xml, 处理的修订处数)。
    """
    n = 0
    # 1) 格式变更记录先整块删：里面是旧格式快照，留着等于把改动前的样子也带出去
    for tag in ("pPrChange", "rPrChange", "sectPrChange", "tblPrChange",
                "trPrChange", "tcPrChange", "tblPrExChange", "tblGridChange",
                "numberingChange"):
        pat = re.compile(r"<w:%s\b[^>]*?(?:/>|>.*?</w:%s>)" % (tag, tag), re.S)
        xml, k = pat.subn("", xml)
        n += k
    # 2) 移动位置标记：成对出现、不含内容，删掉不留痕（不单独计数，一次移动算一处）
    for tag in ("moveFromRangeStart", "moveFromRangeEnd",
                "moveToRangeStart", "moveToRangeEnd"):
        xml, _k = re.subn(r"<w:%s\b[^>]*/>" % tag, "", xml)
    # 3) 删除 / 移走：内容整块丢掉。这些字在"接受修订"之后本来就不存在了。
    #    注意 w:del 不会误伤 w:delText——后面要求紧跟 ">"，字面不同。
    #    moveFrom 只是 moveTo 的另一半，不单独计数。
    for tag in ("del", "moveFrom", "cellDel"):
        pat = re.compile(r"<w:%s\b[^>]*?(?:/>|>.*?</w:%s>)" % (tag, tag), re.S)
        xml, k = pat.subn("", xml)
        if tag != "moveFrom":
            n += k
    # 4) 插入 / 移入 / 新增单元格：保留内容，只去掉标记。
    #    <w:ins> 在 <w:rPr> 里是自闭合的（段落标记修订），删掉即可。
    for tag in ("ins", "moveTo", "cellIns"):
        xml, k1 = re.subn(r"<w:%s\b[^>]*/>" % tag, "", xml)
        xml, k2 = re.subn(r"<w:%s\b[^>]*>(.*?)</w:%s>" % (tag, tag),
                          lambda m: m.group(1), xml, flags=re.S)
        n += k1 + k2
    return xml, n


def _strip_vanish(xml):
    """隐藏文字：保留文字、去掉 vanish 标记。

    选"保留文字"而不是"整段删掉"，因为隐藏文字往往正是作者不想让人看见的那部分
    （客户名、内部备注、没删干净的旧版本）。删掉等于静默丢内容，用户不知道少了什么；
    去掉标记让它变成正常正文，就能走同一套脱敏 + 复核，漏没漏一眼看得见。
    """
    n = 0

    def f(m):
        nonlocal n
        if RE_FALSE_VAL.search(m.group(0)):
            return m.group(0)      # val="0" 表示"不隐藏"，本来就不该动
        n += 1
        return ""

    return RE_VANISH.sub(f, xml), n


def _xml_unescape(s):
    return (s.replace("&lt;", "<").replace("&gt;", ">")
             .replace("&quot;", '"').replace("&apos;", "'")
             .replace("&amp;", "&"))


def _xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _para_text(block):
    return "".join(_xml_unescape(m.group(2)) for m in RE_T.finditer(block))


def _set_para_text(block, new):
    """整段文字写进第一个 <w:t>，其余 <w:t> 清空。无 <w:t> 则原样返回。"""
    # 自闭合的 <w:t/> 不匹配 RE_T，段落里有它就会整段写不进去 = 漏脱。
    # 先展开成成对标签，再走正常替换。
    block = RE_T_SELF.sub(lambda m: "<w:t%s></w:t>" % (m.group(1) or ""), block)
    ts = list(RE_T.finditer(block))
    if not ts:
        return block
    out, last = [], 0
    for i, m in enumerate(ts):
        out.append(block[last:m.start(2)])
        out.append(_xml_escape(new) if i == 0 else "")
        last = m.end(2)
    out.append(block[last:])
    return "".join(out)


def _rebuild(block, pattern, fn):
    """按 pattern 逐个替换，fn(match, index) 返回新片段。"""
    out, last, idx = [], 0, 0
    for m in pattern.finditer(block):
        out.append(block[last:m.start()])
        out.append(fn(m, idx))
        last = m.end()
        idx += 1
    out.append(block[last:])
    return "".join(out)


def _scrub_para(block, mapper, cw, agg, ctx=None, strict_docid=False):
    plain = _para_text(block)
    if not plain.strip():
        return block, 0
    new, n = scrub(plain, mapper, cw, agg, ctx, strict_docid)
    if not n:
        return block, 0
    return _set_para_text(block, new), n


def _sub_first_para(cell, new):
    flag = [False]

    def f(m):
        if flag[0]:
            return m.group(0)
        flag[0] = True
        return _set_para_text(m.group(0), new)

    return RE_PARA.sub(f, cell)


RESULT_HEADERS = ("评估结果", "评估结论", "测评结果", "结论", "结果")
# 表头是电话/传真时，整列都是电话号码。7-8 位本地号没有区号，段落里认不出，
# 只能靠表头。单元格必须整格就是号码，避免把"设备 8 台"这类内容误换。
PHONE_HEADERS = ("电话", "传真", "座机", "联系方式")
RE_TEL_CELL = re.compile(r"^(?:0\d{2,3}[-－ ]?)?\d{7,8}(?:[-－转]\d{1,5})?$")


def _scrub_table(tbl, mapper, cw, agg, ctx=None):
    """表格里单独成格的人名/电话没有上下文，靠表头列名推断。

    两种表都要认：
      1) 常规表：首行是表头，"负责人/姓名"等列整列都是人名；
      2) 键值表："联系人 | 姓名 | 朱文轩" 这种，姓名在表头单元格的右边一格。
    表头是"评估结果/评估结论/结论"的列整列跳过——那一列是闭集，不可能是人名。
    """
    rows = RE_TR.findall(tbl)
    if not rows:
        return tbl, 0
    header = [_para_text(c).strip() for c in RE_TC.findall(rows[0])]
    pcols = {i for i, h in enumerate(header) if any(k in h for k in PERSON_HEADERS)}
    rcols = {i for i, h in enumerate(header) if any(k in h for k in RESULT_HEADERS)}
    tcols = {i for i, h in enumerate(header) if any(k in h for k in PHONE_HEADERS)}
    xcols = {i for i, h in enumerate(header) if any(k in h for k in POSITION_HEADERS)}
    pcols -= rcols
    tcols -= rcols
    total = [0]

    def on_row(m, _i):
        cells = RE_TC.findall(m.group(0))
        texts = [_para_text(c).strip() for c in cells]
        # 位置列整格是地址，不是机房名：先定类别，后面逐段脱敏时才会出 [地址N]
        for i in xcols:
            if i < len(texts):
                for _s, _e, cat, raw in find_idcs(texts[i]):
                    if cat == "机房":
                        mapper.force[raw] = "地址"
        pcell = set(pcols)
        tcell = set(tcols)
        for i, t in enumerate(texts):
            if i + 1 < len(texts) and (t in PERSON_HEADERS or t.endswith("姓名")):
                pcell.add(i + 1)
            if i + 1 < len(texts) and any(k in t for k in PHONE_HEADERS):
                tcell.add(i + 1)
        if not pcell and not tcell:
            return m.group(0)
        ci = [-1]

        def on_cell(mc, _j):
            ci[0] += 1
            t = _para_text(mc.group(0)).strip()
            if ci[0] in tcell and RE_TEL_CELL.fullmatch(t):
                total[0] += 1
                return _sub_first_para(mc.group(0), mapper.get("电话", t))
            if ci[0] not in pcell:
                return mc.group(0)
            if not SURNAME_ONLY.fullmatch(t) or not _is_name(t, ctx):
                return mc.group(0)
            total[0] += 1
            return _sub_first_para(mc.group(0), mapper.get("人员", t))

        return _rebuild(m.group(0), RE_TC, on_cell)

    return _rebuild(tbl, RE_TR, on_row), total[0]


def _docx_transform(path, dest, mapper, cw, agg, stats, images="keep"):
    """打开 docx，清理元数据/批注/修订，再跑表格人名与段落脱敏，写回 dest。

    返回 (替换数, 原文, 脱敏后文本)。

    images: "keep" 原样保留图片（并在报告里列清单提示人工核对）；
            "strip" 删除 word/media 与正文里的图片节点，保证图里的文字不外泄。
    """
    import zipfile
    changed, total = {}, 0
    orig_chunks, new_chunks = [], []
    media_found = []
    dropped = set()
    meta = {"metadata_cleared": [], "comments_removed": 0, "revisions_accepted": 0,
            "hidden_text_revealed": 0, "custom_props_removed": 0,
            "track_revisions_removed": 0, "dropped_parts": []}

    with zipfile.ZipFile(path) as zin:
        names = zin.namelist()
        for item in zin.infolist():
            if RE_MEDIA.match(item.filename):
                media_found.append((item.filename, item.file_size))
        if media_found:
            stats.setdefault("media", []).append((path, media_found, images))

        # ---- 一、元数据 / 批注 / 修订：先清干净，再走正文脱敏 ----
        # 顺序不能反。<w:del> 里的字存在 <w:delText>，_set_para_text 不认它；
        # 先脱敏会把整段文字挤进第一个 <w:t>，修订结构和被删内容都会乱掉。
        for name in names:
            if not RE_DROP_PART.match(name):
                continue
            dropped.add(name)
            xml = zin.read(name).decode("utf-8", "replace")
            if name == "word/comments.xml":
                meta["comments_removed"] += len(re.findall(r"<w:comment[\s>]", xml))
            elif name == "docProps/custom.xml":
                meta["custom_props_removed"] += len(re.findall(r"<property[\s>]", xml))

        if "docProps/core.xml" in names:
            xml = zin.read("docProps/core.xml").decode("utf-8", "replace")
            new, cleared = _clear_fields(xml, CORE_CLEAR)
            meta["metadata_cleared"] += cleared
            if new != xml:
                changed["docProps/core.xml"] = new
        if "docProps/app.xml" in names:
            xml = zin.read("docProps/app.xml").decode("utf-8", "replace")
            new, cleared = _clear_fields(xml, APP_CLEAR)
            meta["metadata_cleared"] += cleared
            if new != xml:
                changed["docProps/app.xml"] = new

        # 删掉的部件必须从这两个索引里摘掉，否则 Word 认为包里缺文件 = 已损坏
        for rn in ("[Content_Types].xml", "_rels/.rels", "word/_rels/document.xml.rels"):
            if rn not in names:
                continue
            xml = zin.read(rn).decode("utf-8", "replace")
            new = xml
            for d in dropped:
                new = _unref_part(new, d)
            if new != xml:
                changed[rn] = new

        # 修订一旦接受就不能再让 Word 继续记录新的
        if "word/settings.xml" in names:
            xml = zin.read("word/settings.xml").decode("utf-8", "replace")
            new, k = re.subn(r"<w:trackRevisions\b[^>]*/>", "", xml)
            if k:
                changed["word/settings.xml"] = new
                meta["track_revisions_removed"] = k

        # ---- 二、整篇上下文：词频表 + 长实体词典 ----
        # 逐段落跑识别时看不到"这个词整篇出现 40 次""这个长串整篇出现 38 次"，
        # 所以先读一遍所有正文部件，建好上下文再替换。
        part_xml = {}
        for name in names:
            if name in dropped or not RE_PART.match(name):
                continue
            try:
                part_xml[name] = zin.read(name).decode("utf-8")
            except UnicodeDecodeError:
                stats.setdefault("warn_enc", []).append(path)
        ctx = DocContext("\n".join(
            _para_text(m.group(0))
            for xml in part_xml.values() for m in RE_PARA.finditer(xml)))

        # ---- 三、正文脱敏 ----
        for name, xml in part_xml.items():
            src_text = "\n".join(_para_text(m.group(0)) for m in RE_PARA.finditer(xml))
            orig_chunks.append(src_text)

            work, k = _accept_revisions(xml)
            meta["revisions_accepted"] += k
            work, k = _strip_vanish(work)
            meta["hidden_text_revealed"] += k
            work = RE_COMMENT_REF.sub("", work)

            out = []
            last = 0
            for m in RE_TBL.finditer(work):
                out.append(work[last:m.start()])
                body, n = _scrub_table(m.group(0), mapper, cw, agg, ctx)
                total += n
                out.append(body)
                last = m.end()
            out.append(work[last:])
            work = "".join(out)

            # 页眉/页脚只有编号本身，没有"编号"二字，按形态直接保护
            strict = name.startswith(("word/header", "word/footer"))

            def on_para(m, _i):
                nonlocal total
                block, n = _scrub_para(m.group(0), mapper, cw, agg, ctx, strict)
                total += n
                return block

            work = _rebuild(work, RE_PARA, on_para)
            if images == "strip":
                # 图片是二进制，文字脱敏碰不到；整块删掉引用与文件，
                # 宁可让客户自己重画，也不把截图里的 IP 和系统名带出去。
                work = RE_DRAWING.sub("", work)
                work = RE_PICT.sub("", work)
            if work != xml:
                changed[name] = work
            new_chunks.append("\n".join(_para_text(m.group(0))
                                         for m in RE_PARA.finditer(work)))

        tmp = dest + ".tmp"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in dropped:
                    continue
                if images == "strip" and RE_MEDIA.match(item.filename):
                    continue
                data = zin.read(item.filename)
                if item.filename in changed:
                    data = changed[item.filename].encode("utf-8")
                zout.writestr(item, data)
    os.replace(tmp, dest)

    meta["dropped_parts"] = sorted(dropped)
    meta["metadata_cleared"] = sorted(set(meta["metadata_cleared"]))
    stats.setdefault("meta", []).append((path, meta))
    return total, "\n".join(orig_chunks), "\n".join(new_chunks)


def process_docx(path, dest, mapper, custom_words, aggressive, stats, images="keep"):
    return _docx_transform(path, dest, mapper, custom_words, aggressive, stats, images)


def docx_restore_file(src, dest, pairs):
    """把占位符换回原文，写回 dest。pairs 为 [(占位符, 原文)]，须按长度倒序。"""
    import zipfile
    changed = {}
    with zipfile.ZipFile(src) as zin:
        for name in zin.namelist():
            if not RE_PART.match(name):
                continue
            xml = zin.read(name).decode("utf-8")
            if "[" not in xml:
                continue

            def rp(m, _i):
                block = m.group(0)
                t = _para_text(block)
                if not t:
                    return block
                u = t
                for ph, orig in pairs:
                    u = u.replace(ph, orig)
                return _set_para_text(block, u) if u != t else block

            work = _rebuild(xml, RE_PARA, rp)
            if work != xml:
                changed[name] = work
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename in changed:
                    data = changed[item.filename].encode("utf-8")
                zout.writestr(item, data)
    return dest


def process_plain(path, mapper, custom_words, aggressive):
    text, enc = read_txt(path)
    new, n = scrub(text, mapper, custom_words, aggressive)
    return new, n, text


def gather_files(target):
    if os.path.isfile(target):
        return [target]
    files = []
    for root, _, names in os.walk(target):
        for n in names:
            if n.lower().endswith((".txt", ".md", ".csv", ".docx")) and not n.startswith("~$"):
                files.append(os.path.join(root, n))
    return sorted(files)


# ---------------------------------------------------------------- 主流程

def run_scrub(args):
    # 口令是硬门槛，不是选项：映射表里是原文对照，明文落盘等于没脱敏。
    # 先校验再动文件，避免跑完才发现映射表不能留。
    map_pwd = getattr(args, "map_password", None)
    if not map_pwd or not map_pwd.strip():
        print("[无法开始] 必须设置映射表口令：--map-password 至少 6 位。\n"
              "  映射表里是原文对照，落到磁盘上等于没脱敏。")
        return 1
    if len(map_pwd) < 6:
        print("[无法开始] 映射表口令至少 6 位。")
        return 1

    files = gather_files(args.target)
    if not files:
        print("未找到可处理文件（支持 .txt/.md/.csv/.docx）")
        return 1

    custom_words = []
    if args.dict:
        raw, _ = read_txt(args.dict)
        custom_words = [w.strip() for w in raw.splitlines()
                        if w.strip() and not w.strip().startswith("#")]
        print("自定义词表：%d 条" % len(custom_words))

    outdir = args.out or os.path.join("out", "desens",
                                      os.path.basename(os.path.abspath(args.target)).rsplit(".", 1)[0])
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    mapper = Mapper()
    stats = {"warn_no_run": [], "warn_enc": [], "files": [], "risks": [],
             "readability": [], "media": []}
    images_mode = getattr(args, "images", "keep")

    for f in files:
        base = os.path.basename(f)
        name, ext = os.path.splitext(base)
        ext = ext.lower()
        dest = os.path.join(outdir, "%s_脱敏%s" % (name, ext))
        try:
            if ext == ".docx":
                n, orig_text, new_text = process_docx(
                    f, dest, mapper, custom_words, args.aggressive, stats, images_mode)
            else:
                new_text, n, orig_text = process_plain(f, mapper, custom_words, args.aggressive)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(new_text)
        except Exception as e:
            print("  [失败] %s : %s" % (base, e))
            continue
        stats["files"].append((base, os.path.basename(dest), n))
        for item in risk_scan(orig_text, new_text):
            stats["risks"].append((base,) + item)
        for item in readability_scan(new_text):
            stats["readability"].append((base,) + item)
        print("  [完成] %s  ->  %s   替换 %d 处" % (base, os.path.basename(dest), n))

    # 映射表
    mapfile = os.path.join(outdir, "映射表_%s.json" % stamp)
    with open(mapfile, "w", encoding="utf-8") as fh:
        json.dump(mapper.dump(map_pwd), fh, ensure_ascii=False, indent=2)

    # 报告（不含原文）
    report = os.path.join(outdir, "脱敏报告_%s.md" % stamp)
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("# 脱敏报告\n\n")
        fh.write("生成时间：%s\n\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        fh.write("## 一、处理结果\n\n| 原文件 | 脱敏文件 | 替换处数 |\n|---|---|---|\n")
        for a, b, n in stats["files"]:
            fh.write("| %s | %s | %d |\n" % (a, b, n))
        fh.write("\n## 二、各类别命中\n\n| 类别 | 数量 |\n|---|---|\n")
        for cat, cnt in sorted(mapper.stat.items(), key=lambda x: -x[1]):
            fh.write("| %s | %d |\n" % (cat, cnt))
        fh.write("\n## 二·补充、无法分类的实体（需人工确认）\n\n")
        un = unclassified_rows(mapper)
        if un:
            fh.write("这些实体没命中单位/系统/型号后缀，按 `[未分类N]` 处理。"
                     "请对照映射表确认它们该归到哪一类。\n\n")
            fh.write("| 占位符 | 遮蔽片段 |\n|---|---|\n")
            for ph, frag in un:
                fh.write("| %s | `%s` |\n" % (ph, frag))
        else:
            fh.write("无。\n")

        fh.write("\n## 三、占位符对照（仅占位符与类别，不含原文）\n\n")
        fh.write("占位符与原文的对应关系见 `%s`，该文件含原文，**严禁外发**。"
                 "已用口令加密，还原时要输同一个口令；口令丢了就没法还原。\n\n"
                 % os.path.basename(mapfile))
        fh.write("## 四、残留风险（需人工复核）\n\n")
        if stats["risks"]:
            fh.write("| 文件 | 风险类型 | 行号 | 遮蔽片段 |\n|---|---|---|---|\n")
            for f, kind, ln, frag in stats["risks"][:120]:
                fh.write("| %s | %s | %d | `%s` |\n" % (f, kind, ln, frag))
            if len(stats["risks"]) > 120:
                fh.write("\n（另有 %d 条未列出，见控制台输出）\n" % (len(stats["risks"]) - 120))
        else:
            fh.write("未发现明显残留。\n")
        fh.write("\n> 遮蔽片段保留首尾字符以便定位，中间以 * 代替，不代表片段全文安全。\n")

        # Word 里看不见、发出去对方却看得见的东西
        fh.write("\n## 五、Word 元数据与隐藏内容\n\n")
        metas = [m for _p, m in stats.get("meta", [])]
        if metas:
            cleared = sorted({x for m in metas for x in m["metadata_cleared"]})
            fh.write("| 项目 | 处理结果 |\n|---|---|\n")
            fh.write("| 文档属性 | %s |\n" % (
                "已清空：" + "、".join("`%s`" % x for x in cleared) if cleared else "无"))
            fh.write("| 自定义属性 | 删除 %d 个 |\n"
                     % sum(m["custom_props_removed"] for m in metas))
            fh.write("| 批注 | 删除 %d 条（comments.xml / people.xml 整份移除） |\n"
                     % sum(m["comments_removed"] for m in metas))
            fh.write("| 修订 | 接受 %d 处（插入保留、删除丢弃） |\n"
                     % sum(m["revisions_accepted"] for m in metas))
            fh.write("| 隐藏文字 | %d 处去掉隐藏标记，文字保留并已走脱敏 |\n"
                     % sum(m["hidden_text_revealed"] for m in metas))
            fh.write("| 修订跟踪 | %s |\n"
                     % ("已关闭" if any(m["track_revisions_removed"] for m in metas)
                        else "未开启"))
        else:
            fh.write("本批没有 .docx，无需处理。\n")

        fh.write("\n## 六、图片（文本脱敏碰不到，必须人工处理）\n\n")
        if stats["media"]:
            any_keep = any(m[2] != "strip" for m in stats["media"])
            if any_keep:
                fh.write("下表是文档里的图片。**图片是按字节原样复制的，里面的 IP、系统名、"
                         "单位名、配置界面一个都没动。**\n\n")
            else:
                fh.write("下表是文档里的图片，已按 `--images=strip` 整块删除"
                         "（图和正文里的图片节点一起删掉了）。\n\n")
            fh.write("| 文件 | 图片 | 大小 | 处理方式 |\n|---|---|---|---|\n")
            for f, items, mode in stats["media"]:
                for mname, msize in items:
                    fh.write("| %s | `%s` | %.0f KB | %s |\n"
                             % (os.path.basename(f), mname.rsplit("/", 1)[-1],
                                msize / 1024.0,
                                "已删除" if mode == "strip" else "原样保留"))
            if any(m[2] != "strip" for m in stats["media"]):
                fh.write("\n> **这些图还留在文档里。** 外发前请逐张打开看：拓扑图上的 IP 和系统名、"
                         "配置截图上的域名和账号、监控大屏上的单位名，全在图里。\n"
                         "> 来不及逐张处理就用 `--images=strip` 重跑一次（图会被整块删掉，"
                         "客户需要图的话再单独重画）。\n")
            else:
                fh.write("\n> 图片已全部移除（`--images=strip`）。正文里对应的图片位置现在是空的，"
                         "需要插图请另行提供重绘版。\n")
        else:
            fh.write("未发现图片。\n")

        # 可读性回检：不判断通顺，只报机械特征，交给人工看
        fh.write("\n## 七、疑似误伤（机械检查，不阻断）\n\n")
        if stats["readability"]:
            fh.write("下面这些位置像是把词拆开了。工具不做语义判断，只按字符位置报出来，"
                     "**请对照脱敏文件人工确认**。\n\n")
            fh.write("| 文件 | 现象 | 行号 | 片段 |\n|---|---|---|---|\n")
            for f, kind, ln, frag in stats["readability"][:80]:
                fh.write("| %s | %s | %d | `%s` |\n" % (f, kind, ln, frag))
            if len(stats["readability"]) > 80:
                fh.write("\n（另有 %d 条未列出）\n" % (len(stats["readability"]) - 80))
            fh.write("\n> 片段取自脱敏后的正文，只含占位符和紧邻的字，不含映射表里的原文。\n")
        else:
            fh.write("未发现占位符被拆进词里的迹象。\n")

    print("\n映射表：%s" % mapfile)
    print("报告  ：%s" % report)
    print("输出目录：%s" % outdir)

    high = [r for r in stats["risks"] if is_high(r[1])]
    if stats["readability"]:
        print("\n[提示] 有 %d 处疑似把词拆开（如 深[单位1]服），见报告第七节，不阻断。"
              % len(stats["readability"]))
    if high:
        print("\n[注意] 存在 %d 条高置信残留（机构名/地名/平台类单位名），"
              "建议人工过一遍报告第四节。" % len(high))
        return 2
    return 0


def run_restore(args):
    try:
        data = load_map(args.restore, getattr(args, "map_password", None))
    except ValueError as e:
        print("[无法还原] %s" % e)
        return 1
    pairs = sorted(((p["placeholder"], p["original"]) for p in data["pairs"]),
                   key=lambda x: -len(x[0]))
    files = gather_files(args.target)
    for f in files:
        name, ext = os.path.splitext(os.path.basename(f))
        dest = os.path.join(os.path.dirname(os.path.abspath(f)), "%s_还原%s" % (name, ext))
        if ext.lower() == ".docx":
            docx_restore_file(f, dest, pairs)
        else:
            text, _ = read_txt(f)
            for ph, orig in pairs:
                text = text.replace(ph, orig)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(text)
        print("  [还原] %s -> %s" % (os.path.basename(f), os.path.basename(dest)))
    return 0


def main():
    ap = argparse.ArgumentParser(description="客户资料本地脱敏工具（离线）")
    ap.add_argument("target", help="待处理文件或目录")
    ap.add_argument("-o", "--out", help="输出目录")
    ap.add_argument("--dict", help="自定义敏感词表（每行一个词，# 开头为注释）")
    ap.add_argument("--aggressive", action="store_true", help="激进模式：对疑似人名也做替换（误杀率上升）")
    ap.add_argument("--restore", help="传入映射表 json，执行还原")
    ap.add_argument("--map-password",
                    help="映射表口令（脱敏时必填，至少 6 位；还原时要用同一个）")
    ap.add_argument("--images", choices=["keep", "strip"], default="keep",
                    help="docx 里的图片怎么处理：keep 原样保留（报告里列清单提醒人工看），"
                         "strip 整块删除（图里的 IP/系统名脱不到，删了最稳）")
    args = ap.parse_args()

    if args.restore:
        return run_restore(args)
    return run_scrub(args)


if __name__ == "__main__":
    sys.exit(main())
