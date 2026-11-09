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

PLACEHOLDER_RE = re.compile(r"\[(单位|机关|人员|IP|域名|型号|电话|邮箱|证件号|编号|路径|账号|组织|自定义)\d*\]")


class Mapper:
    """保证同一原文实体全文映射到同一占位符，编号自增。"""

    def __init__(self):
        self.forward = {}   # (类别, 原文) -> 占位符
        self.backward = {}  # 占位符 -> 原文
        self.counter = {}
        self.stat = {}

    def get(self, cat, raw):
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
        body = {
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
            "note": "此文件包含原文，仅限本地保存，严禁外发。",
            "pairs": [{"category": c, "placeholder": p, "original": o}
                      for (c, o), p in self.forward.items()],
        }
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
RE_PH_LIKE = re.compile(
    r"(?:单位|机关|人员|IP|域名|型号|电话|邮箱|证件号|编号|路径|账号|组织|自定义|地址)\d*",
    re.I)


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


# ---------------------------------------------------------------- 识别规则

# 机构后缀（按长度降序，保证最长匹配优先）
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
    "医院", "研究院", "中心", "厂", "局", "站", "所", "社",
]
ORG_TAIL_RE = re.compile("|".join(re.escape(t) for t in dict.fromkeys(ORG_TAILS)))

# 左向回溯到此字符即停止
ORG_STOP = set(
    "的了在由向对与和及或为是该本我你他她它这那有所把被将等把被使同从到给"
    "和与并而且但则即就都也还又再很更最太不没无"
    "，。；：、！？（）()[]{}<>《》\"'`\n\t\r 　·—…/"
)

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
}

# 复姓（用于姓名识别）
SURNAME = (
    "赵钱孙李周吴郑王冯陈卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏窦章苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐费廉"
    "岑薛雷贺倪汤滕殷罗毕郝邬安常乐于傅齐康伍余元顾孟平黄穆萧尹姚邵"
    "汪祁毛狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁杜阮蓝闵席季麻"
    "强贾路娄江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍虞万支柯卢莫房"
    "解应宗丁宣邓郁单杭洪包诸左石崔吉龚程邢裴陆荣翁荀惠甄曲封芮储靳"
    "段富巫乌焦巴牧山谷车侯全班仰秋仲伊宫宁仇栾暴甘厉戎祖武符刘景詹"
    "束龙叶幸司韶黎薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴胥苍双闻"
    "党翟谭贡劳姬申扶冉宰雍桑桂牛寿通边燕冀浦尚农温别庄晏柴瞿阎慕连"
    "茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘匡国文寇广禄阙东欧"
    "沃利蔚越隆师巩聂晁融冷辛阚简饶空曾沙鞠须丰巢关蒯相查后荆红游权"
    "盖益桓公"
)
COMPOUND_SURNAME = ["欧阳", "司马", "上官", "诸葛", "东方", "独孤", "皇甫", "尉迟",
                    "公孙", "慕容", "长孙", "宇文", "司徒", "夏侯", "令狐", "钟离"]

# 职务/称谓锚点（前后出现时，旁边的 2-3 字视为人名）
ROLE_WORDS = ("责任人", "负责人", "联系人", "编制人", "编写人", "审核人", "审定人",
              "批准人", "签名人", "操作人", "经办人", "承办人", "接收人", "移交人",
              "监交人", "患者", "病人", "医师", "医生", "主任", "院长", "副院长",
              "科长", "处长", "局长", "经理", "项目经理", "工程师",
              "管理员", "安全管理员", "密钥管理员", "审计员", "护士长", "技师",
              "老师", "同学", "先生", "女士",
              "姓名", "患者姓名", "户名", "开户人", "持证人", "签字人", "签发人")

# 以姓开头但并非人名的常见词（避免"项目负责人"被当成"项"姓+"目"）
NOT_NAME = {
    "项目", "本院", "该院", "全院", "外院", "科室", "医院", "系统", "信息", "安全",
    "操作", "管理", "维护", "值班", "交接", "负责", "签字", "审核", "批准", "编制",
    "设备", "网络", "数据", "业务", "服务", "平台", "机房", "云商", "厂商", "供应商",
    "密码", "密钥", "证书", "日志", "主机", "数据库", "影像", "报告", "终端", "用户",
    "本次", "所有", "全部", "相关", "以上", "以下", "上述", "附表", "附件", "表格",
}

# "××市""某区"这类已是占位形态，不重复处理
RE_PLACEHOLDERISH = re.compile(r"(?:[×xX某]{1,4}|\*{1,4})(?:省|市|区|县|镇|路|街|大道|医院|公司|局|院)")

# 标准/规范号白名单前缀（绝不能脱敏）
STD_PREFIX = r"(?:GB|GB/T|GM|GM/T|GA|GA/T|WS|WS/T|YY|YY/T|YD|YD/T|SJ|SJ/T|JR|JR/T|ISO|ISO/IEC|IEC|IEEE|RFC|ANSI|NIST|EN|ITU)"

# 末尾必须是"非字母非数字"：只挡字母时，"GM2024CERT0001234" 里的 "GM202"
# 仍会被认成标准号，并把它整串证书编号从命中列表里挤掉。
RE_STD = re.compile(STD_PREFIX + r"\s?\d[\d.\-—:/]*(?![A-Za-z0-9])", re.I)
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
# 门牌地址：××路 168 号
RE_STREET = re.compile(r"[\u4e00-\u9fa5]{2,12}(?:路|街|大道|大街|巷|胡同|里弄)\s*\d{1,5}\s*(?:号|号楼|栋|座|层|室)?")
# 链式行政区划：省+市、市+区/县。只认连续两级，避免"服务器区""三个区域"被误伤
RE_ADMIN_CHAIN = re.compile(
    r"[\u4e00-\u9fa5]{2,3}(?:省|自治区)[\u4e00-\u9fa5]{2,4}(?:市|州|盟)(?:[\u4e00-\u9fa5]{2,4}(?:区|县|市))?"
    r"|[\u4e00-\u9fa5]{2,4}(?:市)[\u4e00-\u9fa5]{2,4}(?:区|县|市)"
)
# 楼宇名：技术文本里"大厦/广场/大楼"几乎不会作为通用词出现，单独认是安全的。
# 只认这三类，不碰"中心/园区"，避免误伤"数据中心""园区网"。
RE_BUILDING = re.compile(r"[\u4e00-\u9fa5]{2,12}(?:大厦|广场|大楼)")
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

# 保留不改的常见技术串
KEEP = re.compile(r"^(?:SM[2349]|HIS|PACS|LIS|EMR|CA|KMS|HSM|TLS|SSL|IPSec|TLCP|VPN|WAF|API|CPU|USB|AES|RSA|SHA|MD5|CBC|CTR|GCM|RAM|SSD|HDD|IOPS|GB|TB|MB|KB|Mbps|Gbps|NFS|CIFS|SMB|FTP|SFTP|SNMP|NTP|SYSLOG|BIG-IP|RAID|VLAN|NAC|OCSP|CRL|TSA|RA|DICOM|HL7|OFD|PDF)$", re.I)


def _ok_org(name):
    core = name.strip()
    if len(core) < 4 or len(core) > 20:
        return False
    if core in ORG_BLACK:
        return False
    # 全是通用词组合（如"该医院""三级医院"）
    if core.lstrip("该本我你他其此这那") in ORG_BLACK:
        return False
    if re.fullmatch(r"[一二三四五六七八九十第次级]*(?:医院|中心|局|所|站)", core):
        return False
    # 以"的"开头等异常
    if core[0] in "的了在和与及或为是":
        return False
    return True


def find_orgs(text):
    out = []
    for m in ORG_TAIL_RE.finditer(text):
        end = m.end()
        s = m.start()
        limit = max(0, s - 12)
        while s > limit:
            ch = text[s - 1]
            if ch in ORG_STOP:
                break
            s -= 1
        name = text[s:end].strip()
        if _ok_org(name):
            out.append((s, end, "单位", name))
    return out


_ROLE_ALT = "|".join(re.escape(r) for r in ROLE_WORDS)
RE_PERSON_AFTER_ROLE = re.compile(
    r"(?:%s)\s*[:：]?\s*([\u4e00-\u9fa5]{2,3})(?=[，。；、\s（()）]|$)" % _ROLE_ALT)
RE_PERSON_BEFORE_ROLE = re.compile(r"([\u4e00-\u9fa5]{1,3})(?:%s)" % _ROLE_ALT)
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
# 3 字候选的末字若命中这里，说明更像「姓+名+动词」，截成 2 字（周伟补充 → 周伟）
NOT_NAME_CHARS = set(
    "的了是在和与及或为由向对该本各全单同按分共约近达超占"
    "提补说认表示指出讲问答需要应当可能会将已未不没无有"
    "这那其此我你他她它们个些种次项条款章节段句字位名组类批期年月日时分秒")


def find_persons(text, loose=False):
    """只在上下文明确时判定人名，避免把'密码机''服务器'误杀。

    loose=True（--aggressive）时额外扫"孤立的 2-3 字中文串"，
    靠 首字是姓氏 + NOT_NAME 白名单 双重限制，误杀率仍会明显上升。
    """
    out = []
    # 形态一：职务 + 可选冒号/空格 + 姓名
    for m in RE_PERSON_AFTER_ROLE.finditer(text):
        nm = m.group(1)
        if nm in NOT_NAME:
            continue
        out.append((m.start(1), m.end(1), "人员", nm))
    # 形态二：姓名 + 职务（张主任、李工程师）
    for m in RE_PERSON_BEFORE_ROLE.finditer(text):
        nm = m.group(1)
        if len(nm) < 2 or nm in NOT_NAME:
            continue
        if nm[0] not in SURNAME and nm[:2] not in COMPOUND_SURNAME:
            continue
        out.append((m.start(1), m.end(1), "人员", nm))
    # 形态三（仅激进模式）：孤立人名
    if loose:
        for m in RE_LOOSE_NAME.finditer(text):
            nm = m.group(1)
            if nm in NOT_NAME or PLACEHOLDER_RE.search(nm):
                continue
            if nm[0] not in SURNAME and nm[:2] not in COMPOUND_SURNAME:
                continue
            if len(nm) == 3 and nm[2] in NOT_NAME_CHARS:
                nm = nm[:2]
                if len(nm) < 2 or nm in NOT_NAME:
                    continue
            s = m.start(1)
            out.append((s, s + len(nm), "人员", nm))
    return out


def find_addresses(text):
    """地址、链式行政区划、公文文号。已呈占位形态（××市/某区）的跳过。

    设计取舍：只脱"省+市""市+区县""路名+门牌"这类连续结构，
    不对单独的"X市""X区"做猜测式替换。原因是一次误伤会改坏技术语义
    （如"划分三个区域"被替换成"[地址]域"），代价高于漏脱一处裸地名。
    裸地名由报告第四节列出，用 --dict 精确补。
    """
    out = []
    ph = [m.span() for m in RE_PLACEHOLDERISH.finditer(text)]

    def blocked(s, e):
        return any(s < pe and e > ps for ps, pe in ph)

    for m in RE_STREET.finditer(text):
        s, e = m.span()
        if not blocked(s, e):
            out.append((s, e, "地址", m.group(0)))
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
            out.append((s, e, "地址", g))
    for m in RE_DOCNO.finditer(text):
        out.append((m.start(), m.end(), "编号", m.group(0)))
    for m in RE_BUILDING.finditer(text):
        g = m.group(0)
        cut = 0
        while cut < 6 and len(g) > 4 and g[0] in ADMIN_TRIM:
            g = g[1:]
            cut += 1
        s = m.start() + cut
        if len(g) < 4 or g in ADMIN_BAD_WHOLE:
            continue
        if not blocked(s, m.end()):
            out.append((s, m.end(), "地址", g))
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
    for m in RE_MODEL.finditer(text):
        tok = m.group(0)
        if RE_MODEL_EXCLUDE.match(tok) or KEEP.match(tok):
            continue
        if re.match(r"^[A-Za-z]{0,3}\d{1,3}$", tok):  # 纯数字或极短，跳过
            continue
        if re.search(r"[A-Za-z]", tok) and re.search(r"\d", tok) and len(tok) >= 4:
            out.append((m.start(), m.end(), "型号", tok))
    return out


def find_custom(text, words):
    out = []
    for w in words:
        w = w.strip()
        if not w:
            continue
        start = 0
        while True:
            i = text.find(w, start)
            if i < 0:
                break
            out.append((i, i + len(w), "自定义", w))
            start = i + len(w)
    return out


# ---------------------------------------------------------------- 主替换逻辑

def collect(text, custom_words=(), aggressive=False):
    """返回命中列表 [(start, end, cat, raw)]，已按优先级处理重叠。"""
    hits = []
    hits += find_custom(text, custom_words)
    hits += find_orgs(text)
    hits += find_persons(text, loose=aggressive)
    hits += find_addresses(text)
    hits += find_ids(text)

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

    # 去重叠：长优先，其次类别优先级。
    # taken 按 start 升序且互不重叠，插入点前后各查一次即可，O(n log n)。
    prio = {"自定义": 0, "证件号": 1, "编号": 2, "电话": 3, "邮箱": 4, "域名": 5,
            "IP": 6, "账号": 7, "路径": 8, "地址": 9, "单位": 10, "人员": 11, "型号": 12}
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
    return chosen


def scrub(text, mapper, custom_words=(), aggressive=False):
    chosen = collect(text, custom_words=custom_words, aggressive=aggressive)
    if not chosen:
        return text, 0
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


def _scrub_para(block, mapper, cw, agg):
    plain = _para_text(block)
    if not plain.strip():
        return block, 0
    new, n = scrub(plain, mapper, cw, agg)
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


def _scrub_table(tbl, mapper, cw, agg):
    """表格里单独成格的人名没有上下文，靠表头列名推断。"""
    rows = RE_TR.findall(tbl)
    if not rows:
        return tbl, 0
    header = [_para_text(c).strip() for c in RE_TC.findall(rows[0])]
    pcols = {i for i, h in enumerate(header) if any(k in h for k in PERSON_HEADERS)}
    if not pcols:
        return tbl, 0
    total = [0]
    ri = [-1]

    def on_row(m, _i):
        ri[0] += 1
        if ri[0] == 0:
            return m.group(0)
        ci = [-1]

        def on_cell(mc, _j):
            ci[0] += 1
            if ci[0] not in pcols:
                return mc.group(0)
            t = _para_text(mc.group(0)).strip()
            if not (2 <= len(t) <= 4 and SURNAME_ONLY.fullmatch(t)
                    and t not in NOT_NAME and not PLACEHOLDER_RE.search(t)):
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

        # ---- 二、正文脱敏 ----
        for name in names:
            if name in dropped or not RE_PART.match(name):
                continue
            try:
                xml = zin.read(name).decode("utf-8")
            except UnicodeDecodeError:
                stats.setdefault("warn_enc", []).append(path)
                continue
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
                body, n = _scrub_table(m.group(0), mapper, cw, agg)
                total += n
                out.append(body)
                last = m.end()
            out.append(work[last:])
            work = "".join(out)

            def on_para(m, _i):
                nonlocal total
                block, n = _scrub_para(m.group(0), mapper, cw, agg)
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
    stats = {"warn_no_run": [], "warn_enc": [], "files": [], "risks": [], "media": []}
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

    print("\n映射表：%s" % mapfile)
    print("报告  ：%s" % report)
    print("输出目录：%s" % outdir)

    high = [r for r in stats["risks"] if is_high(r[1])]
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
