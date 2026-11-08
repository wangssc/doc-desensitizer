# Document Desensitizer

Replaces identifying details in a document with stable placeholders so the file
can be shared, while keeping the technical substance — sizes, architecture,
algorithms, metrics — untouched.

Runs entirely on your machine. No network, no upload, no account.

---

## What it does

Reads a `.docx` / `.txt` / `.md` / `.csv` and swaps identifying details for
`[type + number]` tokens: person names, organisation names, place names, IPs,
phone numbers, email addresses, account names, ID numbers, device models,
domains and file paths.

The same original always maps to the same placeholder, so the text still reads
coherently.

It writes three things:

- `<name>_脱敏.docx` — the version you can send out
- `映射表_<timestamp>.json` — **contains the originals, can reverse everything,
  never send this anywhere**
- `脱敏报告_<timestamp>.md` — what was replaced and what may still be left;
  contains no originals

Two modes: normal (default, only high-confidence matches) and aggressive
(`--aggressive`, also replaces suspected person names, more false positives).

## What it does NOT do

This section matters more than the one above.

- **No PDF support.** Only `.docx` / `.txt` / `.md` / `.csv`. Convert PDFs to
  docx first.
- **No scanned documents.** No text layer means nothing to read; there is no OCR.
- **Text inside Word images is invisible to it.** IPs, system names, labels and
  stamps that only exist as pixels are not touched. For docx you can delete the
  images outright (`--images strip`, safest) or keep them — the report then
  lists them so a human can look.
- **Names ending in 「平台」 (platform) are not recognised.** Organisation names
  are matched from a suffix list (company, group, hospital, university, bank,
  research institute …) and that list has no entry for platform. Names like
  「××数据共享平台」 stay as they are; add them to a custom word list.
- **No semantic understanding.** It matches patterns. Generic references like
  「某部门」 are left alone, and a technical term that looks like a person name
  can be caught by mistake (more so in aggressive mode).
- **It does not tell you whether the result is safe to send.** It removes what it
  can recognise; read the residual-risk section of the report for the rest.

## Where the data goes

- Listens on **`127.0.0.1:8765` only** — loopback, unreachable from other
  machines on the network.
- **No uploads, no account, no telemetry.**
- The only outward action is opening your browser on startup. The UI loads no
  external resources at all — no CDN, no web fonts, no icon library. To verify:
  open devtools, all requests should go to `127.0.0.1:8765`.
- Everything is written under `out/desens/<batch>/` on this machine.

Before sending anything, check it is not a `映射表*.json` — the mapping table
contains the originals, and shipping it alongside the desensitized file defeats
the entire exercise.

## Usage

Easiest: double-click `启动脱敏工具.bat` (needs Python 3.8+). The browser opens
on its own; drag files into the drop zone.

Or:

```bash
python desensitize_server.py
```

Command line:

```bash
python desensitize.py 客户端资料.docx
python desensitize.py 客户端资料/ -o out/desens
python desensitize.py 资料.docx --dict 自定义词表.txt
python desensitize.py 资料.docx --aggressive
python desensitize.py 资料.docx --images strip
python desensitize.py 脱敏版.docx --restore out/desens/映射表_xxx.json
```

Exit codes: `0` fine; `2` high-risk residue found, needs a human look.

The interface and CLI output are in Chinese; this English file exists so
non-Chinese readers can tell what the tool does and what it refuses to do.

## Building a standalone exe

```bash
pip install pyinstaller python-docx
pyinstaller DesensTool.spec --noconfirm
```

Output is `dist/DesensTool.exe`. No console window, UI bundled inside, so the
single file works on a machine without Python.

## Regression baseline

After any change, these numbers must not move:

```
sample.txt normal mode    -> 24 replacements
sample.txt aggressive     -> 26 replacements
```

`python -c "import desensitize"` must also succeed without `python-docx`
installed; python-docx is only needed when actually reading docx files.

## Requirements

- Python 3.8+
- `python-docx` (docx only; plain text formats need nothing beyond the stdlib)

## License

MIT
