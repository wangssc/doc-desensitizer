# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置：单文件 exe，双击即用，不需要装 Python。
import os

block_cipher = None

a = Analysis(
    ['desensitize_server.py'],
    pathex=[],
    binaries=[],
    datas=[('ui/index.html', 'ui')],
    hiddenimports=['desensitize'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 脱敏只用标准库；这几个是 md2docx / 图标脚本才需要的，排除能省十几 MB
    excludes=[
        'tkinter', 'unittest', 'pydoc', 'doctest',
        'numpy', 'pandas', 'matplotlib', 'scipy',
        'PIL', 'Pillow', 'setuptools', 'pip',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='DesensTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                 # 双击不弹黑框
    disable_windowed_traceback=False,  # 崩溃时弹窗，而不是静默死掉
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app.ico',
)
