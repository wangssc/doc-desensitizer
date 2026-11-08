@echo off
"%SystemRoot%\System32\chcp.com" 65001 >nul 2>&1
title Desensitize Tool - keep this window open
cd /d "%~dp0"

set "PY="
python -V >nul 2>&1 && set "PY=python"
if not defined PY (
    py -3 -V >nul 2>&1 && set "PY=py -3"
)

if not defined PY (
    echo.
    echo   [ERROR] Python 3.8+ not found.
    echo   Install it and check "Add Python to PATH": https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

%PY% -c "import docx" >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [WARN] python-docx not installed - Markdown to Word conversion is disabled.
    echo          Fix:  %PY% -m pip install python-docx -i https://pypi.tuna.tsinghua.edu.cn/simple
    echo          Desensitizing itself does not need it.
    echo.
)

%PY% "%~dp0desensitize_server.py"
if errorlevel 1 (
    echo.
    echo   [ERROR] Server failed to start. Screenshot this window and send it over.
    echo.
    pause
)
