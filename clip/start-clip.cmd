@echo off
rem 双击运行：起一个无控制台的常驻进程，托盘出现「脱敏助手」图标即成功。
rem 这里不做安装、不写注册表、不加开机自启，关掉图标（右键→退出）就结束。
chcp 65001 >nul
cd /d "%~dp0"

where pythonw >nul 2>nul
if errorlevel 1 (
  echo 没找到 pythonw.exe，请先安装 Python 3.8+ 并勾选 "Add Python to PATH"。
  pause
  exit /b 1
)

start "" pythonw "%~dp0clipwatch.py"
exit /b 0
