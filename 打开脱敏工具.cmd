@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0打开脱敏工具.ps1"
if errorlevel 1 pause