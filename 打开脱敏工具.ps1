# 文档脱敏工具启动器
# 已在跑 → 直接开浏览器；没跑 → 起 exe，等它就绪再开
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe  = Join-Path $Root "dist\DesensTool.exe"
if (-not (Test-Path $Exe)) {
    $Exe = Join-Path $Root "DesensTool.exe"
}
if (-not (Test-Path $Exe)) {
    Write-Host "找不到 DesensTool.exe，请确认它和本文件在同一个文件夹。" -ForegroundColor Red
    Read-Host "按回车退出"
    exit 1
}

function Find-Desens {
    foreach ($p in 8765..8775) {
        try {
            $r = Invoke-WebRequest "http://127.0.0.1:$p/api/ping" -UseBasicParsing -TimeoutSec 1
            if ($r.Content -match '"app"\s*:\s*"desens"') { return $p }
        } catch { }
    }
    return 0
}

$port = Find-Desens
if ($port -gt 0) {
    Write-Host "服务已经在运行，正在打开浏览器…" -ForegroundColor Green
    Start-Process "http://127.0.0.1:$port"
    Start-Sleep -Milliseconds 800
    exit 0
}

Write-Host "正在启动…（第一次启动要几秒）" -ForegroundColor Yellow
Start-Process -FilePath $Exe -WindowStyle Hidden

for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 800
    $port = Find-Desens
    if ($port -gt 0) {
        Write-Host "已经启动：http://127.0.0.1:$port" -ForegroundColor Green
        Start-Process "http://127.0.0.1:$port"
        Start-Sleep -Milliseconds 800
        exit 0
    }
}

Write-Host "启动失败。请直接双击 dist\DesensTool.exe 看看报什么错。" -ForegroundColor Red
Read-Host "按回车退出"
exit 1
