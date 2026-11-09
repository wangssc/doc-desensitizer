# 文档脱敏工具启动器（v2 带日志）
# 已在跑 -> 直接开浏览器；没跑 -> 起 exe，等它就绪再开
# 加 -NoBrowser 只起服务不开浏览器（自动化测试用）
param([switch]$NoBrowser)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log  = Join-Path $Root "启动日志.txt"

function Say($msg, $color = "White") {
    Write-Host $msg -ForegroundColor $color
    try { Add-Content -Path $Log -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg) -Encoding UTF8 } catch { }
}

Say "===== 启动开始 ====="

$Exe = Join-Path $Root "dist\DesensTool.exe"
if (-not (Test-Path $Exe)) { $Exe = Join-Path $Root "DesensTool.exe" }
if (-not (Test-Path $Exe)) {
    Say "找不到 DesensTool.exe" "Red"
    Read-Host "按回车退出"
    exit 1
}
Say "exe: $Exe"

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
    Say "服务已经在运行：http://127.0.0.1:$port" "Green"
} else {
    Say "正在启动…（第一次要 10 秒左右）" "Yellow"
    try {
        Start-Process -FilePath $Exe -WindowStyle Hidden -ErrorAction Stop
    } catch {
        Say ("启动 exe 失败：" + $_.Exception.Message) "Red"
        Read-Host "按回车退出"
        exit 1
    }
    $port = 0
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 800
        $port = Find-Desens
        if ($port -gt 0) { break }
    }
    if ($port -eq 0) {
        Say "启动失败：等了 32 秒端口还是没通。" "Red"
        Say "请直接双击 dist\DesensTool.exe，看它报什么错，把上面的文字截图发我。" "Yellow"
        Read-Host "按回车退出"
        exit 1
    }
    Say "已经启动：http://127.0.0.1:$port" "Green"
}

if (-not $NoBrowser) {
    try {
        Start-Process "http://127.0.0.1:$port" -ErrorAction Stop
        Say "浏览器已打开。"
    } catch {
        Say ("打开浏览器失败：" + $_.Exception.Message) "Red"
        Say "请手动在浏览器里打开：http://127.0.0.1:$port" "Yellow"
    }
    Start-Sleep -Milliseconds 800
}

Say "===== 启动结束 ====="
exit 0