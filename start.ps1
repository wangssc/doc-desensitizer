# 文档脱敏工具启动器（v3 单实例锁 + 防抖）
# 已在跑 -> 直接开浏览器；没跑 -> 起 exe，等它就绪再开
# 加 -NoBrowser 只起服务不开浏览器（自动化测试用）
param([switch]$NoBrowser)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log  = Join-Path $Root "启动日志.txt"

function Say($msg, $color = "White") {
    Write-Host $msg -ForegroundColor $color
    try { Add-Content -Path $Log -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg) -Encoding UTF8 } catch { }
}

# ---- 单实例锁：连点时只有一个启动器能干活，其余直接退出 ----
$mutex  = New-Object System.Threading.Mutex($false, "Global\DesensToolLauncher")
$gotLock = $false
try {
    $gotLock = $mutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $gotLock = $true   # 上一个启动器被强杀，锁已归我们
}
if (-not $gotLock) {
    Say "已经在启动了，请等几秒，不要重复点击。" "Yellow"
    exit 0
}

try {
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
        Say "正在启动…（第一次约 10 秒，请不要重复双击）" "Yellow"
        # PyInstaller 单文件版运行时会有父子两个同名进程，Count>0 即说明已在解包中
        $existing = @(Get-Process -Name "DesensTool" -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            Say "程序正在启动中，请稍候…" "Yellow"
        } else {
            try {
                Start-Process -FilePath $Exe -WindowStyle Hidden -ErrorAction Stop
            } catch {
                Say ("启动 exe 失败：" + $_.Exception.Message) "Red"
                Read-Host "按回车退出"
                exit 1
            }
        }
        $port = 0
        $dots = $false
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Milliseconds 1000
            $port = Find-Desens
            if ($port -gt 0) { break }
            if ($i % 2 -eq 1) { Write-Host "." -NoNewline -ForegroundColor Yellow; $dots = $true }
        }
        if ($dots) { Write-Host "" }
        if ($port -eq 0) {
            Say "启动失败：等了 40 秒端口还是没通。" "Red"
            Say "请直接双击 dist\DesensTool.exe，看它报什么错，把上面的文字截图发我。" "Yellow"
            Read-Host "按回车退出"
            exit 1
        }
        Say "已经启动：http://127.0.0.1:$port" "Green"
    }

    if (-not $NoBrowser) {
        # 短时防抖：4 秒内已经开过就不再开，挡住连点/双击被识别成两次
        $stamp = Join-Path $Root ".last-open"
        $now = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        $skip = $false
        if (Test-Path $stamp) {
            try {
                $last = [long](Get-Content $stamp -Raw).Trim()
                if (($now - $last) -lt 4) { $skip = $true }
            } catch { }
        }
        if ($skip) {
            Say "刚才已经打开过浏览器，这次不重复打开。" "Yellow"
        } else {
            try {
                Set-Content -Path $stamp -Value $now -Encoding ASCII
                Start-Process "http://127.0.0.1:$port" -ErrorAction Stop
                Say "浏览器已打开。"
            } catch {
                Say ("打开浏览器失败：" + $_.Exception.Message) "Red"
                Say "请手动在浏览器里打开：http://127.0.0.1:$port" "Yellow"
            }
        }
        Start-Sleep -Milliseconds 800
    }

    Say "===== 启动结束 ====="
    exit 0
} finally {
    try { $mutex.ReleaseMutex() } catch { }
    $mutex.Dispose()
}
