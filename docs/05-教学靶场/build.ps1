# ============================================================================
#  SeepLab · 教学靶场编译脚本（零依赖）
#
#  使用 Windows 自带的 .NET Framework 4.x 编译器，
#  无需安装 Visual Studio / .NET SDK / 任何 NuGet 包。
#
#  用法：
#    powershell -ExecutionPolicy Bypass -File build.ps1
#    SeepLab.exe 01        # 运行模式 01
#    SeepLab.exe all       # 运行全部
# ============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $root 'src\SeepLab'
$out  = Join-Path $root 'SeepLab.exe'

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
if (-not (Test-Path $csc)) { Write-Host "[-] 未找到 csc.exe（.NET Framework 4.x）" -ForegroundColor Red; exit 1 }

$sources = @(
    "$src\Program.cs",
    "$src\Pattern01_SinglePointBool.cs",
    "$src\Pattern02_HardcodedKey.cs",
    "$src\Pattern03_DllSearchOrder.cs",
    "$src\Pattern04_WritableGlobalState.cs",
    "$src\Pattern05_PlaintextIpc.cs",
    "$src\Pattern07_FailOpen.cs"
)

& $csc /nologo /target:exe /platform:anycpu /optimize+ /codepage:65001 /out:$out $sources

if ($LASTEXITCODE -ne 0) { Write-Host "[-] 编译失败" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "[+] SeepLab 编译成功: $out" -ForegroundColor Green
Write-Host ""
Write-Host "试用:" -ForegroundColor Cyan
Write-Host "  SeepLab.exe 01        # 模式 01 · 单点布尔裁决"
Write-Host "  SeepLab.exe 02        # 模式 02 · 硬编码密钥材料"
Write-Host "  SeepLab.exe 03        # 模式 03 · 动态库加载顺序缺陷"
Write-Host "  SeepLab.exe 03 <PE>   # 对任意 PE 做导入表审计"
Write-Host "  SeepLab.exe 04        # 模式 04 · 可写全局状态变量"
Write-Host "  SeepLab.exe 05        # 模式 05 · 明文进程间通信"
Write-Host "  SeepLab.exe 07        # 模式 07 · 空值短路校验"
Write-Host "  SeepLab.exe all       # 依次运行全部"
