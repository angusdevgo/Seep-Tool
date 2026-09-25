$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $root 'src'
$out = Join-Path $root 'SeepTool.exe'

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$wpf = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\WPF"

$sources = @(
    "$src\Program.cs",
    "$src\PeUtil.cs",
    "$src\TargetLocator.cs",
    "$src\DetectionEngine.cs",
    "$src\TargetDetectors.cs",
    "$src\BandizipModule.cs",
    "$src\BandizipDllModule.cs",
    "$src\UninstallToolModule.cs",
    "$src\ListaryModule.cs",
    "$src\OneClickActivate.cs",
    "$src\SeerModule.cs",
    "$src\SnipasteModule.cs"
)

$argsList = @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/platform:x64",
    "/codepage:65001",
    "/lib:$wpf",
    "/r:System.dll",
    "/r:System.Core.dll",
    "/r:Microsoft.CSharp.dll",
    "/r:System.Xaml.dll",
    "/r:WindowsBase.dll",
    "/r:PresentationCore.dll",
    "/r:PresentationFramework.dll",
    "/r:System.Drawing.dll",
    "/r:System.Numerics.dll",
    "/r:System.Web.Extensions.dll",
    "/win32icon:$src\app.ico",
    "/win32manifest:$src\app.manifest",
    "/out:$out"
) + $sources

& $csc $argsList
if ($LASTEXITCODE -ne 0) { throw "Build failed!" }

Copy-Item "$src\app_icon.png" "$root\app_icon.png" -Force
Write-Host "[+] Seep-Tool (WPF Native Pro) 构建成功: $out"
