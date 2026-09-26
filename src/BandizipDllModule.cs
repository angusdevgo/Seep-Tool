// BandizipDllModule.cs — Bandizip 双通道引擎：静态 PE 补丁 + DLL 热注入代理部署
// 支持: 自定义授权用户名/邮箱/密钥 (通过 version_patch.ini 注入显示层)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Seep.Core;

namespace Seep.Modules
{
    public static class BandizipDllModule
    {
        public const string Name = "Bandizip (DLL 注入模式)";
        public const string ExeName = "Bandizip.x64.exe";
        public const string DllName = "version.dll";
        public const string IniName = "version_patch.ini";
        public const string LogName = "version_patch.log";

        // 内置 DLL 资源路径（Suite 根目录下）
        public static string ProxyDllSource = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bandizip", "version.dll");

        public static List<string> Locate() { return TargetLocator.FindBandizip(); }

        // 检测当前状态（是否已部署 DLL 代理 + 是否存在热补丁日志）
        public static string CheckState(string dir, IList<string> log)
        {
            string dll = Path.Combine(dir, DllName);
            string ini = Path.Combine(dir, IniName);
            string logFile = Path.Combine(dir, LogName);

            if (!File.Exists(dll))
            {
                log.Add("[*] 尚未部署 version.dll 代理（将采用静态 PE 补丁模式）");
                return "original";
            }

            // 已部署：检查日志判断热补丁是否成功执行
            if (File.Exists(logFile))
            {
                string content;
                try { content = File.ReadAllText(logFile); }
                catch { return "unknown"; }

                if (content.Contains("3/3 sites succeeded"))
                {
                    log.Add("[✓] DLL 代理已注入，热补丁 3/3 全部生效（Enterprise 激活 + 黑名单直通 + 显示层拦截）");
                    if (File.Exists(ini))
                        log.Add("[+] 检测到 version_patch.ini 配置（自定义授权用户名/邮箱已激活）");
                    else
                        log.Add("[i] 未发现 version_patch.ini（使用默认授权信息：AngusDevLab）");
                    return "patched";
                }
                if (content.Contains("Patch summary"))
                {
                    log.Add("[!] DLL 已注入但补丁未完全生效，建议重新部署");
                    return "unknown";
                }
            }

            log.Add("[*] DLL 已存在但尚未运行 Bandizip（无日志），状态待确认");
            return "unknown";
        }

        public static void Check(string dir, IList<string> log)
        {
            CheckState(dir, log);
        }

        /// <summary>
        /// 部署 version.dll 代理到 Bandizip 目录（一建激活，原地生效）
        /// </summary>
        /// <param name="dir">Bandizip 安装目录</param>
        /// <param name="userName">自定义授权用户名（为空则使用默认 AngusDevLab）</param>
        /// <param name="userEmail">自定义授权邮箱</param>
        /// <param name="userKey">自定义授权密钥文本</param>
        public static bool DeployProxy(string dir, string userName, string userEmail, string userKey, IList<string> log)
        {
            string dll = Path.Combine(dir, DllName);

            // 1. 检查源 DLL 是否存在
            if (!File.Exists(ProxyDllSource))
            {
                // 备用路径：Bandzip/poc/ 目录
                string alt = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Bandzip", "poc", "version.dll");
                if (File.Exists(alt))
                    ProxyDllSource = Path.GetFullPath(alt);
                else
                {
                    log.Add("[-] 未找到内置 version.dll 源文件：" + ProxyDllSource);
                    return false;
                }
            }

            try
            {
                // 2. 检查 Bandizip 是否正在运行（避免文件占用）
                bool needRestart = false;
                var procs = Process.GetProcessesByName("Bandizip");
                if (procs.Length > 0)
                {
                    log.Add("[!] 检测到 Bandizip 正在运行，需要先关闭才能部署 DLL");
                    foreach (var p in procs)
                    {
                        try { p.Kill(); p.WaitForExit(3000); needRestart = true; }
                        catch { }
                    }
                    if (needRestart) log.Add("[+] 已自动关闭 Bandizip 进程");
                }

                // 3. 备份原 version.dll（若存在）
                if (File.Exists(dll))
                {
                    string dllBak = dll + ".bak";
                    if (!File.Exists(dllBak))
                    {
                        File.Copy(dll, dllBak, false);
                        log.Add("[+] 已备份原 version.dll -> " + dllBak);
                    }
                }

                // 4. 复制代理 DLL
                File.Copy(ProxyDllSource, dll, true);
                log.Add("[+] 已部署 version.dll 代理 -> " + dll);

                // 5. 生成 version_patch.ini（自定义授权信息）
                if (!string.IsNullOrEmpty(userName) || !string.IsNullOrEmpty(userEmail))
                {
                    string iniText = BuildIniContent(userName, userEmail, userKey);
                    string iniPath = Path.Combine(dir, IniName);
                    File.WriteAllText(iniPath, iniText, new UTF8Encoding(true)); // 带 BOM UTF-8
                    log.Add("[+] 已写入自定义授权信息 -> " + iniPath);
                    log.Add("    用户: " + (string.IsNullOrEmpty(userName) ? "(默认)" : userName));
                    log.Add("    邮箱: " + (string.IsNullOrEmpty(userEmail) ? "(默认)" : userEmail));
                    if (!string.IsNullOrEmpty(userKey)) log.Add("    密钥: " + userKey);
                }

                log.Add("[✓] DLL 代理部署完成！启动 Bandizip 后将自动激活 Enterprise 版本并显示自定义授权信息。");
                return true;
            }
            catch (UnauthorizedAccessException ex)
            {
                log.Add("[-] 权限不足（需要以管理员身份运行 Seep-Tool）: " + ex.Message);
                return false;
            }
            catch (IOException ex)
            {
                log.Add("[-] 文件被占用，请先关闭 Bandizip: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 生成 version_patch.ini 内容（UTF-8 BOM 编码，\n 转义序列在 DLL 内部解析）
        /// </summary>
        private static string BuildIniContent(string userName, string userEmail, string userKey)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[license]");
            sb.AppendLine("ctrl_id=1319"); // 0x527 = IDC_STATIC_LICENSE
            
            // 组装 text（支持 \n 转义，DLL 内部会自动解析为换行）
            var parts = new List<string>();
            if (!string.IsNullOrEmpty(userName)) parts.Add("授权于：" + userName);
            if (!string.IsNullOrEmpty(userEmail)) parts.Add("邮箱：" + userEmail);
            if (!string.IsNullOrEmpty(userKey)) parts.Add("密钥：" + userKey);
            
            if (parts.Count == 0)
            {
                parts.Add("授权于：AngusDevLab");
                parts.Add("邮箱：angusdevlab@vipuser.com");
                parts.Add("密钥：内部授权");
            }
            
            // 每段之间用 \n 转义（DLL 里会解析为真实换行）
            sb.AppendLine("text=" + string.Join("\\n", parts));
            return sb.ToString();
        }

        /// <summary>
        /// 移除代理 DLL（恢复官方原版）
        /// </summary>
        public static bool RemoveProxy(string dir, IList<string> log)
        {
            string dll = Path.Combine(dir, DllName);
            string ini = Path.Combine(dir, IniName);
            string logFile = Path.Combine(dir, LogName);

            log.Add("=== Bandizip 官方原版彻底还原 ===");
            log.Add("[1] 目标目录: " + dir);

            // 1. 关闭所有可能占用 version.dll 的 Bandizip 相关进程
            KillBandizipProcesses(log);

            bool removed = false;

            // 尝试第一阶段：直接在进程内部执行文件清理与还原
            try
            {
                // 清理文件只读/系统属性
                StripFileAttributes(dll);
                StripFileAttributes(ini);
                StripFileAttributes(logFile);
                string dllBak = dll + ".bak";
                StripFileAttributes(dllBak);

                // 恢复原版 DLL 或删除代理 DLL
                if (File.Exists(dllBak))
                {
                    File.Copy(dllBak, dll, true);
                    File.Delete(dllBak);
                    log.Add("[+] 已从备份恢复原版 version.dll");
                    removed = true;
                }
                else if (File.Exists(dll))
                {
                    var fi = new FileInfo(dll);
                    if (fi.Length < 500000) // 代理 DLL 通常 < 500KB
                    {
                        File.Delete(dll);
                        log.Add("[+] 已删除注入的 version.dll");
                        removed = true;
                    }
                }

                // 恢复可能存在的静态 PE 补丁备份
                string[] exeCandidates = new string[] { "Bandizip.x64.exe", "Bandizip.exe" };
                foreach (var exeName in exeCandidates)
                {
                    string targetExe = Path.Combine(dir, exeName);
                    string targetBak = targetExe + ".bak";
                    if (File.Exists(targetBak))
                    {
                        try
                        {
                            StripFileAttributes(targetExe);
                            File.Copy(targetBak, targetExe, true);
                            File.Delete(targetBak);
                            log.Add("[+] 已从备份恢复原版二进制 -> " + targetExe);
                            removed = true;
                        }
                        catch { }
                    }
                }

                if (File.Exists(ini)) { File.Delete(ini); log.Add("[+] 已删除 version_patch.ini"); }
                if (File.Exists(logFile)) { File.Delete(logFile); log.Add("[+] 已清除运行日志"); }
            }
            catch (Exception ex)
            {
                log.Add("[!] 直接还原遇到权限或句柄锁定: " + ex.Message + "，正在调用系统 UAC 提权强制清理...");
                bool elevatedOk = RunElevatedRemove(dir, log);
                if (elevatedOk)
                {
                    removed = true;
                }
                else
                {
                    log.Add("[-] 提权还原失败，请以管理员身份运行本工具");
                    return false;
                }
            }

            // 再次验证代理 DLL 是否已被彻底清除
            bool stillHasProxy = File.Exists(dll) && new FileInfo(dll).Length < 500000;
            if (stillHasProxy || File.Exists(ini))
            {
                log.Add("[!] 检测到代理文件仍残留，启动强制提权深度清理...");
                RunElevatedRemove(dir, log);
                removed = !File.Exists(ini) && (!File.Exists(dll) || new FileInfo(dll).Length >= 500000);
            }

            log.Add(removed ? "[✓] Bandizip 已彻底还原为官方原版！" : "[=] 未发现代理文件，无需还原");
            return true;
        }

        private static void KillBandizipProcesses(IList<string> log)
        {
            string[] procNames = new string[] { "Bandizip", "Bandizip.x64", "Arkview", "Arkview.x64", "bz", "Updater" };
            foreach (var name in procNames)
            {
                try
                {
                    var procs = Process.GetProcessesByName(name);
                    foreach (var p in procs)
                    {
                        try
                        {
                            p.Kill();
                            p.WaitForExit(2000);
                            log.Add("[*] 已关闭占用进程: " + name);
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        private static void StripFileAttributes(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                }
            }
            catch { }
        }

        private static bool RunElevatedRemove(string dir, IList<string> log)
        {
            try
            {
                string script = @"
$dir = '" + dir.Replace("'", "''") + @"'
$names = @('Bandizip', 'Bandizip.x64', 'Arkview', 'Arkview.x64', 'bz', 'Updater')
Get-Process | Where-Object { $names -contains $_.ProcessName } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

$dll = Join-Path $dir 'version.dll'
$dllBak = Join-Path $dir 'version.dll.bak'
$ini = Join-Path $dir 'version_patch.ini'
$logFile = Join-Path $dir 'version_patch.log'

if (Test-Path $dllBak) {
    Set-ItemProperty $dll -Name Attributes -Value Normal -ErrorAction SilentlyContinue
    Copy-Item $dllBak $dll -Force
    Remove-Item $dllBak -Force
} elseif (Test-Path $dll) {
    $fi = Get-Item $dll
    if ($fi.Length -lt 500000) {
        Set-ItemProperty $dll -Name Attributes -Value Normal -ErrorAction SilentlyContinue
        Remove-Item $dll -Force
    }
}

if (Test-Path $ini) {
    Set-ItemProperty $ini -Name Attributes -Value Normal -ErrorAction SilentlyContinue
    Remove-Item $ini -Force
}
if (Test-Path $logFile) {
    Set-ItemProperty $logFile -Name Attributes -Value Normal -ErrorAction SilentlyContinue
    Remove-Item $logFile -Force
}

$exes = @('Bandizip.x64.exe', 'Bandizip.exe')
foreach ($e in $exes) {
    $p = Join-Path $dir $e
    $pb = $p + '.bak'
    if (Test-Path $pb) {
        Set-ItemProperty $p -Name Attributes -Value Normal -ErrorAction SilentlyContinue
        Copy-Item $pb $p -Force
        Remove-Item $pb -Force
    }
}
";
                string tempPs = Path.Combine(Path.GetTempPath(), "remove_bandizip_proxy.ps1");
                File.WriteAllText(tempPs, script, Encoding.UTF8);

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + tempPs + "\"",
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    UseShellExecute = true
                };

                var p = Process.Start(psi);
                if (p != null) p.WaitForExit();
                try { File.Delete(tempPs); } catch { }

                log.Add("[+] 已通过系统提权成功清理 version.dll 代理与所有配置");
                return true;
            }
            catch (Exception ex)
            {
                log.Add("[-] 提权脚本执行异常: " + ex.Message);
                return false;
            }
        }

        public static readonly Seep.Core.PatchSite[] Sites = new Seep.Core.PatchSite[]
        {
            new PatchSite(0x1317F5,
                "c7 86 20 01 00 00 98 00 00 00",
                "c7 86 20 01 00 00 20 1b 00 00",
                "sub_1401316C0 STD回退分支: 98h(STD) -> 1B20h(Enterprise)"),
            new PatchSite(0x13176D,
                "c7 86 20 01 00 00 d4 03 00 00",
                "c7 86 20 01 00 00 20 1b 00 00",
                "sub_1401316C0 PRO分支: 3D4h(PRO) -> 1B20h(Enterprise)"),
            new PatchSite(0x1347E0,
                "4c 8b dc",
                "31 c0 c3",
                "sub_1401347E0 服务端黑名单核验直通 (xor eax,eax; ret)"),
        };

        // 静态 PE 补丁（备用方案，会破坏 Authenticode 数字签名）
        public static bool PatchStatic(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) exe = Path.Combine(dir, "Bandizip.exe");
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return false; }
            log.Add("[!] 采用静态 PE 补丁（将破坏数字签名，推荐使用 DLL 注入模式）");
            return FilePatcher.PatchInPlace(exe, Sites, log);
        }
    }
}
