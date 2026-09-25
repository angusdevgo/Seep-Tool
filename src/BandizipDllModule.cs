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

            try
            {
                // 关闭运行中的 Bandizip
                var procs = Process.GetProcessesByName("Bandizip");
                foreach (var p in procs)
                {
                    try { p.Kill(); p.WaitForExit(3000); }
                    catch { }
                }

                bool removed = false;

                // 恢复原版 DLL 或删除代理 DLL
                string dllBak = dll + ".bak";
                if (File.Exists(dllBak))
                {
                    File.Copy(dllBak, dll, true);
                    File.Delete(dllBak);
                    log.Add("[+] 已从备份恢复原版 version.dll");
                    removed = true;
                }
                else if (File.Exists(dll))
                {
                    // 检查是否是我们的代理（通过大小判断）
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

                log.Add(removed ? "[✓] Bandizip 已彻底还原为官方原版！" : "[=] 未发现代理文件，无需还原");
                return true;
            }
            catch (Exception ex)
            {
                log.Add("[-] 移除失败: " + ex.Message);
                return false;
            }
        }

        // 保留静态 PE 补丁作为备用方案
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
