// OneClickActivate.cs — Listary 一键离线激活（JavaScriptSerializer 可靠 JSON 解析/序列化）
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web.Script.Serialization; // System.Web.Extensions.dll
using Seep.Core;
using Seep.Modules;

namespace Seep.Modules
{
    public static class OneClickActivate
    {
        public static string ListaryPrefsPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Listary", "UserProfile", "Settings", "Preferences.json");
        }

                public static void RemoveHostsBlock(IList<string> log)
        {
            try
            {
                string hostsPath = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
                if (File.Exists(hostsPath))
                {
                    string content = File.ReadAllText(hostsPath);
                    if (content.Contains("account.listary.com"))
                    {
                        var lines = File.ReadAllLines(hostsPath);
                        var newLines = new List<string>();
                        foreach (var line in lines)
                        {
                            if (!line.Contains("account.listary.com"))
                            {
                                newLines.Add(line);
                            }
                        }

                        try
                        {
                            File.WriteAllLines(hostsPath, newLines.ToArray(), Encoding.ASCII);
                            log.Add("[+] 已成功从 hosts 中移除 account.listary.com 屏蔽项（恢复官方网络连接）");
                        }
                        catch
                        {
                            // 提权写入
                            string tempPs = Path.Combine(Path.GetTempPath(), "remove_hosts.ps1");
                            string psCode = @"$h = ""$env:SystemRoot\System32\drivers\etc\hosts""; (Get-Content $h) | Where-Object { $_ -notmatch 'account\.listary\.com' } | Set-Content $h -Encoding ASCII";
                            File.WriteAllText(tempPs, psCode, Encoding.ASCII);
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
                            log.Add("[+] 已通过提权从 hosts 中移除 account.listary.com 屏蔽项");
                        }
                    }
                    else
                    {
                        log.Add("[=] hosts 中无 account.listary.com 条目，无需清理");
                    }
                }
            }
            catch (Exception ex)
            {
                log.Add("[!] 清理 hosts 异常: " + ex.Message);
            }
        }

public static void EnsureHostsBlock(IList<string> log)
        {
            try
            {
                string hostsPath = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
                if (File.Exists(hostsPath))
                {
                    string content = File.ReadAllText(hostsPath);
                    if (!content.Contains("account.listary.com"))
                    {
                        // 尝试直接追加，如果权限不足则静默忽略或通过提权
                        try
                        {
                            File.AppendAllText(hostsPath, "\r\n# Block Listary license check\r\n127.0.0.1 account.listary.com\r\n");
                            log.Add("[+] 已自动写入 hosts 规则屏蔽 account.listary.com（防回退）");
                        }
                        catch
                        {
                            // 提权写入
                            ProcessStartInfo psi = new ProcessStartInfo
                            {
                                FileName = "powershell.exe",
                                Arguments = "-NoProfile -Command \"Add-Content -Path $env:SystemRoot\\System32\\drivers\\etc\\hosts -Value '`r`n127.0.0.1 account.listary.com' -Encoding ASCII\"",
                                Verb = "runas",
                                WindowStyle = ProcessWindowStyle.Hidden,
                                UseShellExecute = true
                            };
                            Process.Start(psi);
                            log.Add("[+] 已通过提权发起 hosts 防回退规则写入");
                        }
                    }
                    else
                    {
                        log.Add("[=] hosts 已包含 account.listary.com 屏蔽规则（防回退有效）");
                    }
                }
            }
            catch (Exception ex)
            {
                log.Add("[!] 写入 hosts 忽略: " + ex.Message);
            }
        }

        public static bool KillListary(IList<string> log)
        {
            try
            {
                var procs = Process.GetProcessesByName("Listary");
                foreach (var p in procs) { p.Kill(); p.WaitForExit(3000); }
                if (procs.Length > 0) log.Add("[*] 已关闭 Listary 进程 (" + procs.Length + ")");
                System.Threading.Thread.Sleep(800);
                return true;
            }
            catch (Exception ex) { log.Add("[-] 关闭 Listary: " + ex.Message); return false; }
        }

        public static bool StartListary(IList<string> log)
        {
            try
            {
                var dirs = TargetLocator.FindListary();
                if (dirs.Count == 0) { log.Add("[-] 未定位到 Listary.exe"); return false; }
                string exe = Path.Combine(dirs[0], "Listary.exe");
                if (!File.Exists(exe)) { log.Add("[-] 不存在: " + exe); return false; }
                Process.Start(exe);
                log.Add("[+] Listary 已启动");
                return true;
            }
            catch (Exception ex) { log.Add("[-] 启动: " + ex.Message); return false; }
        }

        public static bool ActivateListary(string name, string email, IList<string> log)
        {
            string prefsPath = ListaryPrefsPath();
            log.Add("=== Listary Pro 一键离线激活 ===");
            log.Add("[1] 配置路径: " + prefsPath);

            EnsureHostsBlock(log);
            KillListary(log);

            // 备份
            try
            {
                if (File.Exists(prefsPath))
                {
                    string bak = prefsPath + ".bak";
                    File.Copy(prefsPath, bak, true);
                    log.Add("[2] 已备份 -> " + bak);
                }
                else log.Add("[2] 配置不存在，将新建");
            }
            catch (Exception ex) { log.Add("[-] 备份: " + ex.Message); return false; }

            // 解析 JSON（JavaScriptSerializer）
            Dictionary<string, object> root;
            var serializer = new JavaScriptSerializer();
            try
            {
                if (File.Exists(prefsPath))
                {
                    string json = File.ReadAllText(prefsPath, Encoding.UTF8);
                    if (string.IsNullOrWhiteSpace(json)) json = "{}";
                    root = serializer.Deserialize<Dictionary<string, object>>(json);
                    if (root == null) root = new Dictionary<string, object>();
                    log.Add("[3] 已读取现有配置 (" + json.Length + " 字节)");
                }
                else
                {
                    root = new Dictionary<string, object>();
                    log.Add("[3] 新建配置");
                }
            }
            catch (Exception ex) { log.Add("[-] JSON 解析失败: " + ex.Message); return false; }

            // 生成密钥
            string key;
            try
            {
                key = ListaryModule.Generate(email);
                string ck = ListaryModule.Checksum(email);
                if (key.Substring(160, 19) != ck)
                {
                    log.Add("[-] 算法自检失败");
                    return false;
                }
                log.Add("[4] 密钥生成 (" + key.Length + " 字符) checksum: " + ck);
            }
            catch (Exception ex) { log.Add("[-] 密钥生成: " + ex.Message); return false; }

            // 写入 Settings
            try
            {
                object settingsObj;
                Dictionary<string, object> settings;
                if (!root.TryGetValue("Settings", out settingsObj) || !(settingsObj is Dictionary<string, object>))
                {
                    settings = new Dictionary<string, object>();
                    root["Settings"] = settings;
                }
                else settings = (Dictionary<string, object>)settingsObj;

                settings["Listary5.ProLicense.Name"] = name ?? "Seep User";
                settings["Listary5.ProLicense.Email"] = email ?? "";
                settings["Listary5.ProLicense.Key"] = key;
                settings["LastUpdateTimeV1"] = "0001-01-01T00:00:00";

                string outJson = serializer.Serialize(root);
                string dir = Path.GetDirectoryName(prefsPath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(prefsPath, outJson, new UTF8Encoding(false));
                log.Add("[5] 配置已写入 (" + outJson.Length + " 字节)");
            }
            catch (Exception ex) { log.Add("[-] 写入: " + ex.Message); return false; }

            // 复读校验
            try
            {
                string verifyJson = File.ReadAllText(prefsPath, Encoding.UTF8);
                var verifyRoot = serializer.Deserialize<Dictionary<string, object>>(verifyJson);
                var verifySettings = verifyRoot["Settings"] as Dictionary<string, object>;
                bool ok = verifySettings != null &&
                          (string)verifySettings["Listary5.ProLicense.Key"] == key;
                log.Add("[6] 复读校验: " + (ok ? "PASS" : "FAIL"));
                if (!ok) return false;
            }
            catch (Exception ex) { log.Add("[-] 复读: " + ex.Message); return false; }

            // 重启
            log.Add("[7] 启动 Listary...");
            StartListary(log);
            log.Add("[✓] Listary Pro 离线激活完成！");
            return true;
        }

                /// <summary>
        /// 彻底还原 Listary 到官方原版未激活状态：
        /// 关闭进程 -> 移除 hosts 屏蔽 -> 清理 Preferences.json 授权信息 -> 重启
        /// </summary>
        public static bool RevertListary(IList<string> log)
        {
            string prefsPath = ListaryPrefsPath();
            log.Add("=== Listary Pro 单体彻底还原官方原版 ===");
            log.Add("[1] 配置路径: " + prefsPath);

            // 1. 关闭 Listary
            KillListary(log);

            // 2. 移除 hosts 阻断
            RemoveHostsBlock(log);

            // 3. 彻底清理 Preferences.json 中的授权信息
            try
            {
                if (File.Exists(prefsPath))
                {
                    string json = File.ReadAllText(prefsPath, Encoding.UTF8);
                    if (!string.IsNullOrWhiteSpace(json))
                    {
                        var serializer = new JavaScriptSerializer();
                        var root = serializer.Deserialize<Dictionary<string, object>>(json);
                        if (root != null && root.ContainsKey("Settings"))
                        {
                            var settings = root["Settings"] as Dictionary<string, object>;
                            if (settings != null)
                            {
                                settings.Remove("Listary5.ProLicense.Name");
                                settings.Remove("Listary5.ProLicense.Email");
                                settings.Remove("Listary5.ProLicense.Key");
                                settings.Remove("LastUpdateTimeV1");
                                log.Add("[2] 已彻底清除 Preferences.json 中的所有 ProLicense 授权键值与校验时间戳");
                            }
                        }

                        string outJson = serializer.Serialize(root);
                        File.WriteAllText(prefsPath, outJson, new UTF8Encoding(false));
                        log.Add("[3] 纯净原版配置已写回");
                    }
                }

                // 清理备份文件
                string bak = prefsPath + ".bak";
                if (File.Exists(bak))
                {
                    try { File.Delete(bak); log.Add("[+] 已清理历史备份文件: " + bak); } catch { }
                }
            }
            catch (Exception ex)
            {
                log.Add("[-] 清理配置异常: " + ex.Message);
                return false;
            }

            // 4. 重启 Listary
            log.Add("[4] 重新拉起 Listary 官方程序...");
            StartListary(log);

            log.Add("[✓] Listary 已彻底恢复为官方原版未激活状态！");
            return true;
        }

public static bool ActivateSnipaste(int days, IList<string> log)
        {
            log.Add("=== Snipaste 一键生成激活码 ===");
            try
            {
                string code = SnipasteModule.BuildActivationCode("Seep User", "seep@tool.local", "Personal", days, "", log);
                log.Add("[+] 激活码 (" + code.Length + " 字符) 已自动复制到剪贴板");
                System.Windows.Clipboard.SetText(code);
                log.Add("[i] 请打开 Snipaste → 关于 → 粘贴激活码 → 确认");
                return true;
            }
            catch (Exception ex) { log.Add("[-] 生成: " + ex.Message); return false; }
        }
    }
}
