// SnipasteModule.cs — Snipaste 2.11.3 PRO 1:1 INT0 参考实现 (自动一键激活/公钥替换+持久化免填码)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Seep.Core;

namespace Seep.Modules
{
    public static class SnipasteModule
    {
        public const string Name = "Snipaste";
        public const string ExeName = "Snipaste.exe";

        public static readonly byte[] OfficialPubkey =
            PeUtil.HexToBytes("86a6313855512c692b7f44a7041a86d02890544923714acaeeb29e52883c9060");

        public static string KeypairPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keypair.bin");

        public static bool HasKeypair()
        {
            try
            {
                if (!File.Exists(KeypairPath))
                {
                    byte[] kpBytes = Seep.Core.EmbeddedAssets.GetSnipasteKeypairBytes();
                    File.WriteAllBytes(KeypairPath, kpBytes);
                }
                return true;
            }
            catch
            {
                return true;
            }
        }

        public static List<string> Locate()
        {
            return TargetLocator.FindSnipaste();
        }

        public const long PubkeyPatchFirstOffset = 0x2493C8;
        public static readonly long[] PersistOffsets = new long[] { 0x245A14, 0x245ADA, 0x245B12, 0x245B22 };

        public static string CheckState(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return "missing"; }
            log.Add("[*] " + exe);
            try
            {
                byte[] d = File.ReadAllBytes(exe);

                // 1. 校验公钥是否已替换
                byte[] officialHead = PeUtil.HexToBytes("02 d6 05 06");
                long off1 = PubkeyPatchFirstOffset;
                bool isOfficial = (d[off1] == officialHead[0] && d[off1 + 1] == officialHead[1]
                                && d[off1 + 2] == officialHead[2] && d[off1 + 3] == officialHead[3]);
                bool pubkeyPatched = !isOfficial;

                // 2. 校验持久化（免填码启动即 Pro）
                int persistCount = 0;
                foreach (long rva in PersistOffsets)
                {
                    long off = rva - 0xC00 + 2;
                    if (off + 4 <= d.Length && d[off] == 0 && d[off + 1] == 0 && d[off + 2] == 0 && d[off + 3] == 0)
                        persistCount++;
                }

                if (pubkeyPatched && persistCount == PersistOffsets.Length)
                {
                    log.Add("[+] Snipaste 已完全激活 (公钥替换 + 持久化免填码 Pro 4/4 全部生效)");
                    return "patched";
                }
                else if (pubkeyPatched)
                {
                    log.Add("[*] 公钥已替换但尚未启用持久化，点击一键激活可立即固化为专业版");
                    return "original";
                }
                else
                {
                    log.Add("[*] Snipaste 为官方原版（点击一键激活自动注入专业版）");
                    return "original";
                }
            }
            catch (Exception ex)
            {
                log.Add("[-] 检测异常: " + ex.Message);
                return "unknown";
            }
        }

        public static bool Patch(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return false; }
            log.Add("=== Snipaste 一键极速免激活码写入专业版 ===");

            try
            {
                // 关闭运行中的 Snipaste
                var procs = Process.GetProcessesByName("Snipaste");
                foreach (var p in procs)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }

                string bak = exe + ".official.bak";
                if (!File.Exists(bak))
                {
                    string orig = exe + ".orig";
                    if (File.Exists(orig)) File.Copy(orig, bak, false);
                    else File.Copy(exe, bak, false);
                    log.Add("[+] 已创建官方原版备份: " + bak);
                }

                // 调用 Python 脚本完成公钥替换 + 4 处持久化打桩
                string pyScript = string.Format(@"
import sys, os
sys.path.insert(0, r'{0}\..\Snipaste\src')
from keygen import algo

target = r'{1}'
bak = r'{2}'
kp_path = r'{0}\keypair.bin'
if not os.path.exists(kp_path):
    kp_path = r'{0}\..\Snipaste\tools\keypair.bin'

data = open(bak, 'rb').read()
kp = open(kp_path, 'rb').read()
pub = kp[32:]

out = algo.patch_public_key(data, pub)
out = algo.patch_persist(out, enable=True)

tmp = target + '.tmp'
open(tmp, 'wb').write(out)
os.replace(tmp, target)
print('SUCCESS')
", AppDomain.CurrentDomain.BaseDirectory, exe, bak);

                var psi = new ProcessStartInfo
                {
                    FileName = "python",
                    Arguments = "-c \"" + pyScript.Replace("\"", "\\\"") + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string stdout = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(8000);
                    if (!stdout.Contains("SUCCESS"))
                        throw new InvalidOperationException("Python 补丁执行异常: " + stdout);
                }

                log.Add("[+] 1:1 对齐原项目 INT0 规范：已替换公钥 + 固化 4 处启动即 Pro 判定！");
                log.Add("[+] 完全无需手动复制和粘贴激活码，开箱即是永久专业版！");

                Process.Start(exe);
                log.Add("[✓] Snipaste 已重新启动，专业版已永久生效！");
                return true;
            }
            catch (Exception ex)
            {
                log.Add("[-] 执行异常: " + ex.Message);
                return false;
            }
        }

        public static bool Revert(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            string bak = exe + ".official.bak";
            if (!File.Exists(bak))
                bak = exe + ".orig";

            if (!File.Exists(bak))
            {
                log.Add("[-] 未找到原版备份文件: " + bak);
                return false;
            }
            try
            {
                var procs = Process.GetProcessesByName("Snipaste");
                foreach (var p in procs)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }

                File.Copy(bak, exe, true);
                log.Add("[✓] 已成功从备份还原官方原版 -> " + exe);
                Process.Start(exe);
                return true;
            }
            catch (Exception ex)
            {
                log.Add("[-] 还原失败: " + ex.Message);
                return false;
            }
        }

        public static string BuildActivationCode(string name, string email, string plan, int days, string dom, IList<string> log)
        {
            string script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "snipaste_keygen.py");
            if (!File.Exists(script))
                throw new InvalidOperationException("缺少算号桥: " + script);

            var psi = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = "\"" + script + "\" " + days,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                p.WaitForExit(8000);
                if (stdout.Contains("\"ok\": true") && stdout.Contains("\"code\": \""))
                {
                    int s = stdout.IndexOf("\"code\": \"") + 9;
                    int e = stdout.IndexOf("\"", s);
                    string code = stdout.Substring(s, e - s);
                    return code;
                }
                else
                {
                    throw new InvalidOperationException("算号脚本异常: " + stdout);
                }
            }
        }
    }
}
