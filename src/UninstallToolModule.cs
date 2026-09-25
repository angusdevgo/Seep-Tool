// UninstallToolModule.cs — Geek Uninstaller PRO / Uninstall Tool 补丁与单体还原模块
using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using Seep.Core;

namespace Seep.Modules
{
    public static class UninstallToolModule
    {
        public const string Name = "Uninstall Tool";
        public const string ExeName = "UninstallTool.exe";

        public const long STUB_VA = 0x140001622L;
        public static readonly byte[] STUB_BYTES = new byte[] { 0xB8, 0x03, 0x00, 0x00, 0x00, 0xC3 }; // mov eax,3; ret
        public const long CALL_VA = 0x140009E0FL;
        public const long ORIG_TARGET_VA = 0x1402DE8C8L;

        public static List<string> Locate() { return TargetLocator.FindUninstallTool(); }

        public static int ApplyToPe(byte[] pe, IList<string> log)
        {
            long stubOff, callOff;
            if (!PeUtil.VaToOffset(pe, STUB_VA, out stubOff))
            {
                log.Add("[-] stub VA 0x" + STUB_VA.ToString("x") + " 不在节内");
                return -1;
            }
            if (!PeUtil.VaToOffset(pe, CALL_VA, out callOff))
            {
                log.Add("[-] call VA 0x" + CALL_VA.ToString("x") + " 不在节内");
                return -1;
            }
            if (pe[callOff] == 0xE8)
            {
                int rel = BitConverter.ToInt32(pe, (int)callOff + 1);
                long target = (CALL_VA + 5 + rel) & 0xFFFFFFFFFFFFL;
                if (target == STUB_VA)
                {
                    log.Add("[=] 已处于补丁状态（call 已指向 IsRegistered stub）");
                    return 0;
                }
                if (target != ORIG_TARGET_VA)
                {
                    log.Add("[-] call 原始目标不符: 0x" + target.ToString("x") + " (期望 0x" + ORIG_TARGET_VA.ToString("x") + ")");
                    return -1;
                }
            }
            else
            {
                log.Add("[-] call 指令校验失败（非 E8）");
                return -1;
            }
            Array.Copy(STUB_BYTES, 0, pe, stubOff, STUB_BYTES.Length);
            int newRel = unchecked((int)((STUB_VA - (CALL_VA + 5)) & 0xFFFFFFFFL));
            byte[] newCall = new byte[5];
            newCall[0] = 0xE8;
            Array.Copy(BitConverter.GetBytes(newRel), 0, newCall, 1, 4);
            Array.Copy(newCall, 0, pe, callOff, 5);
            log.Add("[+] stub 写入: VA 0x" + STUB_VA.ToString("x") + " -> mov eax,3; ret");
            log.Add("[+] call 重定向: VA 0x" + CALL_VA.ToString("x") + " -> stub");
            return 2;
        }

        public static string CheckState(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return "missing"; }
            log.Add("[*] " + exe);
            try
            {
                byte[] pe = File.ReadAllBytes(exe);
                long callOff;
                if (PeUtil.VaToOffset(pe, CALL_VA, out callOff) && pe[callOff] == 0xE8)
                {
                    int rel = BitConverter.ToInt32(pe, (int)callOff + 1);
                    long target = (CALL_VA + 5 + rel) & 0xFFFFFFFFFFFFL;
                    if (target == STUB_VA)
                    {
                        log.Add("[+] 状态: 已补丁 (IsRegistered 恒 3)");
                        return "patched";
                    }
                    else
                    {
                        log.Add("[*] 状态: 原版");
                        return "original";
                    }
                }
                else
                {
                    log.Add("[!] 状态: 未知结构");
                    return "unknown";
                }
            }
            catch (Exception ex)
            {
                log.Add("[-] " + ex.Message);
                return "unknown";
            }
        }

        public static void Check(string dir, IList<string> log)
        {
            CheckState(dir, log);
        }

        public static bool Patch(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return false; }
            try
            {
                byte[] pe = File.ReadAllBytes(exe);
                log.Add("[*] " + exe + "  SHA256: " + PeUtil.Sha256Hex(pe));
                int changes = ApplyToPe(pe, log);
                if (changes < 0) return false;
                if (changes == 0) return true;
                
                string bak = Path.ChangeExtension(exe, ".orig.exe");
                if (!File.Exists(bak)) { File.Copy(exe, bak, false); log.Add("[+] 已自动创建备份 -> " + bak); }
                
                File.WriteAllBytes(exe, pe);
                byte[] verify = File.ReadAllBytes(exe);
                long callOff;
                PeUtil.VaToOffset(verify, CALL_VA, out callOff);
                int rel = BitConverter.ToInt32(verify, (int)callOff + 1);
                bool ok = ((CALL_VA + 5 + rel) & 0xFFFFFFFFFFFFL) == STUB_VA;
                log.Add(ok ? "[+] 写回并校验通过：IsRegistered 判定恒 3" : "[-] 复读校验失败");
                return ok;
            }
            catch (IOException ex)
            {
                log.Add("[-] 文件被占用（请先退出 Uninstall Tool）: " + ex.Message);
                return false;
            }
        }

        public static bool Revert(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            string bak = Path.ChangeExtension(exe, ".orig.exe");
            if (!File.Exists(bak))
                bak = exe + ".bak";

            if (!File.Exists(bak))
            {
                log.Add("[-] 未找到原版备份文件: " + bak);
                return false;
            }

            try
            {
                File.Copy(bak, exe, true);
                log.Add("[✓] 已单独成功从备份还原原版 -> " + exe);
                ClearRegistration(log);
                return true;
            }
            catch (IOException ex)
            {
                log.Add("[-] 还原失败: 程序可能正在运行，请先退出: " + ex.Message);
                return false;
            }
        }

        const string REG_KEY = @"Software\CrystalIdea Software\Uninstall Tool";

        public static void WriteRegistration(string name, string code, IList<string> log)
        {
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(REG_KEY))
                {
                    k.SetValue("RN", name, RegistryValueKind.String);
                    k.SetValue("RC", code, RegistryValueKind.String);
                }
                log.Add("[+] 已写入 HKCU\\" + REG_KEY);
            }
            catch (Exception ex) { log.Add("[-] 注册表写入失败: " + ex.Message); }
        }

        public static void ClearRegistration(IList<string> log)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(REG_KEY, true))
                {
                    if (k != null)
                    {
                        k.DeleteValue("RN", false);
                        k.DeleteValue("RC", false);
                        log.Add("[+] 已清理注册表授权登记项 (RN/RC)");
                    }
                }
            }
            catch { }
        }
    }
}
