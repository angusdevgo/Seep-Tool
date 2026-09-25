// SeerModule.cs — Seer 深度鉴权修补与单体独立还原模块
using System;
using System.Collections.Generic;
using Seep.Core;
using System.IO;

namespace Seep.Modules
{
    public static class SeerModule
    {
        public const string Name = "Seer";
        public const string ExeName = "Seer.exe";

        public static readonly byte[] PATCH_IS_LICENSED = PeUtil.HexToBytes("b0 01 c3 90 90");
        public static readonly byte[] PATCH_POPUP_WRAPPER = PeUtil.HexToBytes("31 c0 c3 90 90");

        public static readonly byte[] PROLOGUE_LICENSED = PeUtil.HexToBytes("48 89 4c 24 08");
        public static readonly byte[] PROLOGUE_POPUP = PeUtil.HexToBytes("88 54 24 10 48");

        public static readonly Dictionary<string, long[]> KnownBuilds = new Dictionary<string, long[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "e78ceac28ff7a006c015d4cbdadc6ad1abeacc412beb6642e2f8ce6334eaa63c", new long[] { 0x496C10, 0x495B70 } },
            { "8676e078e42ef314e3ed85934ab897cfad0da8dc8f22bd0310da46a3855b3241", new long[] { 0xB82D10, 0 } }
        };

        public static List<string> Locate() { return TargetLocator.FindSeer(); }

        public static string DetectState(byte[] data)
        {
            string sha = PeUtil.Sha256Hex(data);
            if (KnownBuilds.ContainsKey(sha))
            {
                long[] offsets = KnownBuilds[sha];
                bool p1 = PeUtil.BytesAt(data, offsets[0], PATCH_IS_LICENSED);
                bool p2 = offsets[1] == 0 || PeUtil.BytesAt(data, offsets[1], PATCH_POPUP_WRAPPER);
                if (p1 && p2) return "patched";
                return "original";
            }

            if (PeUtil.BytesAt(data, 0x496C10, PATCH_IS_LICENSED) && PeUtil.BytesAt(data, 0x495B70, PATCH_POPUP_WRAPPER))
                return "patched";

            return "unknown";
        }

        public static string Status(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return "missing"; }
            byte[] data = File.ReadAllBytes(exe);
            string st = DetectState(data);
            if (st == "patched") log.Add("[+] 状态: 已完全激活 (无弹窗 + isLicensed恒真)");
            else if (st == "original") log.Add("[*] 状态: 原版/未完全修补");
            else log.Add("[?] 状态: 未知版本");
            return st;
        }

        public static void Check(string dir, IList<string> log)
        {
            Status(dir, log);
        }

        public static bool Patch(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return false; }
            log.Add("[*] 目标: " + exe);
            try
            {
                byte[] data = File.ReadAllBytes(exe);
                string sha = PeUtil.Sha256Hex(data);
                log.Add("[*] 当前 SHA256: " + sha);

                long offLicensed = 0x496C10;
                long offPopup = 0x495B70;

                if (KnownBuilds.ContainsKey(sha))
                {
                    offLicensed = KnownBuilds[sha][0];
                    offPopup = KnownBuilds[sha][1];
                }

                string bak = exe + ".bak";
                if (!File.Exists(bak))
                {
                    File.Copy(exe, bak, false);
                    log.Add("[+] 已自动创建备份: " + bak);
                }

                Array.Copy(PATCH_IS_LICENSED, 0, data, offLicensed, PATCH_IS_LICENSED.Length);
                log.Add(string.Format("[+] 应用 isLicensed 补丁 @ 0x{0:X} -> mov al, 1; ret", offLicensed));

                if (offPopup > 0)
                {
                    Array.Copy(PATCH_POPUP_WRAPPER, 0, data, offPopup, PATCH_POPUP_WRAPPER.Length);
                    log.Add(string.Format("[+] 应用 弹窗拦截 补丁 @ 0x{0:X} -> xor eax, eax; ret", offPopup));
                }

                File.WriteAllBytes(exe, data);

                byte[] verify = File.ReadAllBytes(exe);
                bool ok1 = PeUtil.BytesAt(verify, offLicensed, PATCH_IS_LICENSED);
                bool ok2 = offPopup == 0 || PeUtil.BytesAt(verify, offPopup, PATCH_POPUP_WRAPPER);

                if (ok1 && ok2)
                {
                    log.Add("[✓] 双重决策分支走查修补成功！已彻底消除 7 天倒计时与激活弹窗。");
                    return true;
                }
                else
                {
                    log.Add("[-] 复读校验未完全通过！");
                    return false;
                }
            }
            catch (IOException ex)
            {
                log.Add("[-] 文件被占用，请先退出 Seer: " + ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                log.Add("[-] 修补异常: " + ex.Message);
                return false;
            }
        }

        // 单独一键还原官方原版
        public static bool Revert(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            string bak = exe + ".bak";
            if (!File.Exists(bak))
            {
                log.Add("[-] 未找到备份文件: " + bak);
                return false;
            }
            try
            {
                File.Copy(bak, exe, true);
                log.Add("[✓] 已成功从备份文件还原 Seer 原版 -> " + exe);
                return true;
            }
            catch (IOException ex)
            {
                log.Add("[-] 还原失败: 程序可能正在运行，请先在任务栏右下角退出 Seer: " + ex.Message);
                return false;
            }
        }
    }
}
