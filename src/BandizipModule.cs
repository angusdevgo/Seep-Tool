// BandizipModule.cs — Bandizip 客户端离线鉴权补丁模块 (CWE-602)
using System;
using System.Collections.Generic;
using System.IO;
using Seep.Core;

namespace Seep.Modules
{
    public static class BandizipModule
    {
        public const string Name = "Bandizip";
        public const string ExeName = "Bandizip.x64.exe";

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

        public static List<string> Locate() { return TargetLocator.FindBandizip(); }

        public static string CheckState(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) exe = Path.Combine(dir, "Bandizip.exe");
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return "missing"; }
            log.Add("[*] " + exe);
            var st = FilePatcher.CheckFile(exe, Sites, log);
            if (st == FilePatcher.SiteState.Patched) return "patched";
            if (st == FilePatcher.SiteState.Original) return "original";
            return "unknown";
        }

        public static void Check(string dir, IList<string> log)
        {
            CheckState(dir, log);
        }

        public static bool Patch(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) exe = Path.Combine(dir, "Bandizip.exe");
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return false; }
            return FilePatcher.PatchInPlace(exe, Sites, log);
        }

        public static bool Revert(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) exe = Path.Combine(dir, "Bandizip.exe");
            return FilePatcher.Revert(exe, log);
        }
    }
}
