// TargetLocator.cs — 高性能毫秒级目录定位（进程嗅探 + 注册表快速查找 + 指定精准目录）
// 彻底移除阻塞式递归遍历，确保 0-10ms 极速响应！
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace Seep.Core
{
    public static class TargetLocator
    {
        // 1. 运行中进程内存嗅探（毫秒级，便携版最强识别方式）
        public static List<string> FindRunningProcessDir(string processName, string exeName)
        {
            var found = new List<string>();
            try
            {
                var procs = Process.GetProcessesByName(processName);
                foreach (var p in procs)
                {
                    try
                    {
                        var path = p.MainModule.FileName;
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            var dir = Path.GetDirectoryName(path);
                            if (File.Exists(Path.Combine(dir, exeName)))
                                found.Add(Norm(dir));
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return Dedup(found);
        }

        // 2. 注册表快速定位（毫秒级）
        public static List<string> FindByDisplayName(string keyword, string exeName)
        {
            var found = new List<string>();
            string[] roots = new string[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };
            RegistryKey[] hives = new RegistryKey[] { Registry.LocalMachine, Registry.CurrentUser };
            foreach (var hive in hives)
            {
                foreach (var root in roots)
                {
                    try
                    {
                        using (var k = hive.OpenSubKey(root))
                        {
                            if (k == null) continue;
                            foreach (var sub in k.GetSubKeyNames())
                            {
                                try
                                {
                                    using (var sk = k.OpenSubKey(sub))
                                    {
                                        if (sk == null) continue;
                                        var name = sk.GetValue("DisplayName") as string;
                                        if (name == null || name.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) < 0) continue;
                                        var loc = sk.GetValue("InstallLocation") as string;
                                        if (!string.IsNullOrEmpty(loc) && File.Exists(Path.Combine(loc, exeName)))
                                            found.Add(Norm(loc));
                                        var dispIcon = sk.GetValue("DisplayIcon") as string;
                                        if (!string.IsNullOrEmpty(dispIcon))
                                        {
                                            var iconPath = dispIcon.Split(',')[0].Trim('"');
                                            var dir = Path.GetDirectoryName(iconPath);
                                            if (!string.IsNullOrEmpty(dir) && File.Exists(Path.Combine(dir, exeName)))
                                                found.Add(Norm(dir));
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            return Dedup(found);
        }

        // 3. 高频精准静态路径直查（仅限 1 层目录，绝不递归遍历全盘）
        public static List<string> CheckKnownDirs(string[] specificDirs, string exeName)
        {
            var found = new List<string>();
            foreach (var dir in specificDirs)
            {
                try
                {
                    if (Directory.Exists(dir) && File.Exists(Path.Combine(dir, exeName)))
                    {
                        found.Add(Norm(dir));
                    }
                }
                catch { }
            }
            return Dedup(found);
        }

        // Bandizip
        public static List<string> FindBandizip()
        {
            var found = new List<string>();
            found.AddRange(FindRunningProcessDir("Bandizip", "Bandizip.exe"));
            found.AddRange(FindRunningProcessDir("Bandizip", "Bandizip.x64.exe"));
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Bandizip"))
                {
                    if (k != null)
                    {
                        var p = k.GetValue("ProgramPath") as string;
                        if (!string.IsNullOrEmpty(p) && File.Exists(p)) found.Add(Norm(Path.GetDirectoryName(p)));
                    }
                }
            }
            catch { }
            found.AddRange(FindByDisplayName("Bandizip", "Bandizip.exe"));
            string[] known = new string[]
            {
                @"C:\Program Files\Bandizip",
                @"C:\Program Files (x86)\Bandizip",
                @"D:\Data\Bandzip",
                @"D:\Data\Bandizip"
            };
            found.AddRange(CheckKnownDirs(known, "Bandizip.x64.exe"));
            found.AddRange(CheckKnownDirs(known, "Bandizip.exe"));
            // paths.json 用户自定义路径兜底
            foreach (var cp in CustomPaths.Get("bandizip"))
                if (File.Exists(Path.Combine(cp, "Bandizip.x64.exe")) || File.Exists(Path.Combine(cp, "Bandizip.exe")))
                    found.Add(Norm(cp));
            return Dedup(found);
        }

        // Seer
        public static List<string> FindSeer()
        {
            var found = new List<string>();
            found.AddRange(FindRunningProcessDir("Seer", "Seer.exe"));
            found.AddRange(FindByDisplayName("Seer", "Seer.exe"));
            string[] known = new string[]
            {
                @"D:\Data\Seer",
                @"C:\Program Files\Seer",
                @"C:\Program Files (x86)\Seer",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Seer")
            };
            found.AddRange(CheckKnownDirs(known, "Seer.exe"));
            // paths.json 用户自定义路径兜底
            foreach (var cp in CustomPaths.Get("seer"))
                if (File.Exists(Path.Combine(cp, "Seer.exe"))) found.Add(Norm(cp));
            return Dedup(found);
        }

        // Snipaste (进程内存嗅探 + 常用解压下载精准路径直达)
        public static List<string> FindSnipaste()
        {
            var found = new List<string>();
            found.AddRange(FindRunningProcessDir("Snipaste", "Snipaste.exe"));
            found.AddRange(FindByDisplayName("Snipaste", "Snipaste.exe"));
            string[] known = new string[]
            {
                @"D:\IDM\压缩包\Snipaste-2.11.3-x64",
                @"D:\IDM\压缩\Snipaste-2.11.3-x64",
                @"D:\Data\Snipaste",
                @"D:\Tool\Snipaste",
                @"C:\Program Files\Snipaste",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Snipaste")
            };
            found.AddRange(CheckKnownDirs(known, "Snipaste.exe"));
            // paths.json 用户自定义路径兜底
            foreach (var cp in CustomPaths.Get("snipaste"))
                if (File.Exists(Path.Combine(cp, "Snipaste.exe"))) found.Add(Norm(cp));
            return Dedup(found);
        }

        // Uninstall Tool
        public static List<string> FindUninstallTool()
        {
            var found = new List<string>();
            found.AddRange(FindRunningProcessDir("UninstallTool", "UninstallTool.exe"));
            found.AddRange(FindByDisplayName("Uninstall Tool", "UninstallTool.exe"));
            string[] known = new string[]
            {
                @"D:\Data\Uninstall Tool",
                @"C:\Program Files\Uninstall Tool",
                @"C:\Program Files (x86)\Uninstall Tool"
            };
            found.AddRange(CheckKnownDirs(known, "UninstallTool.exe"));
            return Dedup(found);
        }

        // Listary
        public static List<string> FindListary()
        {
            var found = new List<string>();
            found.AddRange(FindRunningProcessDir("Listary", "Listary.exe"));
            found.AddRange(FindByDisplayName("Listary", "Listary.exe"));
            string[] known = new string[]
            {
                @"D:\Data\Listary",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Listary"),
                @"C:\Program Files\Listary"
            };
            found.AddRange(CheckKnownDirs(known, "Listary.exe"));
            // paths.json 用户自定义路径兜底
            foreach (var cp in CustomPaths.Get("listary"))
                if (File.Exists(Path.Combine(cp, "Listary.exe"))) found.Add(Norm(cp));
            return Dedup(found);
        }

        static string Norm(string p) { return Path.GetFullPath(p).TrimEnd('\\'); }

        static List<string> Dedup(List<string> input)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var output = new List<string>();
            foreach (var p in input)
            {
                var n = Norm(p);
                if (seen.Add(n)) output.Add(n);
            }
            return output;
        }
    }
}
