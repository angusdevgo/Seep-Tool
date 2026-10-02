// ============================================================================
//  SeepLab Pattern 03 · 动态库加载顺序缺陷（DLL Search Order Hijacking）
// ============================================================================
//
//  教学样本：演示 CWE-427 的典型形态 —— 裸 LoadLibrary + 缺失加载路径限定。
//
//  ⚠️ 本样本【不加载】任何真实系统 DLL 的劫持版本，
//     只演示「调用点是否存在防护」的判定方法。
//
//  编译：csc /nologo /target:exe /out:SeepLab03.exe Pattern03.cs
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SeepLab
{
    public static class Pattern03
    {
        // ─────────────────────────────────────────────────────────────
        //  P/Invoke 声明（教学用）
        // ─────────────────────────────────────────────────────────────

        /// <summary>★ 缺陷 API：不限定搜索路径的加载（真实产品的常见写法）。</summary>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        /// <summary>✅ 加固 API：限定搜索路径（Windows Vista+）。</summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDefaultDllDirectories(uint directoryFlags);

        /// <summary>✅ 加固 API：绝对路径 + 标志位加载。</summary>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        /// <summary>✅ 加固 API：验证 Authenticode 签名。</summary>
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID, IntPtr pWinTrustData);

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32       = 0x00000800;
        private const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;

        // ─────────────────────────────────────────────────────────────
        //  静态分析：演示「如何判定一个程序是否存在 CWE-427」
        // ─────────────────────────────────────────────────────────────

        /// <summary>
        /// 检查一个可执行文件的导入表，输出 CWE-427 判定结果。
        /// 这是真实的审计方法（非模拟），可直接用于任何 PE 文件。
        /// </summary>
        public static void AuditImportTable(string pePath)
        {
            Console.WriteLine(string.Format("  目标: {0}", Path.GetFileName(pePath)));
            if (!File.Exists(pePath))
            {
                Console.WriteLine("  [-] 文件不存在，跳过");
                return;
            }

            byte[] pe = File.ReadAllBytes(pePath);

            // 方法：在原始字节中搜索特征 API 名的 ASCII 序列。
            // 这是教学化的简化实现；生产审计应使用 dumpbin / pefile。
            bool hasLoadLibrary      = HasImport(pe, "LoadLibrary");
            bool hasSetDefaultDirs   = HasImport(pe, "SetDefaultDllDirectories");
            bool hasLoadLibraryEx    = HasImport(pe, "LoadLibraryEx");
            bool hasWinVerifyTrust   = HasImport(pe, "WinVerifyTrust");

            Console.WriteLine();
            Console.WriteLine("  ── 导入表判定结果 ──");
            Console.WriteLine(string.Format("  LoadLibrary               : {0}", (hasLoadLibrary ? "存在" : "不存在")));
            Console.WriteLine(string.Format("  SetDefaultDllDirectories  : {0}", (hasSetDefaultDirs ? "存在 ✅" : "缺失 ❌")));
            Console.WriteLine(string.Format("  WinVerifyTrust            : {0}", (hasWinVerifyTrust ? "存在 ✅" : "缺失 ❌")));
            Console.WriteLine();

            Console.WriteLine("  ── CWE-427 判定 ──");
            if (hasLoadLibrary && !hasSetDefaultDirs)
                Console.WriteLine("  🔴 高危：存在裸 LoadLibrary 且未限定搜索路径");
            else if (hasLoadLibrary && hasSetDefaultDirs)
                Console.WriteLine("  🟢 已加固：加载路径已限定");
            else
                Console.WriteLine("  ⚪ 未见动态加载调用点");
        }

        /// <summary>ASCII 序列搜索（C# 5 兼容的静态方法）。</summary>
        private static bool HasImport(byte[] pe, string api)
        {
            byte[] b = System.Text.Encoding.ASCII.GetBytes(api);
            for (int i = 0; i <= pe.Length - b.Length; i++)
            {
                int j = 0;
                while (j < b.Length && pe[i + j] == b[j]) j++;
                if (j == b.Length) return true;
            }
            return false;
        }

        /// <summary>靶场入口。</summary>
        public static void Run(string[] args)
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 03 · 动态库加载顺序缺陷    ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            // ── 阶段 1：演示「正确 vs 错误」的调用方式 ──
            Console.WriteLine("【教学 1】加载方式的正确与错误对比");
            Console.WriteLine();
            Console.WriteLine("  ❌ 错误写法（真实产品中最常见）:");
            Console.WriteLine("     HMODULE h = LoadLibraryW(L\"helper.dll\");");
            Console.WriteLine("     → Windows 搜索顺序：应用目录优先 → 可被同目录同名 DLL 劫持");
            Console.WriteLine();
            Console.WriteLine("  ✅ 正确写法（入口点首行必须调用）:");
            Console.WriteLine("     SetDefaultDllDirectories(");
            Console.WriteLine("         LOAD_LIBRARY_SEARCH_SYSTEM32 |");
            Console.WriteLine("         LOAD_LIBRARY_SEARCH_APPLICATION_DIR);");
            Console.WriteLine("     → 只从系统目录 + 应用目录加载，切断搜索顺序劫持");
            Console.WriteLine();

            // ── 阶段 2：真实审计演示 ──
            Console.WriteLine("【教学 2】真实导入表审计（把本程序自己作为样本）");
            string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
            AuditImportTable(self);
            Console.WriteLine();

            // ── 阶段 3：可审计任意 PE ──
            if (args.Length > 0)
            {
                Console.WriteLine(string.Format("【附加审计】目标: {0}", args[0]));
                AuditImportTable(args[0]);
            }
            else
            {
                Console.WriteLine("【提示】可传入任意 PE 路径进行导入表审计：");
                Console.WriteLine("       SeepLab03.exe C:\\Path\\To\\Target.exe");
            }
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • 修复成本：★☆☆ —— 入口点加一行 SetDefaultDllDirectories。");
            Console.WriteLine("  • 但严重性是【代码执行级】，高于大多数授权缺陷本身。");
        }
    }
}
