// ============================================================================
//  SeepLab · 教学靶场主入口
// ============================================================================
//
//  用法：
//    SeepLab.exe              → 列出全部模式
//    SeepLab.exe 01           → 运行模式 01（单点布尔裁决）
//    SeepLab.exe 03           → 运行模式 03（动态库加载顺序缺陷）
//    SeepLab.exe 03 <PE路径>   → 对任意 PE 做导入表审计
//    SeepLab.exe all          → 依次运行全部模式
//
//  编译：build.ps1（自动调用 Windows 自带 csc.exe，零依赖）
// ============================================================================

using System;
using System.Linq;

namespace SeepLab
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            if (args.Length == 0)
            {
                PrintMenu();
                return;
            }

            string key = args[0].Trim().ToLowerInvariant();
            string[] rest = args.Skip(1).ToArray();

            switch (key)
            {
                case "01": Pattern01.Run(); break;
                case "02": Pattern02.Run(); break;
                case "03": Pattern03.Run(rest); break;
                case "04": Pattern04.Run(); break;
                case "05": Pattern05.Run(); break;
                case "07": Pattern07.Run(); break;

                case "all":
                    Pattern01.Run(); Console.WriteLine(); Console.WriteLine();
                    Pattern02.Run(); Console.WriteLine(); Console.WriteLine();
                    Pattern04.Run(); Console.WriteLine(); Console.WriteLine();
                    Pattern05.Run(); Console.WriteLine(); Console.WriteLine();
                    Pattern07.Run();
                    break;

                case "help":
                case "-h":
                case "/?":
                    PrintMenu();
                    break;

                default:
                    Console.WriteLine(string.Format("[-] 未知模式: {0}", key));
                    PrintMenu();
                    break;
            }
        }

        private static void PrintMenu()
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════╗");
            Console.WriteLine("║   SeepLab · CWE-602 教学靶场                          ║");
            Console.WriteLine("║   客户端鉴权脆弱性 · 缺陷模式演示                      ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════╝");
            Console.WriteLine();
            Console.WriteLine("  用法: SeepLab.exe <模式编号>");
            Console.WriteLine();
            Console.WriteLine("  ┌──────┬────────────────────────────────┬──────────┐");
            Console.WriteLine("  │ 编号 │ 模式名称                        │ 关联 CWE  │");
            Console.WriteLine("  ├──────┼────────────────────────────────┼──────────┤");
            Console.WriteLine("  │  01  │ 单点布尔裁决                    │ CWE-602  │");
            Console.WriteLine("  │  02  │ 硬编码密钥材料                  │ CWE-321  │");
            Console.WriteLine("  │  03  │ 动态库加载顺序缺陷              │ CWE-427  │");
            Console.WriteLine("  │  04  │ 可写全局状态变量                │ CWE-602  │");
            Console.WriteLine("  │  05  │ 明文进程间通信                  │ CWE-311  │");
            Console.WriteLine("  │  07  │ 空值短路校验 (Fail-Open)        │ CWE-287  │");
            Console.WriteLine("  └──────┴────────────────────────────────┴──────────┘");
            Console.WriteLine();
            Console.WriteLine("  附加用法:");
            Console.WriteLine("    SeepLab.exe all            依次运行全部模式");
            Console.WriteLine("    SeepLab.exe 03 <PE路径>     对任意 PE 做导入表审计");
            Console.WriteLine();
            Console.WriteLine("  ⚠️  本程序仅用于安全教学与防御加固演练。");
        }
    }
}
