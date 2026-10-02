// ============================================================================
//  SeepLab Pattern 01 · 单点布尔裁决（Single-Point Boolean Decision）
// ============================================================================
//
//  这是一个【故意植入缺陷】的教学样本。它演示了 CWE-602 最典型的形态：
//  授权判定收敛于「单一、可写、明文」的布尔量，被多处业务逻辑直接读取。
//
//  编译：build.ps1（Windows 自带 csc.exe，零依赖，C# 5 兼容）
// ============================================================================

using System;

namespace SeepLab
{
    public static class Pattern01
    {
        // ─────────────────────────────────────────────────────────────
        //  ★ 缺陷点 DEFECT-01
        //    授权状态：静态、可写、明文、无完整性保护。
        //    它是整个授权体系的「唯一真相源」，也是唯一的攻击面。
        // ─────────────────────────────────────────────────────────────
        public static bool g_license_state = false;

        /// <summary>授权装载：模拟「从本地凭据判定授权」的过程。</summary>
        public static void LoadLicense(string credential)
        {
            Console.WriteLine("── 授权装载流程 ─────────────────────────");

            // ★ 缺陷点 DEFECT-02（附带演示 · Fail-Open）
            if (string.IsNullOrEmpty(credential))
            {
                g_license_state = true;                       // ← 免检通道
                Console.WriteLine("  [!] 凭据为空 → 进入免检分支（Fail-Open）");
                Console.WriteLine("  [+] 授权状态 = 已激活");
                return;
            }

            // ★ 缺陷点 DEFECT-03：本地校验，无服务端参与
            if (credential.Length > 0 && credential.StartsWith("LAB-"))
            {
                g_license_state = true;
                Console.WriteLine("  [+] 本地前缀校验通过 → 授权状态 = 已激活");
            }
            else
            {
                g_license_state = false;
                Console.WriteLine("  [-] 本地校验失败 → 授权状态 = 未激活");
            }
        }

        // ─────────────────────────────────────────────────────────────
        //  以下 3 个方法读取 g_license_state —— 「扩散效应」的来源
        // ─────────────────────────────────────────────────────────────

        /// <summary>业务点 ①：特权功能 A。</summary>
        public static void ProFeatureA()
        {
            if (g_license_state)                              // ← 读取点 #1
                Console.WriteLine("  [PRO-A] 高级功能 A 已解锁：批量导出");
            else
                Console.WriteLine("  [FREE]  高级功能 A 已锁定（需专业版）");
        }

        /// <summary>业务点 ②：特权功能 B。</summary>
        public static void ProFeatureB()
        {
            if (g_license_state)                              // ← 读取点 #2
                Console.WriteLine("  [PRO-B] 高级功能 B 已解锁：离线 OCR");
            else
                Console.WriteLine("  [FREE]  高级功能 B 已锁定（需专业版）");
        }

        /// <summary>业务点 ③：状态展示（对应「关于框 / 标题栏」）。</summary>
        public static void PrintStatus()
        {
            string edition = g_license_state ? "PROFESSIONAL" : "TRIAL";   // ← 读取点 #3
            Console.WriteLine("  [UI]    当前版本 = " + edition + " Edition");
        }

        /// <summary>靶场入口。</summary>
        public static void Run()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 01 · 单点布尔裁决          ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            Console.WriteLine("【阶段 1】初始状态（未激活）");
            PrintStatus();
            ProFeatureA();
            ProFeatureB();
            Console.WriteLine();

            Console.WriteLine("【阶段 2】正常激活路径（凭据 'LAB-KEY-001'）");
            LoadLicense("LAB-KEY-001");
            PrintStatus();
            ProFeatureA();
            ProFeatureB();
            Console.WriteLine();

            Console.WriteLine("【阶段 3】Fail-Open 免检通道（凭据为空字符串）");
            LoadLicense("");
            PrintStatus();
            ProFeatureA();
            ProFeatureB();
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • g_license_state 被修改 1 次，3 处业务点同时变化 —— 这就是「扩散效应」。");
            Console.WriteLine("  • 攻击者只需改写这 1 个变量，无需触碰任何业务逻辑。");
            Console.WriteLine("  • 防御：取消静态可写状态，改为「凭据驱动 + 每次重新验签」。");
        }
    }
}
