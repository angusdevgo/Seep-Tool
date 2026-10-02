// ============================================================================
//  SeepLab Pattern 07 · 空值短路校验（Fail-Open）
// ============================================================================
//
//  教学样本：演示鉴权分支中最危险的反模式 —— 把「无法判定」当作「判定通过」。
//
//  触发条件：仅需一份【空配置】。无需代码修改、无需逆向。
//  流量表现：客户端完全不发请求 → 服务端风控零感知。
//
//  编译：build.ps1（Windows 自带 csc.exe，零依赖，C# 5 兼容）
// ============================================================================

using System;
using System.IO;

namespace SeepLab
{
    /// <summary>模拟「授权凭据」的数据来源（注册表 / 配置文件 / 环境变量）。</summary>
    public static class FakeCredentialStore
    {
        /// <summary>模拟从配置读取的原始字符串（null = 不存在）。</summary>
        public static string Raw = null;

        /// <summary>模拟配置文件加载：try { } catch { } 的典型后果。</summary>
        public static void LoadFromConfig(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    Console.WriteLine("  [!] 配置文件不存在: " + path);
                    Raw = null;                            // ← 未捕获的失败路径
                    return;
                }
                Raw = File.ReadAllText(path).Trim();
            }
            catch
            {
                Console.WriteLine("  [!] 配置读取异常（已被空 catch 吞掉）");
                Raw = null;                                // ← 静默失败
            }
        }
    }

    public static class Pattern07
    {
        // ─────────────────────────────────────────────────────────────
        //  ★ 缺陷点：Fail-Open 鉴权语义
        //
        //  把三种完全不同的状态混为一谈：
        //      (a) 凭据合法        → 应放行
        //      (b) 凭据不合法      → 应拒绝
        //      (c) 凭据【缺失】    → 应拒绝（但这里放行了！）
        // ─────────────────────────────────────────────────────────────
        public static bool IsAuthorized(out string reason)
        {
            string raw = FakeCredentialStore.Raw;

            // ★★★ 缺陷本体：凭据为空 = 无需校验 = 通过（Fail-Open）
            if (string.IsNullOrWhiteSpace(raw))
            {
                reason = "凭据缺失，视为未配置授权（放行）";
                return true;                               // ← 免检通道
            }

            // 字面量 "null" / "0" 也常被错误处理
            if (raw == "null" || raw == "0")
            {
                reason = "凭据为占位值，视为未配置授权（放行）";
                return true;                               // ← 免检通道
            }

            // 正常路径：本地校验（无服务端）
            if (raw.StartsWith("LAB-") && raw.Length >= 8)
            {
                reason = "本地校验通过";
                return true;
            }

            reason = "本地校验失败";
            return false;
        }

        /// <summary>对照组：正确的 Fail-Closed 实现（教学用，供对比）。</summary>
        public static bool IsAuthorized_FailClosed(out string reason)
        {
            string raw = FakeCredentialStore.Raw;

            // ✅ 正确实现：任何「无法确认有效」的情况一律拒绝
            if (string.IsNullOrWhiteSpace(raw) || raw == "null" || raw == "0")
            {
                reason = "凭据缺失或为占位值 → 拒绝（Fail-Closed）";
                return false;
            }
            if (raw.StartsWith("LAB-") && raw.Length >= 8)
            {
                reason = "本地校验通过";
                return true;
            }
            reason = "本地校验失败 → 拒绝";
            return false;
        }

        /// <summary>靶场入口。</summary>
        public static void Run()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 07 · 空值短路校验          ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            string r, rc;

            Console.WriteLine("【阶段 1】干净环境（无配置文件）");
            FakeCredentialStore.LoadFromConfig("nonexistent.lic");
            Console.WriteLine("  IsAuthorized            = " + IsAuthorized(out r) + "  (" + r + ")");
            Console.WriteLine("  IsAuthorized_FailClosed = " + IsAuthorized_FailClosed(out rc) + "  (" + rc + ")");
            Console.WriteLine();

            Console.WriteLine("【阶段 2】配置文件内容为字面量 \"null\"");
            File.WriteAllText("fake.lic", "null");
            FakeCredentialStore.LoadFromConfig("fake.lic");
            Console.WriteLine("  IsAuthorized            = " + IsAuthorized(out r) + "  (" + r + ")");
            Console.WriteLine("  IsAuthorized_FailClosed = " + IsAuthorized_FailClosed(out rc) + "  (" + rc + ")");
            Console.WriteLine();

            Console.WriteLine("【阶段 3】合法凭据");
            File.WriteAllText("fake.lic", "LAB-KEY-001");
            FakeCredentialStore.LoadFromConfig("fake.lic");
            Console.WriteLine("  IsAuthorized            = " + IsAuthorized(out r) + "  (" + r + ")");
            Console.WriteLine("  IsAuthorized_FailClosed = " + IsAuthorized_FailClosed(out rc) + "  (" + rc + ")");
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • 阶段 1 / 2 中，Fail-Open 版本直接放行 —— 整条校验链被跳过。");
            Console.WriteLine("  • 修复成本：★☆☆（把空值分支改成 return false 即可）。");
            Console.WriteLine("  • 这是最容易被忽略、也最致命的鉴权缺陷。");
        }
    }
}
