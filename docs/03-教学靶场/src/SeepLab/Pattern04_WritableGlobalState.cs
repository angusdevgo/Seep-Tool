// ============================================================================
//  SeepLab Pattern 04 · 可写全局状态（Writable Global State）
// ============================================================================
//
//  教学样本：演示「授权状态被存放在用户可写位置」的三种形态，
//  以及「外部写入 → 功能解锁」的完整链路。
//
//  三种形态：
//    A. 注册表明文布尔值      （对应 BoosterX 类样本）
//    B. 配置文件明文字段      （对应常见桌面软件）
//    C. 环境变量             （对应部分开发工具）
//
//  编译：build.ps1（Windows 自带 csc.exe，零依赖，C# 5 兼容）
// ============================================================================

using System;
using System.IO;
using Microsoft.Win32;

namespace SeepLab
{
    public static class Pattern04
    {
        private const string LabKey = "Software\\SeepLab\\Pattern04";

        // ─────────────────────────────────────────────────────────────
        //  形态 A · 注册表明文布尔值
        // ─────────────────────────────────────────────────────────────
        public static bool ReadFlagFromRegistry(string name)
        {
            // ★ 缺陷点：读取后【无完整性校验、无来源校验】。
            //   任何同用户进程都能写这个键，客户端照单全收。
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(LabKey))
            {
                object v = (k == null) ? null : k.GetValue(name);
                return (v is int) && ((int)v != 0);
            }
        }

        public static void WriteFlagToRegistry(string name, int value)
        {
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(LabKey))
            {
                k.SetValue(name, value, RegistryValueKind.DWord);   // 明文 DWord
            }
        }

        /// <summary>业务逻辑：直接以注册表值作为权益判据（★ 反模式）。</summary>
        public static void FeatureGate_FromRegistry()
        {
            bool isPro = ReadFlagFromRegistry("IsPro");         // ← 权益判据来自用户可写位置
            Console.WriteLine(isPro
                ? "  [PRO]   注册表 IsPro=1 → 专业版功能已解锁"
                : "  [FREE]  注册表 IsPro=0 → 专业版功能已锁定");
        }

        // ─────────────────────────────────────────────────────────────
        //  形态 B · 配置文件明文字段
        // ─────────────────────────────────────────────────────────────
        public static void FeatureGate_FromConfig(string path)
        {
            // ★ 缺陷点：配置文件中的字段直接决定特权。
            if (!File.Exists(path))
            {
                Console.WriteLine("  [FREE]  配置文件不存在 → 功能锁定");
                return;
            }
            string content = File.ReadAllText(path);
            bool isPro = content.Contains("\"edition\": \"pro\"");   // 明文匹配
            Console.WriteLine(isPro
                ? "  [PRO]   配置 edition=pro → 专业版功能已解锁"
                : "  [FREE]  配置 edition=free → 专业版功能已锁定");
        }

        // ─────────────────────────────────────────────────────────────
        //  形态 C · 环境变量
        // ─────────────────────────────────────────────────────────────
        public static void FeatureGate_FromEnv()
        {
            string v = Environment.GetEnvironmentVariable("SEEPLAB_PRO");
            Console.WriteLine(v == "1"
                ? "  [PRO]   环境变量 SEEPLAB_PRO=1 → 已解锁"
                : "  [FREE]  环境变量未设置 → 已锁定");
        }

        // ─────────────────────────────────────────────────────────────
        //  对照：正确的「凭据驱动」实现
        // ─────────────────────────────────────────────────────────────
        /// <summary>
        /// ✅ 正确实现：本地存储只作「用户偏好」，权益判据必须来自
        ///    服务端签名凭据。签名无效 → 一律拒绝（Fail-Closed）。
        /// </summary>
        public static void FeatureGate_Correct(string signedCredential)
        {
            // 教学模拟：真实实现应使用非对称验签。
            bool valid = !string.IsNullOrEmpty(signedCredential)
                      && signedCredential.StartsWith("SIG-");

            Console.WriteLine(valid
                ? "  [PRO]   签名凭据验签通过 → 已解锁"
                : "  [FREE]  无有效签名凭据 → 已锁定（Fail-Closed）");
        }

        /// <summary>靶场入口。</summary>
        public static void Run()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 04 · 可写全局状态          ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            Console.WriteLine("【阶段 1】注册表形态");
            WriteFlagToRegistry("IsPro", 0);
            FeatureGate_FromRegistry();
            Console.WriteLine("  >>> 攻击者操作：写入 IsPro=1（无需触碰二进制）");
            WriteFlagToRegistry("IsPro", 1);
            FeatureGate_FromRegistry();
            Console.WriteLine();

            Console.WriteLine("【阶段 2】配置文件形态");
            File.WriteAllText("lab04.json", "{ \"edition\": \"free\" }");
            FeatureGate_FromConfig("lab04.json");
            Console.WriteLine("  >>> 攻击者操作：把 free 改成 pro");
            File.WriteAllText("lab04.json", "{ \"edition\": \"pro\" }");
            FeatureGate_FromConfig("lab04.json");
            Console.WriteLine();

            Console.WriteLine("【阶段 3】环境变量形态");
            Environment.SetEnvironmentVariable("SEEPLAB_PRO", null);
            FeatureGate_FromEnv();
            Console.WriteLine("  >>> 攻击者操作：set SEEPLAB_PRO=1");
            Environment.SetEnvironmentVariable("SEEPLAB_PRO", "1");
            FeatureGate_FromEnv();
            Console.WriteLine();

            Console.WriteLine("【阶段 4】对照：凭据驱动的正确实现");
            FeatureGate_Correct("");
            FeatureGate_Correct("SIG-VALID-CREDENTIAL");
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • 三种形态的共同点：权益判据存放在【用户可写位置】，且读取后无校验。");
            Console.WriteLine("  • 防御：本地存储只作「用户偏好」，权益判据必须来自服务端签名凭据。");
        }
    }
}
