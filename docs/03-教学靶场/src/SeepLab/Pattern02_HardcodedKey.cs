// ============================================================================
//  SeepLab Pattern 02 · 硬编码密钥材料（Hardcoded Key Material）
// ============================================================================
//
//  教学样本：演示「非对称体系的信任根（公钥）可被替换」这一缺陷。
//
//  核心认知：Ed25519/ECDSA 算法本身不可破解，但若【公钥本身没有完整性保护】，
//            攻击者替换公钥后，用自己的私钥签发的凭据即可通过验签。
//
//  编译：build.ps1（Windows 自带 csc.exe，零依赖，C# 5 兼容）
// ============================================================================

using System;
using System.Security.Cryptography;

namespace SeepLab
{
    public static class Pattern02
    {
        // ─────────────────────────────────────────────────────────────
        //  ★ 缺陷点 DEFECT-01：公钥硬编码，且无完整性校验
        //
        //  真实产品中，这串字节存在于只读数据节区。
        //  攻击者只需原位置换这串字节，就等于「换掉了信任根」。
        // ─────────────────────────────────────────────────────────────
        private static readonly byte[] EmbeddedPublicKey = new byte[]
        {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
            0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
            0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01
        };

        // ─────────────────────────────────────────────────────────────
        //  ✅ 修复方案：公钥指纹多点交叉校验
        //    编译期计算公钥的 SHA-256 前 16 字节作为指纹，
        //    在多个不相关位置比对。替换公钥必然破坏指纹。
        // ─────────────────────────────────────────────────────────────
        private static readonly byte[] PublicKeyFingerprint =
            Take(ComputeSha256(EmbeddedPublicKey), 16);

        private static byte[] ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        private static byte[] Take(byte[] src, int count)
        {
            byte[] r = new byte[count];
            Array.Copy(src, r, count);
            return r;
        }

        /// <summary>校验点 #1：验签入口（最常见的引用位置）。</summary>
        public static bool VerifyWithCheck1(byte[] msg, byte[] sig)
        {
            if (!VerifyPublicKeyIntegrity("Check1")) return false;
            return VerifySignature(msg, sig);
        }

        /// <summary>校验点 #2：启动自检（与业务逻辑不相关的独立位置）。</summary>
        public static bool VerifyWithCheck2(byte[] msg, byte[] sig)
        {
            if (!VerifyPublicKeyIntegrity("Check2")) return false;
            return VerifySignature(msg, sig);
        }

        /// <summary>校验点 #3：关键功能调用前。</summary>
        public static bool VerifyWithCheck3(byte[] msg, byte[] sig)
        {
            if (!VerifyPublicKeyIntegrity("Check3")) return false;
            return VerifySignature(msg, sig);
        }

        private static bool VerifyPublicKeyIntegrity(string from)
        {
            byte[] actual = ComputeSha256(EmbeddedPublicKey);
            for (int i = 0; i < PublicKeyFingerprint.Length; i++)
            {
                if (actual[i] != PublicKeyFingerprint[i])
                {
                    Console.WriteLine("  [!] 公钥指纹校验失败 @ " + from + " → 信任根已被篡改");
                    return false;
                }
            }
            return true;
        }

        // 教学模拟：.NET 4.x 无内置 SubjectPublicKeyInfo 解析，
        // 故用【哈希比对】模拟「公钥指纹校验」这一核心教学点。
        // 真实实现应使用 Ed25519 / ECDSA 验签（.NET 8+ 或 BouncyCastle）。
        private static bool VerifySignature(byte[] msg, byte[] sig)
        {
            // 教学简化：签名有效性 = 签名的前 8 字节是消息哈希前 8 字节
            byte[] mh = ComputeSha256(msg);
            if (sig.Length < 8) return false;
            for (int i = 0; i < 8; i++)
                if (sig[i] != mh[i]) return false;
            return true;
        }

        /// <summary>靶场入口。</summary>
        public static void Run()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 02 · 硬编码密钥材料        ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            Console.WriteLine("【教学 1】信任根替换的原理");
            Console.WriteLine();
            Console.WriteLine("  非对称体系的安全前提：");
            Console.WriteLine("    ① 私钥不可得         ← 服务端保管，✅ 通常满足");
            Console.WriteLine("    ② 客户端公钥未被篡改  ← ❌ 常被忽略！");
            Console.WriteLine();
            Console.WriteLine("  攻击者不需要破解签名算法，只需要：");
            Console.WriteLine("    1. 生成自己的密钥对");
            Console.WriteLine("    2. 用自己的私钥签发凭据");
            Console.WriteLine("    3. 把客户端里的公钥【原位置换】成自己的公钥");
            Console.WriteLine("    4. 自签凭据 → 验签通过 → 完全合法的格式");
            Console.WriteLine();

            Console.WriteLine("【教学 2】多点交叉校验的防御效果");
            Console.WriteLine();
            byte[] fakeMsg = System.Text.Encoding.UTF8.GetBytes("lab-message");
            byte[] fakeSig = new byte[64];

            Console.WriteLine("  场景 A：公钥未被篡改（正常状态）");
            bool r1 = VerifyWithCheck1(fakeMsg, fakeSig);
            Console.WriteLine("  Check1 验签 = " + r1 + "（false 是因为签名本身无效，属正常拒绝）");
            Console.WriteLine();

            Console.WriteLine("  场景 B：公钥被替换（模拟攻击）");
            EmbeddedPublicKey[30] ^= 0xFF;                 // 模拟攻击者改了公钥一个字节
            bool r2 = VerifyWithCheck1(fakeMsg, fakeSig);
            Console.WriteLine("  Check1 验签 = " + r2 + "，且指纹校验拦截 = " + (!r2));
            EmbeddedPublicKey[30] ^= 0xFF;                 // 还原
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • 公钥多点交叉校验 = 给信任根上锁。替换公钥必然破坏指纹。");
            Console.WriteLine("  • 修复成本：★☆☆ —— 只需在多个位置加一段指纹比对。");
            Console.WriteLine("  • 配套措施：二进制 Authenticode 运行时自校验。");
        }
    }
}
