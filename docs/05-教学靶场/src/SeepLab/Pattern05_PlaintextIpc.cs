// ============================================================================
//  SeepLab Pattern 05 · 明文进程间通信（Plaintext IPC）
// ============================================================================
//
//  教学样本：演示「鉴权逻辑下沉到独立进程」这一正确架构，
//            如何因为【通信通道未加固】而完全失效。
//
//  核心认知：把逻辑搬到另一个进程 ≠ 安全。
//            安全强度取决于链路中最薄弱的一环。
//
//  编译：build.ps1（Windows 自带 csc.exe，零依赖，C# 5 兼容）
// ============================================================================

using System;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;

namespace SeepLab
{
    public static class Pattern05
    {
        private static int _lastSeq = 0;

        // ─────────────────────────────────────────────────────────────
        //  ★ 缺陷点：只校验状态码，不校验来源与完整性。
        //    真实产品的典型写法：状态码命中即放行。
        // ─────────────────────────────────────────────────────────────
        public static bool HandlePlaintextResponse(int statusCode)
        {
            return statusCode == 3;               // 3 = 已授权
        }

        // ─────────────────────────────────────────────────────────────
        //  ✅ 加固版：HMAC + 时戳 + 序号 + 来源校验
        // ─────────────────────────────────────────────────────────────
        public static bool HandleSecuredResponse(byte[] payload, byte[] mac,
                                                 long timestamp, int seq,
                                                 byte[] sessionKey,
                                                 out string reason)
        {
            // ① 防重放：时戳必须在 5 秒窗口内
            long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            if (Math.Abs(now - timestamp) > 5)
            {
                reason = "时戳超出窗口（疑似重放）";
                return false;
            }

            // ② 防重放：序号必须递增
            if (seq <= _lastSeq)
            {
                reason = "序号未递增（疑似重放）";
                return false;
            }
            _lastSeq = seq;

            // ③ 消息认证：HMAC 校验（防伪造）—— 常数时间比较
            byte[] block = new byte[8 + 4 + payload.Length];
            Array.Copy(BitConverter.GetBytes(timestamp), 0, block, 0, 8);
            Array.Copy(BitConverter.GetBytes(seq), 0, block, 8, 4);
            Array.Copy(payload, 0, block, 12, payload.Length);

            byte[] expect;
            using (HMACSHA256 h = new HMACSHA256(sessionKey))
            {
                expect = h.ComputeHash(block);
            }
            if (!FixedTimeEquals(mac, expect))
            {
                reason = "HMAC 校验失败（消息被篡改或来源伪造）";
                return false;
            }

            reason = "认证通过";
            return true;
        }

        /// <summary>常数时间比较（防时序侧信道）。</summary>
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= (a[i] ^ b[i]);
            return diff == 0;
        }

        /// <summary>✅ 通道加固：管道 ACL 限制为当前用户。</summary>
        public static void PrintSecuredPipeExample()
        {
            Console.WriteLine("  ✅ 加固的管道创建（ACL 限定当前用户）:");
            Console.WriteLine("     var sec = new PipeSecurity();");
            Console.WriteLine("     sec.AddAccessRule(new PipeAccessRule(");
            Console.WriteLine("         WindowsIdentity.GetCurrent().User,");
            Console.WriteLine("         PipeAccessRights.FullControl,");
            Console.WriteLine("         AccessControlType.Allow));");
            Console.WriteLine("     // 显式拒绝其他用户");
            Console.WriteLine("     sec.AddAccessRule(new PipeAccessRule(");
            Console.WriteLine("         new SecurityIdentifier(WellKnownSidType.WorldSid, null),");
            Console.WriteLine("         PipeAccessRights.ReadWrite,");
            Console.WriteLine("         AccessControlType.Deny));");
        }

        /// <summary>✅ 身份校验：验证对端进程。</summary>
        public static void PrintPeerVerifyExample()
        {
            Console.WriteLine("  ✅ 对端进程校验三要素:");
            Console.WriteLine("     ① 主模块路径必须位于受信任目录");
            Console.WriteLine("     ② 必须通过 Authenticode 签名校验");
            Console.WriteLine("     ③ 绑定 PID，防止句柄复用");
        }

        /// <summary>靶场入口。</summary>
        public static void Run()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║  SeepLab · 模式 05 · 明文进程间通信        ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine();

            Console.WriteLine("【教学 1】明文通道的攻击面");
            Console.WriteLine();
            Console.WriteLine("  架构（真实产品）:");
            Console.WriteLine("  ┌──────────────┐    IPC    ┌──────────────┐");
            Console.WriteLine("  │ 主程序        │ ←──────→ │ 鉴权服务进程   │");
            Console.WriteLine("  │ if(code==3)  │  明文状态码 │  (可能强保护)  │");
            Console.WriteLine("  │   EnablePro  │           │  (虚拟化保护)  │");
            Console.WriteLine("  └──────────────┘           └──────────────┘");
            Console.WriteLine();
            Console.WriteLine("  攻击者不需要碰那个「强保护」的鉴权服务：");
            Console.WriteLine("  只需在 IPC 通道上伪造一个状态码 3 即可。");
            Console.WriteLine();

            Console.WriteLine("【教学 2】状态码值域 = 攻击成本");
            Console.WriteLine();
            Console.WriteLine("  假设状态码是 int32：");
            Console.WriteLine("    搜索空间 = 2^32 ≈ 43 亿");
            Console.WriteLine("    但实际上鉴权状态通常只有 3~5 个含义 → 命中概率极高");
            Console.WriteLine();
            Console.WriteLine("  HandlePlaintextResponse(3) = " + HandlePlaintextResponse(3) + "  ← 伪造成功");
            Console.WriteLine();

            Console.WriteLine("【教学 3】加固后的消息认证");
            Console.WriteLine();
            byte[] sessionKey = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(sessionKey);
            }

            long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            int  seq = 1;
            byte[] payload = Encoding.UTF8.GetBytes("licensed");

            byte[] block = new byte[8 + 4 + payload.Length];
            Array.Copy(BitConverter.GetBytes(ts), 0, block, 0, 8);
            Array.Copy(BitConverter.GetBytes(seq), 0, block, 8, 4);
            Array.Copy(payload, 0, block, 12, payload.Length);

            byte[] mac;
            using (HMACSHA256 h = new HMACSHA256(sessionKey))
            {
                mac = h.ComputeHash(block);
            }

            string r;

            Console.WriteLine("  场景 A：合法消息（HMAC 正确）");
            Console.WriteLine("  HandleSecuredResponse = " + HandleSecuredResponse(payload, mac, ts, seq, sessionKey, out r) + "  (" + r + ")");
            Console.WriteLine();

            Console.WriteLine("  场景 B：消息被篡改");
            byte[] badPayload = (byte[])payload.Clone();
            badPayload[0] ^= 0xFF;
            Console.WriteLine("  HandleSecuredResponse = " + HandleSecuredResponse(badPayload, mac, ts, 2, sessionKey, out r) + "  (" + r + ")");
            Console.WriteLine();

            Console.WriteLine("  场景 C：重放攻击（旧时戳）");
            Console.WriteLine("  HandleSecuredResponse = " + HandleSecuredResponse(payload, mac, ts - 100, 3, sessionKey, out r) + "  (" + r + ")");
            Console.WriteLine();

            PrintSecuredPipeExample();
            Console.WriteLine();
            PrintPeerVerifyExample();
            Console.WriteLine();

            Console.WriteLine("【教学总结】");
            Console.WriteLine("  • 鉴权下沉是正确的架构，但【通道未加固 = 白下沉】。");
            Console.WriteLine("  • 修复成本：★☆☆ —— 加 HMAC + 时戳 + 序号 + 对端校验。");
            Console.WriteLine("  • 修复后，强保护的鉴权内核才能发挥真正价值。");
        }
    }
}
