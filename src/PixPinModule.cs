// PixPinModule.cs — PixPin 会员特权判定分支走查模块 (CWE-602)
//
// 目标: PixAuth.dll —— PixPin 的全部 PRO/VIP 特权判定集中于此本地动态库
// 根因: 14 项会员功能 (FeatureType 枚举) 全部由本地布尔/枚举函数决定，
//       无签名绑定、无服务端权威闭环，单一函数入口恒值化即可全量解除。
//
// 补丁语义（11 处，全部为函数入口恒值化，帧未分配即返回，无栈平衡风险）:
//   A 授权身份: isProUser / isVip 系列 → mov al,1; ret
//   B 功能门控: checkFeatureAllow → mov eax,1; ret
//               featureStatus     → xor eax,eax; ret (Available)
//               isProFeature      → xor al,al; ret
//   C 试用机制: hasActivatedTrialAccess → mov al,1; ret
//               rescheduleTrialExpireTimer → ret (禁用倒计时)
//   D 订阅提醒: showSubscriptionTrialReminder → ret (抑制弹窗)
//
// 逆向证据: docs/PixPin-RE.md（含 14 项 FeatureType 枚举、107 处门控调用点、
//           Frida 运行时全功能矩阵验证、ICF 折叠分析）
using System;
using System.Collections.Generic;
using System.IO;
using Seep.Core;

namespace Seep.Modules
{
    public static class PixPinModule
    {
        public const string Name = "PixPin";
        public const string ExeName = "PixPin.exe";
        public const string AuthDllName = "PixAuth.dll";

        // 已知目标样本指纹（PixPin 3.5.5.1）
        public const string KNOWN_PIXAUTH_SHA256 = "a2f4eb36567a2400932576c6841e264f"; // MD5 参考，SHA 由运行时计算

        // ─── 11 处特权判定补丁点（RVA 寻址）───
        // 完整 FeatureType 映射见 docs/PixPin-RE.md
        public static readonly PatchSite[] Sites = new PatchSite[]
        {
            // A. 授权身份判定（4 处 + ICF 折叠 1 处 = 覆盖 5 个符号）
            new PatchSite(0x0C3270, "48 83 ec 28",     "b0 01 c3",       "A1 PixAuth::UserInfo::isProUser"),
            new PatchSite(0x09C430, "48 83 c1 10",     "b0 01 c3",       "A2 PixAuth::Application::isProUser"),
            new PatchSite(0x0EE950, "40 53 48 83 ec 20", "b0 01 c3",     "A3 PixAuth::VipInfo::isVip"),
            new PatchSite(0x0EE910, "40 53 48 83 ec 20", "b0 01 c3",     "A4 PixAuth::Subscription::isVip"),
            new PatchSite(0x0EE7B0, "40 53 48 83 ec 20", "b0 01 c3",     "A5 PrepaidInfo::isVip + VipInfo::hasPrepaid (ICF 折叠)"),

            // B. 功能门控判定（3 处，覆盖全部 14 项 FeatureType）
            new PatchSite(0x0A74D0, "48 89 5c 24 10 48", "b8 01 00 00 00 c3", "B1 checkFeatureAllow -> Allow(1)"),
            new PatchSite(0x0A8040, "48 89 5c 24 10 56", "31 c0 c3",          "B2 featureStatus -> Available(0)"),
            new PatchSite(0x0A86F0, "48 89 5c 24 08 57", "32 c0 c3",          "B3 isProFeature -> false"),

            // C. 试用机制判定（2 处）
            new PatchSite(0x0A84B0, "40 53 48 83 ec 20", "b0 01 c3", "C1 hasActivatedTrialAccess -> true"),
            new PatchSite(0x0A8C30, "40 53 55 56 57 48", "c3",       "C2 rescheduleTrialExpireTimer -> 禁用倒计时"),

            // D. 订阅提醒抑制（1 处）
            new PatchSite(0x09D560, "40 55 53 56 57 41", "c3",       "D1 showSubscriptionTrialReminder -> 抑制弹窗"),
        };

        // 未覆盖的埋点/文案函数（非门控，见 docs/PixPin-RE.md §4）
        // VipInfo::hasSubscription  (0x0EE7D0) — UpgradeFunnel 埋点 + 到期提醒
        // VipInfo::isLifetimeVip    (0x0EE8F0) — UserType 埋点字段 + UI 标签

        public static List<string> Locate() { return TargetLocator.FindPixPin(); }

        // 确保 PixPin 已退出（否则 PixAuth.dll 被占用无法写入）
        public static bool EnsureClosed(IList<string> log)
        {
            try
            {
                var procs = System.Diagnostics.Process.GetProcessesByName("PixPin");
                var procsAux = System.Diagnostics.Process.GetProcessesByName("PixPinAuxiliary");
                int n = procs.Length + procsAux.Length;
                if (n == 0) return true;

                foreach (var p in procs)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }
                foreach (var p in procsAux)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }
                System.Threading.Thread.Sleep(900);

                int left = System.Diagnostics.Process.GetProcessesByName("PixPin").Length
                         + System.Diagnostics.Process.GetProcessesByName("PixPinAuxiliary").Length;
                if (left > 0)
                {
                    log.Add("[-] PixPin 仍在运行（" + left + " 个进程），请手动完全退出后重试");
                    return false;
                }
                log.Add("[*] 已自动关闭 PixPin 进程（" + n + " 个）以释放文件占用");
                return true;
            }
            catch (Exception ex)
            {
                log.Add("[!] 进程检查异常: " + ex.Message);
                return true;
            }
        }

        // ─── 状态检测 ───
        public static string DetectState(byte[] data)
        {
            int patched = 0, original = 0, unknown = 0;
            foreach (var s in Sites)
            {
                long off;
                if (!PeUtil.RvaToOffset(data, s.Offset, out off)) { unknown++; continue; }
                if (PeUtil.BytesAt(data, off, s.Replace)) patched++;
                else if (PeUtil.BytesAt(data, off, s.Expect)) original++;
                else unknown++;
            }
            if (patched == Sites.Length) return "patched";
            if (original > 0) return "original";
            if (unknown == Sites.Length) return "unknown";
            return original > 0 ? "original" : "unknown";
        }

        public static string Status(string dir, IList<string> log)
        {
            string dll = Path.Combine(dir, AuthDllName);
            if (!File.Exists(dll)) { log.Add("[-] 未找到 " + AuthDllName); return "missing"; }
            log.Add("[*] " + dll);

            try
            {
                byte[] data = File.ReadAllBytes(dll);
                log.Add("[*] SHA256: " + PeUtil.Sha256Hex(data));

                int patched = 0, original = 0, unknown = 0;
                foreach (var s in Sites)
                {
                    long off;
                    if (!PeUtil.RvaToOffset(data, s.Offset, out off)) { unknown++; continue; }
                    if (PeUtil.BytesAt(data, off, s.Replace)) patched++;
                    else if (PeUtil.BytesAt(data, off, s.Expect)) original++;
                    else unknown++;
                }
                log.Add(string.Format("    补丁点统计: 已补丁 {0} / 原版 {1} / 未知 {2} (共 {3})",
                    patched, original, unknown, Sites.Length));

                if (patched == Sites.Length)
                {
                    log.Add("[+] 状态: 已激活（14 项会员功能全部解锁）");
                    return "patched";
                }
                if (original > 0)
                {
                    log.Add("[*] 状态: 原版/未完全修补");
                    return "original";
                }
                log.Add("[?] 状态: 未知构建（特征码不匹配）");
                return "unknown";
            }
            catch (Exception ex)
            {
                log.Add("[-] 检测异常: " + ex.Message);
                return "unknown";
            }
        }

        public static void Check(string dir, IList<string> log) { Status(dir, log); }

        // ─── 应用补丁（自动备份 .orig）───
        public static bool Patch(string dir, IList<string> log)
        {
            string dll = Path.Combine(dir, AuthDllName);
            if (!File.Exists(dll)) { log.Add("[-] 未找到 " + AuthDllName); return false; }
            log.Add("[*] 目标: " + dll);

            if (!EnsureClosed(log)) return false;

            try
            {
                byte[] data = File.ReadAllBytes(dll);
                log.Add("[*] SHA256: " + PeUtil.Sha256Hex(data));

                // 预检 + 构建写入计划
                var plan = new List<KeyValuePair<long, byte[]>>();
                int already = 0;
                foreach (var s in Sites)
                {
                    long off;
                    if (!PeUtil.RvaToOffset(data, s.Offset, out off))
                    {
                        log.Add("[-] RVA 0x" + s.Offset.ToString("X") + " 无法映射（" + s.Note + "）");
                        return false;
                    }
                    if (PeUtil.BytesAt(data, off, s.Replace)) { already++; continue; }
                    if (!PeUtil.BytesAt(data, off, s.Expect))
                    {
                        log.Add("[-] 特征码不匹配 @0x" + off.ToString("X") + "（" + s.Note + "）");
                        log.Add("    期望: " + PeUtil.Hex(s.Expect));
                        return false;
                    }
                    plan.Add(new KeyValuePair<long, byte[]>(off, s.Replace));
                }

                if (plan.Count == 0)
                {
                    log.Add("[=] 目标已完全修补（11/11 已在位），无需写入");
                    return true;
                }

                // 备份
                string bak = dll + ".orig";
                if (!File.Exists(bak))
                {
                    File.Copy(dll, bak, false);
                    log.Add("[+] 已备份原件 -> " + bak);
                }
                else log.Add("[=] 备份已存在（保留最初原件）: " + bak);

                // 写入
                foreach (var kv in plan)
                    Array.Copy(kv.Value, 0, data, kv.Key, kv.Value.Length);
                File.WriteAllBytes(dll, data);

                // 复读校验
                byte[] verify = File.ReadAllBytes(dll);
                int ok = 0;
                foreach (var s in Sites)
                {
                    long off;
                    PeUtil.RvaToOffset(verify, s.Offset, out off);
                    if (PeUtil.BytesAt(verify, off, s.Replace)) ok++;
                }

                log.Add(string.Format("[+] 写入 {0} 处补丁（原有 {1} 处），复读校验 {2}/{3}",
                    plan.Count, already, ok, Sites.Length));
                log.Add("[+] 新 SHA256: " + PeUtil.Sha256Hex(verify));

                if (ok == Sites.Length)
                {
                    log.Add("[✓] PixPin 会员特权修补成功！14 项功能已全部解锁：");
                    log.Add("    翻译 / 表格识别 / 公式识别 / 智能擦除 / 全局鼠标 / 配置同步");
                    log.Add("    长截图自动裁剪 / 录制片段 / 键鼠录制 / 导出预览 / 另存为PDF");
                    log.Add("    自动马赛克同步 / 工业条码识别 / 摄像头录制");
                    log.Add("    注：翻译功能的服务端算力仍需配套代理重定向");
                    return true;
                }
                log.Add("[-] 复读校验未完全通过");
                return false;
            }
            catch (IOException ex)
            {
                log.Add("[-] 文件被占用，请先完全退出 PixPin: " + ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                log.Add("[-] 修补异常: " + ex.Message);
                return false;
            }
        }

        // ─── 单体独立还原 ───
        public static bool Revert(string dir, IList<string> log)
        {
            string dll = Path.Combine(dir, AuthDllName);
            string bak = dll + ".orig";
            if (!File.Exists(bak))
            {
                log.Add("[-] 未找到备份文件: " + bak);
                return false;
            }
            if (!EnsureClosed(log)) return false;
            try
            {
                File.Copy(bak, dll, true);
                log.Add("[✓] 已从备份还原官方原版 -> " + dll);
                log.Add("[+] SHA256: " + PeUtil.Sha256File(dll));
                return true;
            }
            catch (IOException ex)
            {
                log.Add("[-] 还原失败（PixPin 可能正在运行）: " + ex.Message);
                return false;
            }
        }
    }
}
