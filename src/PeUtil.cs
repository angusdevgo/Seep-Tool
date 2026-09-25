// PeUtil.cs — PE 结构解析与通用工具（VA↔文件偏移、SHA256、字节特征检查）
// C# 5 / .NET Framework 4.x compatible.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Seep.Core
{
    public static class PeUtil
    {
        // 把 VA（含 ImageBase）映射为文件偏移。返回 false 表示不在任何节内。
        public static bool VaToOffset(byte[] pe, long va, out long offset)
        {
            offset = 0;
            int peOff = BitConverter.ToInt32(pe, 0x3C);
            int nsec = BitConverter.ToUInt16(pe, peOff + 6);
            int opt = peOff + 24;
            long imgBase = BitConverter.ToInt64(pe, opt + 24);
            int secOff = opt + BitConverter.ToUInt16(pe, peOff + 20);
            for (int i = 0; i < nsec; i++)
            {
                int so = secOff + i * 40;
                int vsize = BitConverter.ToInt32(pe, so + 8);
                long vaddr = BitConverter.ToUInt32(pe, so + 12);
                int rsize = BitConverter.ToInt32(pe, so + 16);
                long raddr = BitConverter.ToUInt32(pe, so + 20);
                long sva = imgBase + vaddr;
                if (va >= sva && va < sva + Math.Max(vsize, rsize))
                {
                    offset = raddr + (va - sva);
                    return true;
                }
            }
            return false;
        }

        // 把 RVA 映射为文件偏移。
        public static bool RvaToOffset(byte[] pe, long rva, out long offset)
        {
            offset = 0;
            int peOff = BitConverter.ToInt32(pe, 0x3C);
            int nsec = BitConverter.ToUInt16(pe, peOff + 6);
            int opt = peOff + 24;
            int secOff = opt + BitConverter.ToUInt16(pe, peOff + 20);
            for (int i = 0; i < nsec; i++)
            {
                int so = secOff + i * 40;
                int vsize = BitConverter.ToInt32(pe, so + 8);
                long vaddr = BitConverter.ToUInt32(pe, so + 12);
                int rsize = BitConverter.ToInt32(pe, so + 16);
                long raddr = BitConverter.ToUInt32(pe, so + 20);
                if (rva >= vaddr && rva < vaddr + Math.Max(vsize, rsize))
                {
                    offset = raddr + (rva - vaddr);
                    return true;
                }
            }
            return false;
        }

        public static string Sha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(data);
                var sb = new System.Text.StringBuilder(h.Length * 2);
                for (int i = 0; i < h.Length; i++) sb.Append(h[i].ToString("x2"));
                return sb.ToString();
            }
        }

        public static string Sha256File(string path)
        {
            return Sha256Hex(System.IO.File.ReadAllBytes(path));
        }

        public static bool BytesAt(byte[] data, long offset, byte[] pattern)
        {
            if (offset < 0 || offset + pattern.Length > data.Length) return false;
            for (int i = 0; i < pattern.Length; i++)
                if (data[offset + i] != pattern[i]) return false;
            return true;
        }

        public static string Hex(byte[] b)
        {
            var sb = new System.Text.StringBuilder(b.Length * 3);
            for (int i = 0; i < b.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(b[i].ToString("x2"));
            }
            return sb.ToString();
        }

        public static byte[] HexToBytes(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            var outBytes = new byte[hex.Length / 2];
            for (int i = 0; i < outBytes.Length; i++)
                outBytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return outBytes;
        }
    }

    // 单个补丁点定义
    public struct PatchSite
    {
        public long Offset;        // 文件偏移
        public byte[] Expect;      // 原始字节
        public byte[] Replace;     // 补丁字节
        public string Note;

        public PatchSite(long offset, string expectHex, string replaceHex, string note)
        {
            Offset = offset;
            Expect = PeUtil.HexToBytes(expectHex);
            Replace = PeUtil.HexToBytes(replaceHex);
            Note = note;
        }
    }

    // 通用文件补丁引擎：预检 → 备份 → 写入 → 复读校验
    public static class FilePatcher
    {
        public enum SiteState { Patched, Original, Unknown }

        public static SiteState CheckSite(byte[] data, PatchSite site)
        {
            return CheckSite(data, site.Offset, site);
        }

        public static SiteState CheckSite(byte[] data, long offset, PatchSite site)
        {
            if (PeUtil.BytesAt(data, offset, site.Replace)) return SiteState.Patched;
            if (PeUtil.BytesAt(data, offset, site.Expect)) return SiteState.Original;
            return SiteState.Unknown;
        }

        public static SiteState CheckFile(string exePath, PatchSite[] sites, IList<string> log)
        {
            byte[] data = System.IO.File.ReadAllBytes(exePath);
            SiteState overall = SiteState.Patched;
            foreach (var s in sites)
            {
                long off;
                if (!PeUtil.RvaToOffset(data, s.Offset, out off) && s.Offset >= data.Length)
                {
                    log.Add("[-] 偏移 0x" + s.Offset.ToString("X") + " 越界（" + s.Note + "）");
                    return SiteState.Unknown;
                }
                var st = CheckSite(data, s.Offset >= data.Length ? s : new PatchSite { Offset = off, Expect = s.Expect, Replace = s.Replace, Note = s.Note });
                log.Add(string.Format("  0x{0:X}: {1}  ({2})", s.Offset, st, s.Note));
                if (st == SiteState.Unknown) return SiteState.Unknown;
                if (st == SiteState.Original) overall = SiteState.Original;
            }
            return overall;
        }

        // 原位补丁（自动备份 .bak；幂等）
        public static bool PatchInPlace(string exePath, PatchSite[] sites, IList<string> log)
        {
            byte[] data = System.IO.File.ReadAllBytes(exePath);
            log.Add("目标: " + exePath + " (" + data.Length + " 字节)");
            log.Add("SHA256: " + PeUtil.Sha256Hex(data));

            // 预检：RVA→文件偏移映射
            var plan = new List<KeyValuePair<long, byte[]>>();
            foreach (var s in sites)
            {
                long off = s.Offset;
                if (s.Offset >= data.Length)
                {
                    long mapped;
                    if (!PeUtil.RvaToOffset(data, s.Offset, out mapped))
                    {
                        log.Add("[-] 偏移 0x" + s.Offset.ToString("X") + " 无法映射（" + s.Note + "）");
                        return false;
                    }
                    off = mapped;
                }
                var st = CheckSite(data, off, s);
                if (st == SiteState.Patched) { log.Add("[=] 0x" + off.ToString("X") + " 已处于补丁状态（" + s.Note + "）"); continue; }
                if (st == SiteState.Unknown)
                {
                    log.Add("[-] 0x" + off.ToString("X") + " 特征码不匹配（" + s.Note + "）");
                    log.Add("    期望: " + PeUtil.Hex(s.Expect) + "  实际: " + PeUtil.Hex(BytesAt2(data, off, s.Expect.Length)));
                    return false;
                }
                log.Add("[+] 0x" + off.ToString("X") + " 特征码匹配: " + s.Note);
                plan.Add(new KeyValuePair<long, byte[]>(off, s.Replace));
            }

            if (plan.Count == 0)
            {
                log.Add("[*] 目标已完全修补，无需写入。");
                return true;
            }

            string bak = exePath + ".bak";
            if (!System.IO.File.Exists(bak))
            {
                System.IO.File.Copy(exePath, bak, false);
                log.Add("[+] 已备份原件 -> " + bak);
            }
            else log.Add("[=] 备份已存在（保留最初原件）: " + bak);

            foreach (var kv in plan)
                Array.Copy(kv.Value, 0, data, kv.Key, kv.Value.Length);
            System.IO.File.WriteAllBytes(exePath, data);

            // 复读校验
            byte[] verify = System.IO.File.ReadAllBytes(exePath);
            foreach (var s in sites)
            {
                long off = s.Offset;
                if (s.Offset >= verify.Length)
                {
                    long mapped;
                    PeUtil.RvaToOffset(verify, s.Offset, out mapped);
                    off = mapped;
                }
                if (CheckSite(verify, off, s) != SiteState.Patched)
                {
                    log.Add("[-] 复读校验失败: 0x" + off.ToString("X"));
                    return false;
                }
            }
            log.Add("[+] 补丁写入完成并复读校验通过（" + plan.Count + " 处）");
            log.Add("[+] 新 SHA256: " + PeUtil.Sha256Hex(verify));
            return true;
        }

        private static byte[] BytesAt2(byte[] data, long off, int len)
        {
            var b = new byte[len];
            for (int i = 0; i < len; i++) b[i] = (off + i < data.Length) ? data[off + i] : (byte)0;
            return b;
        }

        // 还原 .bak
        public static bool Revert(string exePath, IList<string> log)
        {
            string bak = exePath + ".bak";
            if (!System.IO.File.Exists(bak)) { log.Add("[-] 备份不存在: " + bak); return false; }
            System.IO.File.Copy(bak, exePath, true);
            log.Add("[+] 已从备份还原 -> " + exePath);
            log.Add("[+] SHA256: " + PeUtil.Sha256File(exePath));
            return true;
        }
    }
}
