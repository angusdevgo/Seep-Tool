// SnipasteModule.cs — Snipaste 2.11.3 PRO 激活码生成与公钥修补模块
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Seep.Core;

namespace Seep.Modules
{
    public static class SnipasteModule
    {
        public const string Name = "Snipaste";
        public const string ExeName = "Snipaste.exe";

        public static readonly byte[] OfficialPubkey =
            PeUtil.HexToBytes("86a6313855512c692b7f44a7041a86d02890544923714acaeeb29e52883c9060");

        public static string KeypairPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keypair.bin");

        public static bool HasKeypair()
        {
            if (File.Exists(KeypairPath)) return true;
            string alt = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Snipaste", "tools", "keypair.bin");
            if (File.Exists(alt))
            {
                try { File.Copy(alt, KeypairPath, true); return true; } catch { return true; }
            }
            return false;
        }

        public static List<string> Locate()
        {
            return TargetLocator.FindSnipaste();
        }

        // persist 补丁点（与 Snipaste/src/keygen/algo.py 一致，RVA - 0xC00 + 2）
        public static readonly long[] PersistOffsets = new long[] { 0x245A14, 0x245ADA, 0x245B12, 0x245B22 };
        // 官方公钥密文 9 处补丁首偏移
        public const long PubkeyPatchFirstOffset = 0x2493C8;

        public static string CheckState(string dir, IList<string> log)
        {
            string exe = Path.Combine(dir, ExeName);
            if (!File.Exists(exe)) { log.Add("[-] 未找到 " + ExeName); return "missing"; }
            log.Add("[*] " + exe);
            try
            {
                byte[] d = File.ReadAllBytes(exe);

                // 1. 校验 persist 补丁（4 处失败出口立即数应为 0）
                int persistOk = 0;
                foreach (long off in PersistOffsets)
                {
                    long realOff = off - 0xC00 + 2;
                    if (realOff + 4 <= d.Length &&
                        d[realOff] == 0 && d[realOff + 1] == 0 && d[realOff + 2] == 0 && d[realOff + 3] == 0)
                        persistOk++;
                }

                // 2. 校验公钥是否已替换为本地 keypair 公钥（非官方）
                bool pubkeyPatched = false;
                if (HasKeypair())
                {
                    byte[] kp = File.ReadAllBytes(KeypairPath);
                    byte[] localPub = new byte[32];
                    Array.Copy(kp, 32, localPub, 0, 32);
                    // 官方公钥密文 XOR keystream = 明文公钥；若 exe 内解出的公钥 != 官方 = 已替换
                    // 简化校验：比较第 1 处补丁点的 4 字节，官方为 02d60506
                    byte[] officialCipherHead = PeUtil.HexToBytes("02 d6 05 06");
                    long off1 = PubkeyPatchFirstOffset;
                    bool isOfficial = (d[off1] == officialCipherHead[0] && d[off1+1] == officialCipherHead[1]
                                    && d[off1+2] == officialCipherHead[2] && d[off1+3] == officialCipherHead[3]);
                    pubkeyPatched = !isOfficial;
                }

                if (persistOk == PersistOffsets.Length && pubkeyPatched)
                {
                    log.Add("[+] Snipaste 已完成公钥替换与启动持久化（4/4 persist + pubkey patch）");
                    return "patched";
                }
                else if (persistOk == PersistOffsets.Length || pubkeyPatched)
                {
                    log.Add(string.Format("[!] 部分修补: persist {0}/4, pubkey {1}", persistOk, pubkeyPatched ? "已替换" : "官方"));
                    return "original";
                }
                else
                {
                    log.Add("[*] Snipaste 为官方原版（未打公钥/persist 补丁）");
                    return "original";
                }
            }
            catch (Exception ex)
            {
                log.Add("[-] 检测异常: " + ex.Message);
                return "unknown";
            }
        }

        // 设备码与哈希
        public static string ReadMachineGuid()
        {
            using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
            {
                var v = k == null ? null : k.GetValue("MachineGuid") as string;
                if (string.IsNullOrEmpty(v)) throw new InvalidOperationException("无法读取 MachineGuid");
                return v;
            }
        }

        public static string ComputeMachineId(string machineGuid)
        {
            byte[] digest = Blake2s128(Encoding.UTF8.GetBytes("Snipaste 2" + "1" + machineGuid));
            byte[] tail = new byte[6];
            Array.Copy(digest, 10, tail, 0, 6);
            var hex = new StringBuilder(12);
            foreach (var b in tail) hex.Append(b.ToString("X2"));
            string h = hex.ToString();
            return h.Substring(0, 4) + "-" + h.Substring(4) + AdjacentCharDiffSum(h) + "1";
        }

        public static string AdjacentCharDiffSum(string s)
        {
            if (string.IsNullOrEmpty(s)) return "0";
            int n = s.Length;
            if (n == 1) return s;
            int total = 0;
            for (int i = 1; i < n; i++) total += Math.Abs(s[i] - s[i - 1]);
            return s[total % n].ToString();
        }

        // BLAKE2s-128
        static readonly uint[] IV = new uint[]
        {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        };
        static readonly int[] Sigma = new int[]
        {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,
            11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,
            7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,
            9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,
            2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,
            12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,
            13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,
            6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,
            10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0,
        };

        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

        static void G(uint[] v, int a, int b, int c, int d, uint x, uint y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = Rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Rotr(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = Rotr(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = Rotr(v[b] ^ v[c], 7);
        }

        public static byte[] Blake2s128(byte[] input)
        {
            uint[] h = (uint[])IV.Clone();
            h[0] ^= 0x01010000u;
            h[0] ^= 16u;

            const int blockSize = 64;
            int remaining = input.Length;
            int offset = 0;
            byte[] block = new byte[blockSize];

            Action<bool, ulong> compress = delegate(bool isLast, ulong tBlock)
            {
                uint[] m = new uint[16];
                for (int i = 0; i < 16; i++)
                    m[i] = BitConverter.ToUInt32(block, i * 4);
                uint[] v = new uint[16];
                Array.Copy(h, v, 8);
                Array.Copy(IV, 0, v, 8, 8);
                v[12] ^= (uint)tBlock;
                v[13] ^= (uint)(tBlock >> 32);
                if (isLast) v[14] ^= 0xFFFFFFFFu;
                for (int r = 0; r < 10; r++)
                {
                    int s = r * 16;
                    G(v, 0, 4, 8, 12, m[Sigma[s + 0]], m[Sigma[s + 1]]);
                    G(v, 1, 5, 9, 13, m[Sigma[s + 2]], m[Sigma[s + 3]]);
                    G(v, 2, 6, 10, 14, m[Sigma[s + 4]], m[Sigma[s + 5]]);
                    G(v, 3, 7, 11, 15, m[Sigma[s + 6]], m[Sigma[s + 7]]);
                    G(v, 0, 5, 10, 15, m[Sigma[s + 8]], m[Sigma[s + 9]]);
                    G(v, 1, 6, 11, 12, m[Sigma[s + 10]], m[Sigma[s + 11]]);
                    G(v, 2, 7, 8, 13, m[Sigma[s + 12]], m[Sigma[s + 13]]);
                    G(v, 3, 4, 9, 14, m[Sigma[s + 14]], m[Sigma[s + 15]]);
                }
                for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
            };

            if (remaining == 0)
            {
                compress(true, 0);
            }
            else
            {
                ulong t = 0;
                while (remaining > blockSize)
                {
                    Array.Copy(input, offset, block, 0, blockSize);
                    t += blockSize;
                    compress(false, t);
                    offset += blockSize;
                    remaining -= blockSize;
                }
                Array.Clear(block, 0, blockSize);
                Array.Copy(input, offset, block, 0, remaining);
                compress(true, (ulong)input.Length);
            }

            byte[] outBytes = new byte[16];
            for (int i = 0; i < 4; i++)
                Array.Copy(BitConverter.GetBytes(h[i]), 0, outBytes, i * 4, 4);
            return outBytes;
        }

        public static string BuildActivationCode(string name, string email, string plan, int days, string dom, IList<string> log)
        {
            string guid = ReadMachineGuid();
            string mid = ComputeMachineId(guid);
            log.Add("[*] MachineGuid: " + guid);
            log.Add("[+] 期望设备码: " + mid);

            string script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "snipaste_keygen.py");
            if (!File.Exists(script))
                throw new InvalidOperationException("缺少算号桥: " + script);

            var psi = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = "\"" + script + "\" " + days,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                p.WaitForExit(8000);
                if (stdout.Contains("\"ok\": true") && stdout.Contains("\"code\": \""))
                {
                    int s = stdout.IndexOf("\"code\": \"") + 9;
                    int e = stdout.IndexOf("\"", s);
                    string code = stdout.Substring(s, e - s);
                    log.Add("[+] Ed25519 签名与 Gzip 封装完成！");
                    return code;
                }
                else
                {
                    throw new InvalidOperationException("算号脚本异常: " + stdout);
                }
            }
        }
    }
}
