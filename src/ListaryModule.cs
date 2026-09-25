// ListaryModule.cs — Listary Pro 算号模块（算法全还原，无补丁依赖）
// 逻辑来源: Listary/src/LicenseAlgo.cs（逆向自 Listary.Core.Pro.LicenseChecker）
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Seep.Modules
{
    public static class ListaryModule
    {
        public const string Name = "Listary Pro";
        public const string ExeName = "Listary.exe";

        public const string CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        public const string SALT = "Listaryl047YpyZUU5M";
        public const int LICENSE_LEN = 192;
        public const int CHECK_POS = 160;
        public const int CHECK_LEN = 19;

        public static readonly HashSet<string> Blacklist = new HashSet<string>(StringComparer.Ordinal)
        {
            "710ab287938947d40d8d5857f663753c",
            "c109e3ee2bd74d5b88de647eebc2fd0e",
            "1229667d8ecc0616bffd7740c4323f9a",
            "b05744004c455956e5408a9b1c95b047",
            "57a39722f37db4727e0f425156f3b2d7",
            "0c16a79693d8d58e1e5b81f48f9ba64b",
        };

        // H1: 多项式滚动 h = h*43 + c
        static uint H1(string s)
        {
            uint h = 0;
            for (int i = 0; i < s.Length; i++) h = h * 43 + (uint)s[i];
            return h;
        }

        // H2: ELF 风格
        static uint H2(string s)
        {
            uint h = 0;
            for (int i = 0; i < s.Length; i++)
            {
                h = (h << 4) + (uint)s[i];
                uint g = h & 0xF0000000u;
                if (g != 0) { h ^= (g >> 24); h ^= g; }
            }
            return h;
        }

        // H3: 4 轮异或
        static uint H3(string s)
        {
            uint h = 0;
            for (int r = 0; r < 4; r++)
                for (int j = r; j < s.Length; j += 4)
                    h ^= ((uint)s[j]) << ((r * 8) % 32);
            return h;
        }

        static BigInteger BuildV(string emailLower)
        {
            return ((BigInteger)H1(emailLower) << 64)
                 | ((BigInteger)H2(emailLower) << 32)
                 | (BigInteger)H3(emailLower);
        }

        public static string Checksum(string email)
        {
            string el = (email ?? "").ToLowerInvariant().Trim();
            BigInteger v = BuildV(el);
            var sb = new StringBuilder(CHECK_LEN);
            for (int i = 0; i < CHECK_LEN; i++)
            {
                int shift = 96 - (i + 1) * 5;
                sb.Append(CHARSET[(int)((v >> shift) & 31)]);
            }
            return sb.ToString();
        }

        private static readonly Random _rnd = new Random();

        public static string Generate(string email)
        {
            string el = (email ?? "").ToLowerInvariant().Trim();
            if (el.Length == 0) throw new ArgumentException("email 为空");
            string ck = Checksum(el);
            var sb = new StringBuilder(LICENSE_LEN);
            lock (_rnd)
            {
                for (int i = 0; i < CHECK_POS; i++) sb.Append(CHARSET[_rnd.Next(CHARSET.Length)]);
                sb.Append(ck);
                for (int i = 0; i < LICENSE_LEN - CHECK_POS - CHECK_LEN; i++) sb.Append(CHARSET[_rnd.Next(CHARSET.Length)]);
            }
            return sb.ToString();
        }

        public static bool Verify(string email, string license)
        {
            if (email == null || license == null || license.Length != LICENSE_LEN) return false;
            string el = email.ToLowerInvariant().Trim();
            if (el.Length == 0) return false;
            if (license.Substring(CHECK_POS, CHECK_LEN) != Checksum(el)) return false;
            return !Blacklist.Contains(MD5Hex(el + SALT));
        }

        public static string MD5Hex(string s)
        {
            using (var md5 = MD5.Create())
            {
                byte[] b = md5.ComputeHash(Encoding.UTF8.GetBytes(s));
                var sb = new StringBuilder(b.Length * 2);
                foreach (var x in b) sb.Append(x.ToString("x2"));
                return sb.ToString();
            }
        }

        static readonly string[] MailDomains = new string[]
        {
            "gmail.com", "outlook.com", "qq.com", "163.com", "foxmail.com",
            "proton.me", "mail.com", "example.com", "icloud.com", "hotmail.com"
        };
        static readonly string MailAlnum = "abcdefghijklmnopqrstuvwxyz0123456789";

        public static string RandomEmail()
        {
            var sb = new StringBuilder("user");
            lock (_rnd)
            {
                for (int i = 0; i < 8; i++) sb.Append(MailAlnum[_rnd.Next(MailAlnum.Length)]);
                sb.Append('@').Append(MailDomains[_rnd.Next(MailDomains.Length)]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 读取 Listary 6 的 Preferences.json，校验 ProLicense 是否已写入且通过算法自检。
        /// 配置路径: %APPDATA%\Listary\UserProfile\Settings\Preferences.json
        /// 节点: Settings.Listary5.ProLicense { Name, Email, Key }
        /// </summary>
        public static string CheckLicenseState(IList<string> log)
        {
            string prefsPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Listary", "UserProfile", "Settings", "Preferences.json");

            if (!System.IO.File.Exists(prefsPath))
            {
                log.Add("[*] 未找到 Listary 配置文件: " + prefsPath);
                return "original";
            }

            try
            {
                string json = System.IO.File.ReadAllText(prefsPath);
                // Listary 的 JSON 键是扁平的（如 "Listary5.ProLicense.Name"）
                string name = ExtractJsonField(json, "Listary5.ProLicense.Name");
                string email = ExtractJsonField(json, "Listary5.ProLicense.Email");
                string key = ExtractJsonField(json, "Listary5.ProLicense.Key");

                if (string.IsNullOrEmpty(key) || key.Length < 32)
                {
                    log.Add("[*] Listary ProLicense 未写入或为空");
                    return "original";
                }

                log.Add("[*] Listary ProLicense 已配置:");
                log.Add("    Name : " + name);
                log.Add("    Email: " + email);
                log.Add("    Key  : " + key.Substring(0, Math.Min(40, key.Length)) + "...");

                // 用还原的算法做本地校验
                bool pass = Verify(email, key);
                log.Add(pass
                    ? "[+] 算法自检 PASS: 该授权凭据已通过 96-bit 校验段验证（已激活）"
                    : "[-] 算法自检 FAIL: 授权凭据不匹配（可能为无效密钥）");
                return pass ? "patched" : "original";
            }
            catch (Exception ex)
            {
                log.Add("[-] 读取配置失败: " + ex.Message);
                return "unknown";
            }
        }

        // 简易 JSON 字段提取（支持转义）
        static string ExtractJsonField(string json, string field)
        {
            int i = json.IndexOf("\"" + field + "\"");
            if (i < 0) return null;
            i = json.IndexOf(':', i);
            if (i < 0) return null;
            i++;
            while (i < json.Length && json[i] == ' ') i++;
            if (i >= json.Length || json[i] != '"') return null;
            i++;
            var sb = new StringBuilder();
            while (i < json.Length && json[i] != '"')
            {
                if (json[i] == '\\' && i + 1 < json.Length)
                {
                    char n = json[i + 1];
                    if (n == 'n') sb.Append('\n');
                    else if (n == 't') sb.Append('\t');
                    else sb.Append(n);
                    i += 2;
                }
                else sb.Append(json[i++]);
            }
            return sb.ToString();
        }
    }
}
