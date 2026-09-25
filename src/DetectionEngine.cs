// DetectionEngine.cs — 统一检测引擎（接口契约 + 指纹库 + 缓存 + paths.json 自定义路径）
// C# 5 / .NET Framework 4.x compatible.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Seep.Core
{
    // ─── 检测结果 ───
    public class DetectionResult
    {
        public string State;                   // patched / original / ready / missing / unknown
        public string Detail;                  // 人话描述（Badge tooltip）
        public List<string> Evidence = new List<string>();  // 判定依据

        public static DetectionResult Of(string state, string detail)
        {
            return new DetectionResult { State = state, Detail = detail };
        }
    }

    // ─── 统一检测接口 ───
    public interface ITargetDetector
    {
        string Key { get; }                    // "bandizip" / "ut" / "seer" / "listary" / "snipaste"
        List<string> Locate();                 // 安装目录定位（进程嗅探→注册表→paths.json→常见路径）
        DetectionResult Detect(string dir);    // 确定性状态判定
    }

    // ─── paths.json 自定义路径持久化 ───
    public static class CustomPaths
    {
        private static readonly string FilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "paths.json");
        private static Dictionary<string, List<string>> _cache;

        public static Dictionary<string, List<string>> Load()
        {
            if (_cache != null) return _cache;
            _cache = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(FilePath))
                {
                    string json = File.ReadAllText(FilePath);
                    ParseAndFill(json, _cache);
                }
            }
            catch { }
            return _cache;
        }

        public static void Save(string key, string path)
        {
            var dict = Load();
            List<string> list;
            if (!dict.TryGetValue(key, out list))
            {
                list = new List<string>();
                dict[key] = list;
            }
            if (!list.Contains(path)) list.Insert(0, path);
            Save();
        }

        public static List<string> Get(string key)
        {
            List<string> list;
            return Load().TryGetValue(key, out list) ? list : new List<string>();
        }

        private static void Save()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("{\n");
                bool first = true;
                foreach (var kv in _cache)
                {
                    if (!first) sb.Append(",\n");
                    sb.Append("  \"").Append(kv.Key).Append("\": [");
                    for (int i = 0; i < kv.Value.Count; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        sb.Append("\"").Append(kv.Value[i].Replace("\\", "\\\\")).Append("\"");
                    }
                    sb.Append("]");
                    first = false;
                }
                sb.Append("\n}\n");
                File.WriteAllText(FilePath, sb.ToString());
            }
            catch { }
        }

        private static void ParseAndFill(string json, Dictionary<string, List<string>> dict)
        {
            // 手写轻量解析（无外部依赖）
            int i = 0;
            while ((i = json.IndexOf('"', i)) >= 0)
            {
                int keyEnd = json.IndexOf('"', i + 1);
                if (keyEnd < 0) break;
                string key = json.Substring(i + 1, keyEnd - i - 1);
                int colon = json.IndexOf(':', keyEnd);
                if (colon < 0) break;
                int arrStart = json.IndexOf('[', colon);
                int arrEnd = json.IndexOf(']', arrStart);
                if (arrStart < 0 || arrEnd < 0) { i = keyEnd; continue; }

                var list = new List<string>();
                string arrBody = json.Substring(arrStart + 1, arrEnd - arrStart - 1);
                int j = 0;
                while ((j = arrBody.IndexOf('"', j)) >= 0)
                {
                    int strEnd = arrBody.IndexOf('"', j + 1);
                    if (strEnd < 0) break;
                    string val = arrBody.Substring(j + 1, strEnd - j - 1).Replace("\\\\", "\\");
                    if (Directory.Exists(val) || File.Exists(val)) list.Add(val);
                    j = strEnd + 1;
                }
                if (list.Count > 0) dict[key] = list;
                i = arrEnd;
            }
        }
    }

    // ─── 检测结果缓存 ───
    public class CachedDetection
    {
        public string Key;
        public string State;
        public string Path;
        public string Sha256;
        public long FileSize;
        public DateTime Mtime;
        public DateTime Timestamp;
        public string Detail;
    }

    public static class DetectionCache
    {
        private static readonly string FilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "detection_cache.json");
        private static readonly TimeSpan Ttl = TimeSpan.FromHours(24);
        private static Dictionary<string, CachedDetection> _cache;

        public static Dictionary<string, CachedDetection> Load()
        {
            if (_cache != null) return _cache;
            _cache = new Dictionary<string, CachedDetection>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(FilePath))
                {
                    string json = File.ReadAllText(FilePath);
                    ParseAndFill(json, _cache);
                }
            }
            catch { }
            return _cache;
        }

        public static CachedDetection Get(string key)
        {
            CachedDetection c;
            if (Load().TryGetValue(key, out c))
            {
                if (DateTime.Now - c.Timestamp < Ttl) return c;
            }
            return null;
        }

        // 缓存有效性校验：文件 mtime + size 未变
        public static CachedDetection GetValid(string key, string currentPath)
        {
            var c = Get(key);
            if (c == null || c.Path != currentPath) return null;
            if (string.IsNullOrEmpty(c.Path)) return c; // missing 类缓存无需文件校验
            try
            {
                var fi = new FileInfo(c.Path);
                if (!fi.Exists) return null;
                if (fi.Length != c.FileSize) return null;
                if (Math.Abs((fi.LastWriteTime - c.Mtime).TotalSeconds) > 2) return null;
                return c;
            }
            catch { return null; }
        }

        public static void Put(CachedDetection entry)
        {
            Load()[entry.Key] = entry;
            Save();
        }

        private static void Save()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("{\n");
                bool first = true;
                foreach (var kv in _cache)
                {
                    if (!first) sb.Append(",\n");
                    var c = kv.Value;
                    sb.Append("  \"").Append(kv.Key).Append("\": {")
                      .Append("\"state\":\"").Append(c.State).Append("\",")
                      .Append("\"path\":\"").Append((c.Path ?? "").Replace("\\", "\\\\")).Append("\",")
                      .Append("\"detail\":\"").Append((c.Detail ?? "").Replace("\"", "'")).Append("\",")
                      .Append("\"sha256\":\"").Append(c.Sha256 ?? "").Append("\",")
                      .Append("\"size\":").Append(c.FileSize).Append(",")
                      .Append("\"mtime\":\"").Append(c.Mtime.ToString("o")).Append("\",")
                      .Append("\"ts\":\"").Append(c.Timestamp.ToString("o")).Append("\"}")
                      ;
                    first = false;
                }
                sb.Append("\n}\n");
                File.WriteAllText(FilePath, sb.ToString());
            }
            catch { }
        }

        private static void ParseAndFill(string json, Dictionary<string, CachedDetection> dict)
        {
            int i = 0;
            while ((i = json.IndexOf('"', i)) >= 0)
            {
                int keyEnd = json.IndexOf('"', i + 1);
                if (keyEnd < 0) break;
                string key = json.Substring(i + 1, keyEnd - i - 1);
                int objStart = json.IndexOf('{', keyEnd);
                int objEnd = json.IndexOf('}', objStart);
                if (objStart < 0 || objEnd < 0) { i = keyEnd; continue; }

                var body = json.Substring(objStart, objEnd - objStart);
                var c = new CachedDetection { Key = key };
                c.State = ExtractField(body, "state");
                c.Path = ExtractField(body, "path");
                c.Detail = ExtractField(body, "detail");
                c.Sha256 = ExtractField(body, "sha256");

                string sz = ExtractField(body, "size");
                long szL;
                if (long.TryParse(sz, out szL)) c.FileSize = szL;

                string mt = ExtractField(body, "mtime");
                DateTime mtD;
                if (DateTime.TryParse(mt, out mtD)) c.Mtime = mtD;

                string ts = ExtractField(body, "ts");
                DateTime tsD;
                if (DateTime.TryParse(ts, out tsD)) c.Timestamp = tsD;

                if (!string.IsNullOrEmpty(c.State)) dict[key] = c;
                i = objEnd;
            }
        }

        private static string ExtractField(string json, string field)
        {
            string pat = "\"" + field + "\":";
            int i = json.IndexOf(pat);
            if (i < 0) return null;
            i += pat.Length;
            while (i < json.Length && json[i] == ' ') i++;
            if (i >= json.Length) return null;
            if (json[i] == '"')
            {
                i++;
                var sb = new StringBuilder();
                while (i < json.Length && json[i] != '"')
                {
                    if (json[i] == '\\' && i + 1 < json.Length) { sb.Append(json[i + 1]); i += 2; }
                    else sb.Append(json[i++]);
                }
                return sb.ToString();
            }
            int j = i;
            while (j < json.Length && json[j] != ',' && json[j] != '}') j++;
            return json.Substring(i, j - i).Trim();
        }
    }
}
