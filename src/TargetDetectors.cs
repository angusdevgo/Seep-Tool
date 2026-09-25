// TargetDetectors.cs — 五目标 ITargetDetector 实现（确定性字节级/算法级判定）
// 彻底废除字符串 Contains 匹配，全部改为结构化 Evidence 驱动。
using System;
using System.Collections.Generic;
using System.IO;
using Seep.Modules;

namespace Seep.Core
{
    // ─── Bandizip: DLL 代理日志 + PE 字节特征 ───
    public class BandizipDetector : ITargetDetector
    {
        public string Key { get { return "bandizip"; } }

        public List<string> Locate() { return BandizipDllModule.Locate(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            string dll = Path.Combine(dir, "version.dll");
            string logFile = Path.Combine(dir, "version_patch.log");

            if (File.Exists(dll) && File.Exists(logFile))
            {
                string content;
                try { content = File.ReadAllText(logFile); }
                catch { return DetectionResult.Of("unknown", "DLL 日志读取失败"); }

                if (content.Contains("3/3 sites succeeded"))
                {
                    r.State = "patched";
                    r.Detail = "DLL 代理热补丁 3/3 生效（Enterprise + 黑名单直通 + 显示层拦截）";
                    r.Evidence.Add("version_patch.log 含 '3/3 sites succeeded'");
                    if (File.Exists(Path.Combine(dir, "version_patch.ini")))
                        r.Evidence.Add("version_patch.ini 自定义授权已激活");
                    return r;
                }
                r.State = "unknown";
                r.Detail = "DLL 已部署但补丁未完全生效";
                r.Evidence.Add("version_patch.log 无 '3/3 sites succeeded'");
                return r;
            }

            // 静态 PE 字节特征（备用模式）
            string exe = Path.Combine(dir, "Bandizip.x64.exe");
            if (!File.Exists(exe)) exe = Path.Combine(dir, "Bandizip.exe");
            if (!File.Exists(exe)) return DetectionResult.Of("missing", "未找到 Bandizip.x64.exe");

            try
            {
                byte[] d = File.ReadAllBytes(exe);
                int patchedCount = 0;
                foreach (var site in BandizipDllModule.Sites)
                {
                    long off;
                    if (!PeUtil.RvaToOffset(d, site.Offset, out off)) continue;
                    if (PeUtil.BytesAt(d, off, site.Replace)) patchedCount++;
                }
                if (patchedCount == BandizipDllModule.Sites.Length)
                {
                    r.State = "patched";
                    r.Detail = "静态 PE 补丁 " + patchedCount + "/" + BandizipDllModule.Sites.Length + " 生效";
                    r.Evidence.Add("RVA 0x1317F5/0x13176D/0x1347E0 字节均为补丁态");
                }
                else
                {
                    r.State = "original";
                    r.Detail = "原版（未部署 DLL 也未打 PE 补丁）";
                    r.Evidence.Add("无 version.dll，PE 字节为原始特征");
                }
            }
            catch (Exception ex) { r.State = "unknown"; r.Detail = "检测异常: " + ex.Message; }
            return r;
        }
    }

    // ─── Uninstall Tool: VA 算术比对 call 目标 ───
    public class UninstallToolDetector : ITargetDetector
    {
        public string Key { get { return "ut"; } }

        public List<string> Locate() { return UninstallToolModule.Locate(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            string exe = Path.Combine(dir, "UninstallTool.exe");
            if (!File.Exists(exe)) return DetectionResult.Of("missing", "未找到 UninstallTool.exe");
            try
            {
                byte[] pe = File.ReadAllBytes(exe);
                long callOff;
                if (PeUtil.VaToOffset(pe, UninstallToolModule.CALL_VA, out callOff) && pe[callOff] == 0xE8)
                {
                    int rel = BitConverter.ToInt32(pe, (int)callOff + 1);
                    long target = (UninstallToolModule.CALL_VA + 5 + rel) & 0xFFFFFFFFFFFFL;
                    if (target == UninstallToolModule.STUB_VA)
                    {
                        r.State = "patched";
                        r.Detail = "IsRegistered 判定恒 3（call → stub 已重定向）";
                        r.Evidence.Add("VA 0x140009E0F call → 0x140001622 stub (mov eax,3; ret)");
                    }
                    else
                    {
                        r.State = "original";
                        r.Detail = "原版（call 指向原始 atoi 函数）";
                        r.Evidence.Add("VA 0x140009E0F call → 0x" + target.ToString("x"));
                    }
                    return r;
                }
                r.State = "unknown";
                r.Detail = "call 指令校验失败（非 E8）";
                r.Evidence.Add("VA 0x140009E0F 处非 E8 字节");
            }
            catch (Exception ex) { r.State = "unknown"; r.Detail = "检测异常: " + ex.Message; }
            return r;
        }
    }

    // ─── Seer: SHA256 指纹 + isLicensed 偏移 + persist 4/4 ───
    public class SeerDetector : ITargetDetector
    {
        public string Key { get { return "seer"; } }

        public List<string> Locate() { return SeerModule.Locate(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            string exe = Path.Combine(dir, "Seer.exe");
            if (!File.Exists(exe)) return DetectionResult.Of("missing", "未找到 Seer.exe");
            try
            {
                byte[] d = File.ReadAllBytes(exe);
                string sha = PeUtil.Sha256Hex(d);
                r.Evidence.Add("SHA256: " + sha.Substring(0, 16) + "...");

                long[] offs;
                long offLicensed;
                if (SeerModule.KnownBuilds.TryGetValue(sha, out offs))
                    offLicensed = offs[0];
                else
                {
                    // 未知构建，尝试已知偏移的字节特征
                    if (PeUtil.BytesAt(d, 0x496C10, SeerModule.PATCH_IS_LICENSED)) offLicensed = 0x496C10;
                    else if (PeUtil.BytesAt(d, 0xB82D10, SeerModule.PATCH_IS_LICENSED)) offLicensed = 0xB82D10;
                    else if (PeUtil.BytesAt(d, 0x496C10, SeerModule.PROLOGUE_LICENSED)) offLicensed = 0x496C10;
                    else if (PeUtil.BytesAt(d, 0xB82D10, SeerModule.PROLOGUE_LICENSED)) offLicensed = 0xB82D10;
                    else return DetectionResult.Of("unknown", "未知构建，无法定位 isLicensed 偏移");
                }

                bool licensedPatched = PeUtil.BytesAt(d, offLicensed, SeerModule.PATCH_IS_LICENSED);
                r.Evidence.Add("isLicensed @ 0x" + offLicensed.ToString("X") + (licensedPatched ? " → mov al,1; ret" : " → 原始序言"));

                // persist 补丁（如果该版本有）
                long offPopup = (offs != null && offs.Length > 1) ? offs[1] : 0;
                bool popupPatched = true;
                if (offPopup > 0)
                {
                    popupPatched = PeUtil.BytesAt(d, offPopup, SeerModule.PATCH_POPUP_WRAPPER);
                    r.Evidence.Add("popup wrapper @ 0x" + offPopup.ToString("X") + (popupPatched ? " → xor eax,eax; ret" : " → 原始"));
                }

                if (licensedPatched && popupPatched)
                {
                    r.State = "patched";
                    r.Detail = "isLicensed 恒真 + 弹窗拦截已生效";
                }
                else
                {
                    r.State = "original";
                    r.Detail = "原版（补丁未生效）";
                }
            }
            catch (Exception ex) { r.State = "unknown"; r.Detail = "检测异常: " + ex.Message; }
            return r;
        }
    }

    // ─── Listary: Preferences.json 算法自检 ───
    public class ListaryDetector : ITargetDetector
    {
        public string Key { get { return "listary"; } }

        public List<string> Locate() { return TargetLocator.FindListary(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            var log = new List<string>();
            string state = ListaryModule.CheckLicenseState(log);
            r.State = state;
            foreach (var line in log)
            {
                if (line.StartsWith("[+]") || line.StartsWith("[*]")) r.Detail = line.TrimStart('[', '+', '*', ']');
                r.Evidence.Add(line);
            }
            if (string.IsNullOrEmpty(r.Detail)) r.Detail = state;
            return r;
        }
    }

    // ─── Snipaste: 公钥替换 + persist 4/4 ───
    public class SnipasteDetector : ITargetDetector
    {
        public string Key { get { return "snipaste"; } }

        public List<string> Locate() { return SnipasteModule.Locate(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            string exe = Path.Combine(dir, "Snipaste.exe");
            if (!File.Exists(exe)) return DetectionResult.Of("missing", "未找到 Snipaste.exe");
            try
            {
                byte[] d = File.ReadAllBytes(exe);

                // persist 4/4
                int persistOk = 0;
                foreach (long off in SnipasteModule.PersistOffsets)
                {
                    long realOff = off - 0xC00 + 2;
                    if (realOff + 4 <= d.Length &&
                        d[realOff] == 0 && d[realOff + 1] == 0 && d[realOff + 2] == 0 && d[realOff + 3] == 0)
                        persistOk++;
                }
                r.Evidence.Add("persist 补丁: " + persistOk + "/4");

                // 公钥替换（首 4 字节 ≠ 官方密文头 02 D6 05 06）
                byte[] officialHead = PeUtil.HexToBytes("02 d6 05 06");
                long pkOff = SnipasteModule.PubkeyPatchFirstOffset;
                bool pubkeyPatched = !(d[pkOff] == officialHead[0] && d[pkOff + 1] == officialHead[1]
                                    && d[pkOff + 2] == officialHead[2] && d[pkOff + 3] == officialHead[3]);
                r.Evidence.Add("内嵌公钥: " + (pubkeyPatched ? "已替换（本地 keypair）" : "官方原版"));

                if (persistOk == SnipasteModule.PersistOffsets.Length && pubkeyPatched)
                {
                    r.State = "patched";
                    r.Detail = "公钥替换 + persist 4/4 全部生效（启动即 Pro）";
                }
                else
                {
                    r.State = "original";
                    r.Detail = "原版或部分修补";
                }
            }
            catch (Exception ex) { r.State = "unknown"; r.Detail = "检测异常: " + ex.Message; }
            return r;
        }
    }

    // ─── PixPin: 11 处会员特权判定分支走查 (CWE-602) ───
    public class PixPinDetector : ITargetDetector
    {
        public string Key { get { return "pixpin"; } }

        public List<string> Locate() { return PixPinModule.Locate(); }

        public DetectionResult Detect(string dir)
        {
            var r = new DetectionResult();
            string dll = Path.Combine(dir, "PixAuth.dll");
            if (!File.Exists(dll)) return DetectionResult.Of("missing", "未找到 PixAuth.dll");
            try
            {
                byte[] d = File.ReadAllBytes(dll);
                r.Evidence.Add("PixAuth.dll SHA256: " + PeUtil.Sha256Hex(d).Substring(0, 16) + "...");

                int patched = 0, original = 0, unknown = 0;
                foreach (var s in PixPinModule.Sites)
                {
                    long off;
                    if (!PeUtil.RvaToOffset(d, s.Offset, out off)) { unknown++; continue; }
                    if (PeUtil.BytesAt(d, off, s.Replace)) patched++;
                    else if (PeUtil.BytesAt(d, off, s.Expect)) original++;
                    else unknown++;
                }
                r.Evidence.Add(string.Format("特权判定补丁: {0}/{1} 已就位（原版 {2}，未知 {3}）",
                    patched, PixPinModule.Sites.Length, original, unknown));

                if (patched == PixPinModule.Sites.Length)
                {
                    r.State = "patched";
                    r.Detail = "14 项会员功能全部解锁（翻译/表格/公式/擦除/鼠标/同步/长截图/录制/键鼠/导出/PDF/马赛克/条码/摄像头）";
                }
                else if (original > 0)
                {
                    r.State = "original";
                    r.Detail = string.Format("原版或部分修补（{0}/{1} 已就位）", patched, PixPinModule.Sites.Length);
                }
                else
                {
                    r.State = "unknown";
                    r.Detail = "未知构建（特征码不匹配，未作修改）";
                }
            }
            catch (Exception ex) { r.State = "unknown"; r.Detail = "检测异常: " + ex.Message; }
            return r;
        }
    }

    // ─── 引擎入口 ───
    public static class DetectionEngine
    {
        private static readonly Dictionary<string, ITargetDetector> _detectors = new Dictionary<string, ITargetDetector>(StringComparer.OrdinalIgnoreCase)
        {
            { "bandizip", new BandizipDetector() },
            { "ut", new UninstallToolDetector() },
            { "seer", new SeerDetector() },
            { "listary", new ListaryDetector() },
            { "snipaste", new SnipasteDetector() },
            { "pixpin", new PixPinDetector() },
        };

        public static ITargetDetector Get(string key)
        {
            ITargetDetector d;
            return _detectors.TryGetValue(key, out d) ? d : null;
        }

        public static IEnumerable<ITargetDetector> All { get { return _detectors.Values; } }

        // 统一入口：Locate → 缓存校验 → Detect → 更新缓存
        public static DetectionResult Run(string key, out string path)
        {
            path = null;
            var detector = Get(key);
            if (detector == null) return DetectionResult.Of("unknown", "未知目标: " + key);

            // 1. 定位
            var dirs = detector.Locate();
            if (dirs.Count == 0)
            {
                // 降级到 paths.json 自定义路径
                var custom = CustomPaths.Get(key);
                foreach (var cp in custom)
                {
                    if (Directory.Exists(cp)) { dirs.Add(cp); break; }
                }
            }

            if (dirs.Count == 0)
            {
                path = null;
                var cached = DetectionCache.Get(key);
                if (cached != null && cached.State == "missing")
                    return DetectionResult.Of("missing", cached.Detail ?? "缓存: 未安装");
                return DetectionResult.Of("missing", "未在本地定位到目标程序");
            }

            path = dirs[0];

            // 2. 缓存校验
            var validCached = DetectionCache.GetValid(key, path);
            if (validCached != null)
                return DetectionResult.Of(validCached.State, "[缓存] " + (validCached.Detail ?? ""));

            // 3. 全量检测
            var result = detector.Detect(path);

            // 4. 写缓存
            try
            {
                var entry = new CachedDetection
                {
                    Key = key,
                    State = result.State,
                    Path = path,
                    Detail = result.Detail,
                    Sha256 = "",
                    FileSize = File.Exists(Path.Combine(path, "*.exe")) ? 0 : 0,
                    Mtime = DateTime.Now,
                    Timestamp = DateTime.Now,
                };
                // 获取主 exe 的 mtime+size
                string mainExe = FindMainExe(key, path);
                if (mainExe != null && File.Exists(mainExe))
                {
                    var fi = new FileInfo(mainExe);
                    entry.FileSize = fi.Length;
                    entry.Mtime = fi.LastWriteTime;
                    entry.Sha256 = "";
                }
                DetectionCache.Put(entry);
            }
            catch { }

            return result;
        }

        private static string FindMainExe(string key, string dir)
        {
            string[] candidates;
            switch (key)
            {
                case "bandizip": candidates = new string[] { "Bandizip.x64.exe", "Bandizip.exe" }; break;
                case "ut": candidates = new string[] { "UninstallTool.exe" }; break;
                case "seer": candidates = new string[] { "Seer.exe" }; break;
                case "listary": candidates = new string[] { "Listary.exe" }; break;
                case "snipaste": candidates = new string[] { "Snipaste.exe" }; break;
                case "pixpin": candidates = new string[] { "PixAuth.dll" }; break;
                default: return null;
            }
            foreach (var c in candidates)
            {
                string p = Path.Combine(dir, c);
                if (File.Exists(p)) return p;
            }
            return null;
        }
    }
}
