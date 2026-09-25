# PixPin 会员特权判定体系 —— 逆向测绘报告 (CWE-602)

> 目标：`D:\Data\PixPin\PixPin.exe` + `PixAuth.dll`
> 版本：PixPin 3.5.5.1
> `PixAuth.dll` 原版 SHA256：`c6a3d8716efebdd2e3e21045996cae51414d031c8cd74a6fc1d1d5207c9d45d2`
> `PixAuth.dll` 补丁后 SHA256：`0766adbd8bf027e9dfd2913876eee244ba6e3dc417c708e6ee58cba3220de9c3`

---

## 1. 架构总览

PixPin 的全部 PRO/VIP 特权判定集中在外置动态库 **`PixAuth.dll`**（3,766,072 字节，Qt5 C++）：

```
┌──────────────────────────────────────────────────────────────────┐
│  PixPin.exe  (23,662,904 字节)                                    │
│  107 处功能门控调用点                                              │
│  ├─ checkFeatureAllow(FeatureType, bool)  × 22                   │
│  ├─ featureStatus(FeatureType)            × 28                   │
│  ├─ Application::isProUser()              × 45                   │
│  ├─ VipInfo::isVip()                      ×  2                   │
│  └─ VipInfo::hasPrepaid()                 ×  1                   │
└───────────────────────────┬──────────────────────────────────────┘
                            │ IAT 导入
┌───────────────────────────▼──────────────────────────────────────┐
│  PixAuth.dll  (3,766,072 字节)                                    │
│  PixFeatureManager / Application / VipInfo / Subscription /       │
│  PrepaidInfo —— 全部为本地布尔/枚举判定，无签名、无服务端权威      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. 会员功能全集（FeatureType 枚举，14 项）

从 Qt 元对象字符串数据（`PixAuth.dll` @ `0x0378162`）提取：

| idx | FeatureType | 官方名称 | 快捷键 | 官方描述要点 |
|:--:|:---|:---|:--:|:---|
| 0 | `Translation` | 翻译 | `Ctrl+Q` | AI 屏幕取词一键翻译；Multi-language / AI Engine / Original Text Comparison |
| 1 | `TableRecognition` | 表格识别 | `Shift+Q` | 表格结构还原 + 一键导出 Excel；High Precision Recognition |
| 2 | `FormulaRecognition` | 公式识别 | `Shift+F` | 数学公式 → LaTeX 格式转换 |
| 3 | `SmartErase` | 智能擦除 | — | 智能移除杂物与敏感信息，还原自然背景 |
| 4 | `GlobalMouse` | 全局鼠标 | — | 全局鼠标增强（未在升级弹窗展示） |
| 5 | `ConfigSync` | 配置同步 | — | 云端备份设置与历史，多设备无缝衔接 |
| 6 | `LongScreenshotAutoCrop` | 长截图自动裁剪 | — | 滚动截图自动检测裁剪，一次成图 |
| 7 | `RecordClip` | 录制片段 | — | 录屏快速裁剪，保留关键片段 |
| 8 | `RecordKeyMouse` | 键鼠录制 | — | 键鼠操作可视化录制与回显 |
| 9 | `ExportPreview` | 导出预览 | — | 实时预览编码效果，画质/体积权衡 |
| 10 | `SaveAsPDF` | 另存为 PDF | — | 一键生成通用 PDF |
| 11 | `AutoMosaicSync` | 自动马赛克同步 | — | 自动马赛克处理与同步（未在弹窗展示） |
| 12 | `IndustrialBarcode` | 工业条码识别 | — | Code128/EAN-8/13/UPC-A/E/ITF/Codabar/39/93 等 20+ 格式 |
| 13 | `CameraRecording` | 摄像头录制 | — | 屏幕 + 摄像头画中画同步录制 |

> 数据源：`VipFeatureDialog::getFeatureInfo`（RVA `0x0AC5B0`，函数体 6972 字节）——官方升级弹窗的功能介绍数据源。

---

## 3. 补丁点清单（11 处）

全部为**函数入口恒值化**（帧未分配即返回，无栈平衡风险）：

### A. 授权身份判定（5 处符号 / 4 处补丁）

| RVA | 原始字节 | 补丁字节 | 原始符号 |
|:---|:---|:---|:---|
| `0x0C3270` | `48 83 EC 28` | `B0 01 C3` | `PixAuth::UserInfo::isProUser()` |
| `0x09C430` | `48 83 C1 10` | `B0 01 C3` | `PixAuth::Application::isProUser()` |
| `0x0EE950` | `40 53 48 83 EC 20` | `B0 01 C3` | `PixAuth::VipInfo::isVip()` |
| `0x0EE910` | `40 53 48 83 EC 20` | `B0 01 C3` | `PixAuth::Subscription::isVip()` |
| `0x0EE7B0` | `40 53 48 83 EC 20` | `B0 01 C3` | `PrepaidInfo::isVip()` + `VipInfo::hasPrepaid()` **(ICF 折叠)** |

### B. 功能门控判定（3 处，覆盖全部 14 项 FeatureType）

| RVA | 原始字节 | 补丁字节 | 语义 |
|:---|:---|:---|:---|
| `0x0A74D0` | `48 89 5C 24 10 48` | `B8 01 00 00 00 C3` | `checkFeatureAllow()` → 恒 `Allow(1)` |
| `0x0A8040` | `48 89 5C 24 10 56` | `31 C0 C3` | `featureStatus()` → 恒 `Available(0)` |
| `0x0A86F0` | `48 89 5C 24 08 57` | `32 C0 C3` | `isProFeature()` → 恒 `false` |

### C. 试用机制判定（2 处）

| RVA | 原始字节 | 补丁字节 | 语义 |
|:---|:---|:---|:---|
| `0x0A84B0` | `40 53 48 83 EC 20` | `B0 01 C3` | `hasActivatedTrialAccess()` → 恒 `true` |
| `0x0A8C30` | `40 53 55 56 57 48` | `C3` | `rescheduleTrialExpireTimer()` → 禁用倒计时 |

### D. 订阅提醒抑制（1 处）

| RVA | 原始字节 | 补丁字节 | 语义 |
|:---|:---|:---|:---|
| `0x09D560` | `40 55 53 56 57 41` | `C3` | `showSubscriptionTrialReminder()` → 抑制弹窗 |

> 补丁前 `PixAuth.dll` 自动备份为 `PixAuth.dll.orig`，可一键单体还原。
> `PixPin.exe` **不做任何修改**（保持官方逐字节一致）。

---

## 4. ICF 折叠发现（Identical COMDAT Folding）

MSVC 链接器将语义完全相同的函数折叠到同一地址：

```
0x1800EE7B0  ← 同时承载两个导出符号
              ├─ ?hasPrepaid@VipInfo@PixAuth@@QEBA_NXZ
              └─ ?isVip@PrepaidInfo@PixAuth@@QEBA_NXZ
```

**影响**：1 处补丁顺带覆盖 2 个判定符号 → 单点失效影响面被放大。

**防御建议**：编译期禁用 ICF（`/OPT:NOICF`）。

---

## 5. 未覆盖函数（经评估为非门控）

以下 5 个函数**不在补丁清单内**，经逆向确认**不参与功能准入判定**：

| 函数 | RVA | 调用点 | 实际用途 |
|:---|:---|:--:|:---|
| `VipInfo::hasSubscription()` | `0x0EE7D0` | 3 | `UpgradeFunnel_Entry` 埋点 + 会员到期提醒 |
| `VipInfo::isLifetimeVip()` | `0x0EE8F0` | 5 | `UserType` 埋点字段 + UI 标签（Lifetime/Subscription） |
| `PrepaidInfo::isLifetime()` | `0x0EE810` | (tail-jmp) | 同上 |
| `Subscription::isValid()` | `0x0EE900` | 0 | PixAuth 内部使用（未导入主程序） |
| `Subscription::status()` | `0x0BD2F0` | 0 | 状态枚举读取（未导入主程序） |

**逆向证据**：调用点均位于 `PixTrack` 埋点链（字符串：`UpgradeFunnel_Entry` / `TriggerSource` / `Result=AlreadyPro` / `NextStep=BuyDialog` / `UserType`）与 UI 文案选择分支。

---

## 6. 运行时验证（Frida 实机矩阵）

通过 Frida 17.18 附加运行中的 PixPin 进程，直接调用补丁后的门控函数：

```
=== Application 层判定 ===
  Application::isProUser()  = 1 (true)
  VipInfo::isVip()          = 1 (true)
  VipInfo::hasPrepaid()     = 1 (true)
  VipInfo::hasSubscription()= 0   ← 未补丁（非门控）
  VipInfo::isLifetimeVip()  = 0   ← 未补丁（非门控）

=== PixFeatureManager 全功能矩阵 (14 项) ===
  idx  FeatureType               checkFeatureAllow  featureStatus  hasTrialAccess
   0   Translation               Allow(1)           Available(0)   true
   1   TableRecognition          Allow(1)           Available(0)   true
   2   FormulaRecognition        Allow(1)           Available(0)   true
   3   SmartErase                Allow(1)           Available(0)   true
   4   GlobalMouse               Allow(1)           Available(0)   true
   5   ConfigSync                Allow(1)           Available(0)   true
   6   LongScreenshotAutoCrop    Allow(1)           Available(0)   true
   7   RecordClip                Allow(1)           Available(0)   true
   8   RecordKeyMouse            Allow(1)           Available(0)   true
   9   ExportPreview             Allow(1)           Available(0)   true
  10   SaveAsPDF                 Allow(1)           Available(0)   true
  11   AutoMosaicSync            Allow(1)           Available(0)   true
  12   IndustrialBarcode         Allow(1)           Available(0)   true
  13   CameraRecording           Allow(1)           Available(0)   true
```

**结论**：14 项功能的 `checkFeatureAllow` 恒返回 `Allow(1)`、`featureStatus` 恒返回 `Available(0)`、`hasTrialAccess` 恒 `true`。

---

## 7. 攻克率统计

| 维度 | 数值 |
|:---|:---|
| 会员功能总数 | **14 项** |
| 可攻克功能数 | **14 项（100%）** |
| 纯本地攻克（无外部依赖） | **13 项** |
| 核心补丁量 | **11 处 / 32 字节** |
| 需外部配合 | 翻译（服务端算力需代理重定向） |

---

## 8. 弱点总结（CWE-602）

| 弱点 | 说明 |
|:---|:---|
| **本地布尔判定** | 14 项特权全部由 `PixAuth.dll` 内本地函数决定，无签名绑定 |
| **单一入口可恒值化** | `mov al,1; ret` 即可解除整个功能域 |
| **无完整性自校验** | `PixAuth.dll` 无 CRC/哈希自检，磁盘修改即生效 |
| **ICF 折叠放大失效面** | 单点补丁覆盖多符号 |
| **埋点与门控耦合** | 特权判定函数被同时用于准入与埋点，无法单点消除痕迹 |

---

## 9. 纵深防御修复方案

1. **客户端加固**
   - 14 项特权判定下沉 Native + 代码虚拟化（VMProtect / Themida）；
   - `.text` 段运行时 CRC 自校验 + 关键函数页 `PAGE_EXECUTE_READ` 写保护；
   - 编译期禁用 ICF（`/OPT:NOICF`）避免单点失效扩散；
   - 反调试 / 反内存补丁：`CheckRemoteDebuggerPresent` + 硬件断点检测。

2. **传输层收敛**
   - 全链路 TLS 双向证书绑定（SSL Pinning），阻断 API 端点重定向；
   - 请求级 Sign + Nonce + Timestamp 动态签名。

3. **服务端权威闭环**
   - 特权状态不落本地布尔值，改为服务端签发的**短期 License Token（Ed25519 + Valid-Until 时间戳）**；
   - 核心权益（翻译/OCR 额度）以服务端异步通知 + 二次验签为唯一凭据；
   - 埋点数据源与准入判定彻底解耦，埋点使用不可伪造的 Token 声明。

---

## 10. 复现步骤

```powershell
# 1. 启动 Seep-Tool
.\SeepTool.exe

# 2. 在「目标状态与修补矩阵」中找到 PixPin 卡片
#    点击 [修补 ⚡]  → 自动关闭 PixPin → 备份 .orig → 写入 11 处补丁 → 复读校验
#    点击 [还原 ↻]  → 从 .orig 恢复官方原版

# 3. 验证
#    启动 PixPin → 会员功能（表格识别/公式识别/长截图/录制等）全部可用
```

**手工还原**：
```powershell
Copy-Item "D:\Data\PixPin\PixAuth.dll.orig" "D:\Data\PixPin\PixAuth.dll" -Force
```

---
INT0 COLLECTIVE // 学术研究用途 // 支持正版 PixPin (https://pixpin.cn/)
