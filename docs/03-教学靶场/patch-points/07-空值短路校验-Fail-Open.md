# 点位分析 07 · 空值短路校验（Fail-Open）

> **靶场**：`SeepLab.exe 07` ｜ **源码**：`src/SeepLab/Pattern07_FailOpen.cs`
> **关联 CWE**：`CWE-287` · `CWE-863` ｜ **涉及真实产品**：1 款（见 §8）
>
> ⭐ **本模式是「成本最低、危害最高」的鉴权缺陷。**
> 修复只需改一个分支，但漏掉它可能让全部防护失效。

---

## 1. 靶场程序信息

| 项目 | 内容 |
|:---|:---|
| **源码文件** | `src/SeepLab/Pattern07_FailOpen.cs` |
| **参考构建 SHA256** | `5218d0e87e025859e84b1ff5d5a8e9e1937bffdd772b0104b1ebe05a4b6cb756` |
| **运行命令** | `SeepLab.exe 07` |

---

## 2. 缺陷成因（源码层）

### 2.1 缺陷核心

```csharp
public static bool IsAuthorized(out string reason)
{
    string raw = FakeCredentialStore.Raw;

    // ★★★ 缺陷本体 ★★★
    if (string.IsNullOrWhiteSpace(raw))
    {
        reason = "凭据缺失，视为未配置授权（放行）";
        return true;                       // ← 免检通道
    }

    // 字面量 "null" / "0" 也常被错误处理
    if (raw == "null" || raw == "0")
    {
        reason = "凭据为占位值，视为未配置授权（放行）";
        return true;                       // ← 免检通道
    }

    // 正常路径：本地校验
    if (raw.StartsWith("LAB-") && raw.Length >= 8)
    {
        reason = "本地校验通过";
        return true;
    }

    reason = "本地校验失败";
    return false;
}
```

### 2.2 问题本质：混淆了三种状态

```
鉴权函数必须区分三种完全不同的状态：

  (a) 凭据合法        → 应放行  ✅
  (b) 凭据不合法      → 应拒绝  ✅
  (c) 凭据【缺失】    → 应拒绝  ← ★ 这里却放行了！

"缺失"不是"有效"，但在上面的代码里被当成了"无需校验"。
```

### 2.3 Fail-Open vs Fail-Closed

```
❌ Fail-Open（当前实现 —— 危险）
   ┌─────────────────────────────────────────┐
   │  凭据为空？ ──是──→ [ 进入"校验通过"分支 ] │  ← 免检通道
   │            └──否──→ [ 正常校验 ]          │
   └─────────────────────────────────────────┘

✅ Fail-Closed（正确实现 —— 安全）
   ┌─────────────────────────────────────────┐
   │  凭据为空？ ──是──→ [ 判定失败，拒绝服务 ] │  ← 默认拒绝
   │            └──否──→ [ 正常校验 ]          │
   └─────────────────────────────────────────┘
```

### 2.4 为什么这是最危险的缺陷

| 维度 | 说明 |
|:---|:---|
| **触发成本** | 极低 —— **一份空配置即可**，无需任何技术手段 |
| **服务端可见性** | **零** —— 客户端完全不发请求，风控无异常信号 |
| **绕过范围** | 全部 —— 跳过整条校验链 |
| **与保护强度的关系** | **无关** —— 混淆/虚拟化**完全无法防护语义缺陷** |
| **发现难度** | 高 —— 静态审计时容易被忽略（"空值处理"看起来像正常防御） |

> ### 🔑 核心教训
> **Fail-Open 是最危险的鉴权反模式。**
> 它把「**无法判定**」错误地当作「**判定通过**」，
> 让"配置缺失"变成了"免检通道"。

---

## 3. 二进制分析

### 3.1 关键字符串

| 字符串 | 用途 | 参考偏移 |
|:---|:---|:---|
| `null` | 占位值判定（★ 缺陷特征） | `0x0047b7` |
| `LAB-` | 本地校验前缀 | `0x0030c4` |

### 3.2 判定指令特征（IL 层）

```il
// Fail-Open 的典型 IL 形态
ldarg.0                                  // 加载凭据
call       bool [mscorlib]System.String::IsNullOrWhiteSpace(string)
brfalse.s  LABEL_NORMAL_CHECK            // 非空 → 走正常校验
// ↓ fall-through = 空值分支
ldc.i4.1                                 // ★ 加载常量 1（true）
ret                                      // ★ 直接返回 true ← 免检通道
LABEL_NORMAL_CHECK:
...
```

**关键特征**：**空值分支的 fall-through 直接 `ldc.i4.1` + `ret`**。

> 💡 **通用识别技巧**：
> 在 IL/汇编中查找"**空值检查后的分支直接返回成功值**"这一模式：
> * IL：`IsNullOrEmpty` / `IsNullOrWhiteSpace` 后的分支是 `ldc.i4.1; ret`
> * 汇编：`test rax,rax` / `cmp` 后的分支是 `mov eax,1; ret` 或 `mov al,1; ret`
>
> **这个模式在真实产品中非常常见。**

### 3.3 对照：Fail-Closed 的 IL 形态

```il
// Fail-Closed 的正确形态
ldarg.0
call       bool [mscorlib]System.String::IsNullOrWhiteSpace(string)
brfalse.s  LABEL_NORMAL_CHECK
// ↓ fall-through = 空值分支
ldc.i4.0                                 // ★ 加载常量 0（false）
ret                                      // ★ 返回 false ← 默认拒绝
LABEL_NORMAL_CHECK:
...
```

**两者唯一的区别**：`ldc.i4.1`（1）vs `ldc.i4.0`（0）。
**一个字节的差异，决定了整个授权体系是否有效。**

---

## 4. 完整点位表 ★

### 4.1 源码级点位（缺陷位置）

| # | 方法 | 位置 | 缺陷 | 正确写法 |
|---:|:---|:---|:---|:---|
| **P1** | `IsAuthorized` | `IsNullOrWhiteSpace` 分支 | `return true` | `return false` |
| **P2** | `IsAuthorized` | `raw == "null"` 分支 | `return true` | `return false` |
| **P3** | `IsAuthorized` | `raw == "0"` 分支 | `return true` | `return false` |
| **P4** | `FakeCredentialStore.LoadFromConfig` | `catch { }` 空捕获 | 静默失败 → `Raw = null` | 应记录并**标记为失败状态** |

### 4.2 二进制点位（IL 指令级）

| # | 目标方法 | 指令特征 | 原始 IL | 修补字节 | 效果 |
|---:|:---|:---|:---|:---|:---|
| **P5** | `IsAuthorized` | 空值分支返回常量 | `ldc.i4.1` = `17` | `ldc.i4.0` = `16` | 空值 → 拒绝（**修复 Fail-Open**） |
| **P6** | `IsAuthorized` | 占位值分支返回常量 | `ldc.i4.1` = `17` | `ldc.i4.0` = `16` | 占位值 → 拒绝 |
| **P7** | `IsAuthorized` | 正常校验分支 | `ldc.i4.1` = `17` | `ldc.i4.0` = `16` | 正常路径也拒绝（**破坏功能**） |

> ⭐ **P5 是"修复"，P7 是"破坏"** —— 两者字节相同，效果相反。
> **这说明：修改必须精确到"哪一处"，而不是"哪个字节"。**

### 4.3 对照实验：三种修改的效果 ★

| 改法 | 目标 | 结果 | 教学结论 |
|:---|:---|:---|:---|
| **改 P5** | 空值分支 | 空值 → 拒绝，正常凭据仍通过 | ✅ **正确的修复** |
| **改 P7** | 正常分支 | 合法凭据也被拒绝 | ❌ **破坏功能** |
| **改 P5+P6+P7** | 全部分支 | 恒定拒绝 | ❌ 完全不可用 |
| **不修改，仅提供空配置** | — | 🔴 **免检通过** | ★ 缺陷的实际触发方式 |

### 4.4 攻击侧 vs 防御侧（同一处代码）

```
                    ┌─────────────────────────┐
                    │  IsNullOrWhiteSpace 分支 │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
     【攻击者视角】                        【防御者视角】
     提供空配置 → 免检通过                  把 return true 改为 return false
     成本：0（无需任何工具）                 成本：1 个字节
     效果：绕过整条校验链                   效果：封堵免检通道
```

> ### 🔑 核心结论
> **这是所有鉴权缺陷中"攻防成本最不对称"的一处：**
> * 攻击成本 ≈ **0**（一份空文件）
> * 防御成本 ≈ **1 个字节**
>
> **但漏掉它的代价 = 全部防护失效。**

---

## 5. 定位方法

### 5.1 源码审计（最有效）

```csharp
// 在代码库中搜索以下模式（命中即为潜在 Fail-Open）
//   模式 1：空值检查后返回 true
if (string.IsNullOrEmpty(x)) return true;
if (string.IsNullOrWhiteSpace(x)) return true;
if (x == null) return true;

//   模式 2：空 catch 导致状态为默认值
try { ... } catch { }          // ← 静默失败

//   模式 3：默认值即"通过"
bool ok = true;                // ← 默认值应为 false
if (CheckLicense()) ok = true;
```

```powershell
# 在代码库中批量搜索
Select-String -Path .\**\*.cs -Pattern 'IsNullOrEmpty|IsNullOrWhiteSpace' -Context 0,2
```

### 5.2 二进制审计

```powershell
# 搜索字符串（提示可能存在空值处理逻辑）
strings.exe -u Target.exe | Select-String "null|empty"

# 在 IDA 中查找模式：
#   test rax, rax
#   jz   SHORT loc_XXX
#   mov  eax, 1        ← ★ 空值分支返回 1
#   ret
#   loc_XXX:
```

### 5.3 运行时验证（★ 最直接）

```powershell
# 1) 清空所有授权相关配置
# 2) 在隔离环境中运行程序
# 3) 观察：
#    ① 程序是否发起网络请求？（Fail-Open 时【完全不发】）
#    ② 功能是否可用？（可用 = 免检通道存在）
#
# 这是判定 Fail-Open 最直接的方法：
#   「配置全空 + 不发请求 + 功能可用」= 确认存在免检通道
```

---

## 6. 验证步骤

```powershell
# 运行靶场，观察 Fail-Open vs Fail-Closed 的对比
.\SeepLab.exe 07
```

**预期输出对照**：

| 场景 | `IsAuthorized`（缺陷版） | `IsAuthorized_FailClosed`（正确版） |
|:---|:---|:---|
| **阶段 1** 无配置文件 | 🔴 `True`（放行） | 🟢 `False`（拒绝） |
| **阶段 2** 内容为 `"null"` | 🔴 `True`（放行） | 🟢 `False`（拒绝） |
| **阶段 3** 合法凭据 | ✅ `True`（放行） | ✅ `True`（放行） |

> ⭐ **阶段 1 和阶段 2 是最关键的教学点**：
> **干净环境（无任何配置）下，缺陷版本直接放行** ——
> 这就是"免检通道"，也是攻击者最省力的利用方式。

---

## 7. 回滚方式

```powershell
# 清理测试文件
del fake.lic
# 或重新编译
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

---

## 8. 软件归属对照表 ★

| 产品 | 该缺陷落在哪一层 | 说明 | 详细公告 |
|:---|:---|:---|:---|
| **BoosterX** | 启动期授权装载流程的空值判定 | 凭据为 `null` / 空串 / 字面量 `"null"` 时被解释为"无需校验"，直接进入"校验通过"分支；**不发任何请求** | [查看](../../04-安全公告/07-空值短路校验-Fail-Open/BoosterX.md) |

### 对照要点

| 靶场演示的 | 真实产品中的对应 |
|:---|:---|
| `IsNullOrWhiteSpace` → `return true` | BoosterX 启动期授权装载的空值短路 |
| `raw == "null"` → `return true` | 字面量 `"null"` 被当作占位值放行 |
| 干净环境（无配置）直接放行 | 攻击者仅需一份空配置 |
| 客户端完全不发请求 | 服务端风控零感知 |
| 混淆无法防护语义缺陷 | BoosterX 使用商业级虚拟化保护，但该缺陷依然存在 |
| 修复成本 1 个字节 | 最不对称的攻防成本 |

> ⭐ **本案例的核心教学价值**：
> **BoosterX 是全部样本中混淆保护最强的一个**（符号重命名 + 字符串加密 +
> 程序集代码加密 + 代码虚拟化），**但 Fail-Open 缺陷依然完整存在。**
>
> 这直接证明了：
> ### 📌 混淆强度与安全架构是两个正交维度。
> **再高的分析成本，也无法弥补一个语义层面的设计错误。**

---

## 9. 防御加固方案

### 9.1 全面 Fail-Closed 重构

```csharp
public static class AuthDecision
{
    public static bool IsAuthorized(string credential, out string reason)
    {
        // ① 缺失 → 拒绝
        if (string.IsNullOrWhiteSpace(credential) || credential == "null")
        {
            reason = "凭据缺失或为占位值";
            return false;                          // ← Fail-Closed
        }

        // ② 格式非法 → 拒绝
        LicensePayload payload;
        if (!TryParse(credential, out payload))
        {
            reason = "凭据格式非法";
            return false;                          // ← Fail-Closed
        }

        // ③ 验签失败 → 拒绝
        if (!Ed25519.Verify(payload.Signature, payload.Body, ServerPublicKey))
        {
            reason = "签名验证失败";
            return false;                          // ← Fail-Closed
        }

        // ④ 设备绑定不符 → 拒绝
        if (!payload.MatchesDevice(DeviceFingerprint.Compute()))
        {
            reason = "设备绑定不匹配";
            return false;                          // ← Fail-Closed
        }

        // ⑤ 已过期 → 拒绝
        if (!payload.IsValidNow(MonotonicClock.Now))
        {
            reason = "凭据已过期";
            return false;                          // ← Fail-Closed
        }

        reason = "OK";
        return true;
    }
}
```

### 9.2 排查清单（★ 必须逐项检查）

| # | 检查项 | 危险写法 | 正确写法 |
|---:|:---|:---|:---|
| 1 | 空值分支 | `if (empty) return true;` | `if (empty) return false;` |
| 2 | 默认值 | `bool ok = true;` | `bool ok = false;` |
| 3 | 异常处理 | `catch { }` | `catch { return false; }` |
| 4 | 解析失败 | `if (!parse) return true;` | `if (!parse) return false;` |
| 5 | 网络超时 | `if (timeout) return true;` | `if (timeout) return false;` |
| 6 | 配置缺失 | `if (!exists) return true;` | `if (!exists) return false;` |
| 7 | 签名缺失 | `if (sig == null) return true;` | `if (sig == null) return false;` |
| 8 | 版本不符 | `if (mismatch) return true;` | `if (mismatch) return false;` |

> ### ⚠️ 一句话原则
> **"无法确认有效"必须等同于"无效"。**
> 任何"默认通过"的分支都是潜在漏洞。

### 9.3 加固优先级

```
最高优先（成本最低，收益最高）★
  └─ 排查全部"默认通过"分支，改为 Fail-Closed     ← 成本：几行代码

第二优先
  ├─ 移除空 catch（改为记录 + 返回失败）
  └─ 默认值统一改为 false

第三优先
  └─ 建立代码审查红线：禁止出现"空值即通过"模式
```

---

## 参考

- [CWE-287 · 不正确的身份验证](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-863 · 授权不正确](https://cwe.mitre.org/data/definitions/863.html)
- [OWASP · Fail Securely](https://owasp.org/www-community/Improper_Error_Handling)
- [靶场总览](../README.md) ｜ [模式 07 公告](../../04-安全公告/07-空值短路校验-Fail-Open/)

---

<sub>本靶场为自建样本（MIT 协议），与任何真实产品无关。软件归属对照表仅引用公开的设计层分析。</sub>
