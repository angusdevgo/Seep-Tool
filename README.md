<p align="center">
  <strong>CWE-602 · Client-Side Authorization Vulnerability · Whitebox Audit Methodology</strong>
</p>

<h1 align="center">Seep-Tool</h1>

<p align="center">
  <strong>客户端鉴权脆弱性（CWE-602）白盒审计方法论与纵深防御加固研究框架</strong><br>
  <em>A Documentation-Only Research Framework for Client-Side Enforcement of Server-Side Security</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Type-Documentation%20Only-blue?style=for-the-badge" alt="Documentation Only">
  <img src="https://img.shields.io/badge/Security-CWE--602-red?style=for-the-badge" alt="CWE-602">
  <img src="https://img.shields.io/badge/Focus-Defense%20%26%20Remediation-success?style=for-the-badge" alt="Defense">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge" alt="License"></a>
</p>

---

## ⚠️ 重要声明：本仓库不含任何可执行程序

> **本仓库是纯文档型安全研究知识库。**
>
> - ❌ **不提供**任何可执行文件（EXE / DLL / 安装包）
> - ❌ **不提供**任何一键激活、授权绕过、补丁工具
> - ❌ **不提供**任何注册机、密钥生成器或规避技术措施的方法
> - ✅ **只提供**脆弱性成因分析、审计方法论与**企业级防御加固方案**
>
> 本项目的全部内容面向**软件开发者、安全工程师与安全专业学生**，
> 目的是帮助研发团队**识别并修复**客户端鉴权设计缺陷，构建更健壮的商业软件。

---

## 🔬 研究背景

### 什么是 CWE-602？

根据 [MITRE CWE 官方定义](https://cwe.mitre.org/data/definitions/602.html)：

> **CWE-602: Client-Side Enforcement of Server-Side Security**
> 当软件依赖客户端来实施本应由服务端强保证的安全策略时，攻击者可以通过篡改客户端状态、
> 改写本地函数返回值或修改内存，绕过全部安全限制。

这是一个**架构级缺陷**，而非某个具体的编码错误。它的危害在于：
**一旦攻击者获得对客户端运行环境的完全控制权（这在桌面软件场景下是必然的），
所有由客户端自行裁决的安全决策都将失去可信性。**

### 为什么桌面软件特别容易中招？

| 客观约束 | 导致的设计陷阱 |
|:---|:---|
| 需要支持**离线使用** | 无法每次启动都向服务端校验 → 退化为本地裁决 |
| 需要**低延迟**响应 | 特权判定走本地缓存 → 状态可被篡改 |
| 需要**减少服务器成本** | 把权限计算放到客户端 → 决策逻辑暴露 |
| 需要**保护商业利益** | 自行发明加密/校验方案 → 引入新的密码学缺陷 |

---

## 🧭 方法论框架：四层审计视角

本方法论建议从四个层次逐级审计客户端鉴权实现：

```
┌───────────────────────────────────────────────────────────────┐
│ L1 · 架构层 (Architecture)                                    │
│   谁拥有最终裁决权？是否存在“服务端权威”闭环？                    │
├───────────────────────────────────────────────────────────────┤
│ L2 · 密码学层 (Cryptography)                                  │
│   凭据如何签发与验证？是否使用标准非对称签名？                     │
├───────────────────────────────────────────────────────────────┤
│ L3 · 运行时层 (Runtime)                                       │
│   决策状态存储在哪？是否可被外部读写？                            │
├───────────────────────────────────────────────────────────────┤
│ L4 · 代码形态层 (Code Form)                                   │
│   关键逻辑是否暴露？是否可被静态/动态分析定位？                     │
└───────────────────────────────────────────────────────────────┘
```

> 📖 详见 [docs/01-理论基础/01-CWE602-原理与成因分析.md](docs/01-理论基础/01-CWE602-原理与成因分析.md)

---

## 🎯 客户端脆弱性模式矩阵

下表归纳了桌面客户端在鉴权设计中最常见的七类架构缺陷模式（**已做抽象化处理，不含具体攻击步骤**）：

| # | 缺陷模式 | 涉及产品（实测样本） | 关联 CWE | 加固方向 |
|:---:|:---|:---|:---|:---|
| 1 | **单点布尔裁决** | **PixPin** · **Seer** · **XYplorer** · **Allen Explorer** · **Bandizip** · **Burp Suite** · **BoosterX** | CWE-602 | 业务逻辑内联化，消除显式判定出口 |
| 2 | **硬编码密钥材料** | **Snipaste PRO** · **Allen Explorer** · **BoosterX** | CWE-321 / CWE-798 | 改用非对称签名（Ed25519 / RSA-PSS） |
| 3 | **动态库加载顺序缺陷** | **Bandizip** · **Burp Suite** · **XYplorer** | CWE-427 | `SetDefaultDllDirectories` + 签名白名单 |
| 4 | **可写全局状态变量** | **XYplorer** · **Bandizip** · **BoosterX** | CWE-602 | 敏感状态加密存储 + 用毕擦除 |
| 5 | **明文进程间通信** | **Uninstall Tool** | CWE-311 / CWE-345 | HMAC 消息认证 + 时戳防重放 |
| 6 | **自研弱校验算法** | **Listary Pro** | CWE-327 | 使用行业标准密码学原语 |
| 7 | **空值短路校验（Fail-Open）** | **BoosterX** | CWE-287 | 鉴权分支全面改为 Fail-Closed |

> 📖 每种模式的成因剖析与对照代码，详见 [docs/01-理论基础/02-客户端脆弱性模式矩阵.md](docs/01-理论基础/02-客户端脆弱性模式矩阵.md)
>
> 📋 上述 10 款产品的逐款安全公告（含受影响版本、组件、根因与加固方案），详见 [docs/04-安全公告/README.md](docs/04-安全公告/README.md)

---

## 🛡️ 纵深防御加固体系

针对上述缺陷，本方法论提出**三层纵深防护架构（Defense-in-Depth）**：

```
┌───────────────────────────────────────────────────────────────┐
│ 第一层 · 传输与权威层 (Server-Side Authority)                  │
│  • 确立“服务端权威”原则：核心权益必须由服务端签发并二次验签          │
│  • 离线许可证采用非对称签名（Ed25519），私钥永不离线               │
│  • 全链路双向 mTLS 证书绑定 + 时戳 Nonce 防重放                   │
├───────────────────────────────────────────────────────────────┤
│ 第二层 · 环境与运行时层 (Runtime Integrity)                    │
│  • 关键系统 API 调用完整性自检 (Anti-Hook / Direct Syscalls)     │
│  • 自身二进制 Authenticode 签名动态复核                          │
│  • 严格 DLL 搜索目录白名单 (SetDefaultDllDirectories)            │
│  • 敏感内存区域加密与用毕即时擦除                                 │
├───────────────────────────────────────────────────────────────┤
│ 第三层 · 代码形态与混淆层 (Obfuscation)                        │
│  • 控制流平坦化 (Control Flow Flattening) 与虚假控制流            │
│  • 关键判定逻辑代码虚拟化 (VMP) 保护                             │
│  • 符号剥离与敏感字符串动态解密                                    │
└───────────────────────────────────────────────────────────────┘
```

> 📖 完整实现指南，详见 [docs/02-防御体系/01-纵深防御加固体系.md](docs/02-防御体系/01-纵深防御加固体系.md)

---

## 📚 文档目录（按类型分类）

> 📂 完整目录导航见 **[docs/README.md](docs/README.md)**
>
> 文档仓库按**类型**组织，每个类型下是**具体内容**；安全公告按**缺陷模式**分类，每个模式下列出**具体软件**。

### 📖 理论基础 · `docs/01-理论基础/`

| 文档 | 内容 |
|:---|:---|
| [CWE-602 原理与成因分析](docs/01-理论基础/01-CWE602-原理与成因分析.md) | 缺陷本质、为何客户端裁决不可信、四层审计视角 |
| [客户端脆弱性模式矩阵](docs/01-理论基础/02-客户端脆弱性模式矩阵.md) | **七类**高频缺陷模式的成因、反例与对照修正 |

### 🛡️ 防御体系 · `docs/02-防御体系/`

| 文档 | 内容 |
|:---|:---|
| [纵深防御加固体系](docs/02-防御体系/01-纵深防御加固体系.md) | 三层防护架构的工程落地指南 |
| [Ed25519 离线许可体系设计](docs/02-防御体系/02-Ed25519离线许可体系设计.md) | 可直接用于生产的非对称离线授权方案（含防御性参考代码） |
| [发布前安全自检清单](docs/02-防御体系/03-发布前安全自检清单.md) | 桌面软件上线前必过的 20 项客户端安全基准 |

### 📋 披露流程 · `docs/03-披露流程/`

| 文档 | 内容 |
|:---|:---|
| [负责任的漏洞披露流程](docs/03-披露流程/01-负责任的漏洞披露流程.md) | 安全研究者与厂商协作的标准流程与邮件模板 |

### 🔍 安全公告 · `docs/04-安全公告/`

> 📊 公告总览矩阵见 **[安全公告总览](docs/04-安全公告/README.md)**

按**缺陷模式**分类，每个模式文件夹下是**具体软件**的公告文件：

| 模式 | 名称 | CWE | 涉及产品 | 目录 |
|:---:|:---|:---|:---:|:---|
| 1 | 单点布尔裁决 | CWE-602 | 7 款 | [进入 →](docs/04-安全公告/01-单点布尔裁决/) |
| 2 | 硬编码密钥材料 | CWE-321 / CWE-798 | 3 款 | [进入 →](docs/04-安全公告/02-硬编码密钥材料/) |
| 3 | 动态库加载顺序缺陷 | CWE-427 | 3 款 | [进入 →](docs/04-安全公告/03-动态库加载顺序缺陷/) |
| 4 | 可写全局状态变量 | CWE-602 | 3 款 | [进入 →](docs/04-安全公告/04-可写全局状态变量/) |
| 5 | 明文进程间通信 | CWE-311 / CWE-345 | 1 款 | [进入 →](docs/04-安全公告/05-明文进程间通信/) |
| 6 | 自研弱校验算法 | CWE-327 | 1 款 | [进入 →](docs/04-安全公告/06-自研弱校验算法/) |
| 7 | 空值短路校验 (Fail-Open) | CWE-287 / CWE-863 | 1 款 | [进入 →](docs/04-安全公告/07-空值短路校验-Fail-Open/) |

---

## ⚖️ 合规与伦理声明

1. **教育目的**：本仓库全部内容仅用于**安全知识普及、防御架构教学与授权范围内的安全评估**；
2. **不提供攻击工具**：本项目刻意**不包含**任何可运行的规避技术措施制品、注册机或补丁工具；
3. **负责任披露**：如您在实际产品中发现本方法论描述的缺陷，请遵循
   [docs/03-披露流程/01-负责任的漏洞披露流程.md](docs/03-披露流程/01-负责任的漏洞披露流程.md) 联系厂商，而非公开利用；
4. **尊重知识产权**：所有提及的商业软件均归其各自权利人所有。若相关软件对您产生了实际价值，
   请通过官方渠道购买正版许可；
5. **禁止滥用**：严禁将本方法论用于任何违反法律法规的活动。使用者应自行承担全部法律责任。

---

## 📄 License

本项目遵循 **[GNU General Public License v3.0](LICENSE)** 许可协议。

```
Copyright (C) 2026 Angus (angusdevgo)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
