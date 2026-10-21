# AGENTS.md — lengsuo-extension

浏览器扩展仓。**一个扩展 = `extensions/` 下的一个目录**。
**只装前端资产**：manifest、内容脚本、主世界脚本、background、站点填充脚本。

### ⭐ 多扩展结构（加扩展 = 加目录，不改构建脚本）
```
extensions/
  credential/                 ← 扩展 1（凭据）
    manifest.json
    src/{background,content,main_world,autofill}/
    keys/extension_public_key.pem
    tests/*.test.mjs
  <另一个扩展>/               ← 扩展 2（以后）
```
- 构建：`node build/build.mjs` ⇒ 遍历 `extensions/*`，每个产出 `dist/<name>/`
- ⛔ **不要**把扩展的源码放到仓根 ⇒ 会被当成"公共代码"混在一起
- 每个扩展**各有自己的固定公钥**（⇒ 各自的扩展 ID）

## 1. 边界（本仓装什么 / 不装什么）

| 装 | 不装 |
|---|---|
| `manifest.json` | ⛔ Rust 代码（Native Messaging host 在客户端仓） |
| `src/**` 的 JS | ⛔ 私钥 / 凭据 / 任何秘密 |
| `extensions/*/keys/extension_public_key.pem`（**公钥，可公开**） | ⛔ 与服务端的直连（一切经 Native Messaging） |
| `build/` `tests/` | ⛔ 任何 GPL-3.0 实现的代码（见 §4） |

## 2. 与其它仓的关系（本仓不产生代码依赖）

| 对端 | 渠道 | 对齐方式 |
|---|---|---|
| 客户端仓（Rust host） | Native Messaging（本机进程） | 契约文档 + 固定扩展 ID |
| 客户端仓（内核包） | 构建产物随包分发 | 契约文档 §5.5 目录摘要算法 |

⭐ **跨仓唯一真相**：`lengsuo-browser/docs/credential-wire-contract.md`
（信封格式 / authData / attestationObject / 恢复码 KDF / 消息协议 / 跨仓常量 / 目录摘要算法）
⇒ **改字节布局必须先改那份文档。**

### 三个不能改的常量
| 常量 | 值 |
|---|---|
| Native Messaging host 名 | `lengsuo.credential` |
| 扩展 ID | `SbzJDF-u75AnlyE5` |
| 扩展目录名 | `lengsuo-credential` |

⚠️ **扩展 ID 一旦定下不可改** ⇒ 公钥必须入库、私钥绝不入库。

## 3. 门禁

```bash
node build/build.mjs --digest     # 构建全部扩展 + 摘要
node --test "tests/*.test.mjs" "extensions/*/tests/*.test.mjs"
```
- ⛔ `dist/` 不入库
- ⛔ 私钥不入库（`.gitignore` 只挡私钥，**固定公钥必须入库**）
- ⛔ 树内不得出现 GPL-3.0 实现的标识（CI 有检查）

### ⚠️ `.gitignore` 的密钥规则必须能匹配任意深度
扩展目录是**嵌套**的 ⇒ 规则要写 `**/keys/*_private*.pem`（带 `**/` 锚定）。
⛔ 只写 `keys/*_private*.pem` **匹配不到** `extensions/credential/keys/` 下的私钥
⇒ **私钥会被误提交**。加新扩展层级时，务必实跑 `git check-ignore -v <私钥路径>` 验证。

## 4. 许可红线

本仓实现**不得**复制或改后使用任何 **GPL-3.0** 项目的代码。
⇒ 凭据相关实现只用 **MIT / Apache-2.0** 的库，或自己写。
⇒ 行为可以照着做（黑盒只读观察），**代码必须自己写**。

## 5. 安全口径（不可放宽）

| 规则 | 原因 |
|---|---|
| **白名单默认全禁**（`enable: []` + `disable: ["*"]`） | 自动填充 = 把凭据送到页面 |
| ⛔ **取不到策略就不填**（fail-closed） | 策略不可用 ≠ 策略放行 |
| ⛔ **host 缺失要显式报错**，不静默降级 | 降级 = 悄悄不工作，用户无从察觉 |
| ⛔ **TOTP secret 不出 host 进程** | secret 泄露 = 长期有效凭据泄露 |
| ⛔ **保留原生作回退**（`type = 10`） | host 不可用时页面仍能登录 |

## 6. 文档

`docs/` 只留本地，不随仓库分发（见 `.gitignore`）。
