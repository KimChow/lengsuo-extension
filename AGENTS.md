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

## 6. 文档放置规则（docs/ 只留本地，不入库）

**一句话：`docs/` 是本地工作区资产，只给智能体和开发方看，不随仓库分发，也不出现在 git 历史里。**

### 6.1 什么写哪里

| 内容 | 位置 | 是否入库 |
|---|---|---|
| 进度台账、验收记录、任务书、对照资料、研究稿、状态快照 | `docs/` | **不入库** |
| 对外说明、装了什么、怎么构建、当前状态 | `README.md` | 入库 |
| 协作规则、门禁、边界、验收判据 | `AGENTS.md` | 入库 |
| 代码里的行为注释、类型说明、错误码语义 | 源码内 | 入库 |

**判据一句话：写给「读者和下一个智能体」看的东西进 `docs/`；写给「装这份代码的人」看的进 README 与规则文件。**

### 6.2 硬性要求

- `docs/` 全量在 `.gitignore` 里，**取消索引跟踪**；仓库历史中**不得残留**任何 `docs/` 路径。
- 新增文档**直接写进 `docs/`**，不要先写到仓根再补 gitignore。
- 写文档前先看 `docs/` 已有同类文件，**更新而不是新建**；确需新建时用 `主题-类型.md`。
- 文档里**不写对标产品名**，只用中性代号（`对标端` / `参照平台`）；来源标识只记在本地工作区。
- 提交前自检：`git status` 里**不应出现 `docs/`**；若出现说明误加，`git rm -r --cached docs` 撤回。
- 不做 `git add .` / `git add -A` 盲加；**按文件路径逐个 add**。

### 6.3 两台机器的文档同步

- 本机与 47 **各有一份 `docs/`**，内容取**并集**（本机独有 + 47 独有），不是互相覆盖。
- 同步用文件级传输，**不走 git**（git 里已经没有 docs 了）：
  ```bash
  # 本机 -> 47
  (cd <repo> && tar -cf - docs) | ssh 47 "cd <repo> && tar -xf -"
  # 47 -> 本机
  ssh 47 "cd <repo> && tar -cf - docs" | (cd <repo> && tar -xf -)
  ```
- 同步**只做文件搬运，不做删除**；清理旧文档由人工在两侧分别处理。
- 依赖 `docs/` 存在才通过的测试要加 `skipUnless(DOCS.is_dir())`，否则 CI 会因缺文件变红。

### 6.4 与门禁的关系

- `scripts/check_line_limit.py` 管**行数**，`scripts/check_no_source_leak.py` 管**内容脱敏**。
- 本节管**边界**（文档不进仓、不进历史）。三者独立，缺一不可。
