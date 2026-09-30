# Key Management Ceremony Orchestration System

编排**根密钥全生命周期仪式**的系统：生成（GENERATE）、轮换（ROTATE）、
备份/份额恢复（BACKUP）、销毁（DESTROY）。每次仪式都强制固定参与角色、
门限份额、设备远程证明和严格的操作顺序；任何单人都无法重建密钥。

纯 Python 标准库实现（无第三方依赖），包含一个 RFC 8032 Ed25519 的独立实现。

---

## 1. 它保证什么

| 需求 | 实现方式 |
|---|---|
| **固定参与角色** | 四种固定角色：`ROOT_OWNER`（安全负责人）、`KEY_STEWARD`（HSM 托管员）、`WITNESS_SHAREHOLDER`（独立见证人）、`ENCLAVE_OPERATOR`（签名飞地操作员）。策略创建后不可变，仪式打开时冻结快照。任何单个组织角色凑不齐门限（策略校验强制）。 |
| **门限份额** | Feldman 可验证 Shamir 秘密分享（默认 3-of-4），份额域 = MODP-14 安全素数群的素数阶子群（`(q-1)/2` 阶），承诺 `C_j = g2^coeff_j`。每台设备独立验证自己的份额 `g2^s_i == Π C_j^(i^j)` 后才允许确认。 |
| **任何单人不能重建密钥** | 编排器在 GENERATE/ROTATE 中**从不接触份额明文**：多项式在编排端生成后，份额用各设备的封装公钥（素数子群 KEM + HKDF + HMAC AEAD，绑定 `仪式ID|设备ID` 上下文）逐个密封投递；确认只需设备签名声明 VSS 校验通过。签名种子只从同一常数项派生，私钥材料用服务主包装密钥单独封存。 |
| **设备证明** | 每台设备有身份密钥（Ed25519）、封装密钥（MODP）和软件度量（SHA256）。仪式先颁发挑战随机数，设备对 `(挑战, 当前度量, 封装公钥, 时间戳)` 签名报价；编排器校验签名、度量与注册值一致、封装公钥与注册一致、时间窗、子群成员关系，然后才投递份额。 |
| **操作顺序** | 严格阶段机：`OPEN → ATTESTED → DELIVERED → CONFIRMED → COMMIT → COMPLETED`，不可跳级、不可回退；动作信封带设备签名与一次性 nonce（重放/同 nonce 换载荷分别报 `DUPLICATE_ACTION` / `REPLAY_DETECTED`）；仪式有截止时间，超时自动 ABORT。 |
| **开始后参与者/策略变化必须废弃本轮并保留审计** | 策略修订（`revise_policy`）会自动 ABORT 所有使用旧策略的打开中仪式；手动 ABORT 擦除本轮所有秘密态（待定签名种子、入站恢复份额、投递信封），但审计链完整保留，之后可开新一轮。 |
| **新旧密钥交接窗口并存** | ROTATE 先生成 `STAGED` 后继版本；发布是对“当前 ACTIVE 版本”的**比较并交换（CAS）**。发布成功后旧版本变 `RETIRING`，两者在交接窗口（策略 `handover_seconds`）内并存。同一 purpose 同时只允许一个打开的轮换仪式、至多一个 RETIRING 版本。 |
| **签名方只用已激活版本** | `sign` 只使用 `ACTIVE`；对 STAGED/RETIRING/DESTROYED 签名抛 `CONFLICT_STATE`。 |
| **验证方继续识别历史版本** | `verify` 遍历该 purpose 所有已识别版本（STAGED/ACTIVE/RETIRING/DESTROYED），返回匹配版本及其状态；销毁只擦除私钥材料，公钥/指纹/承诺永久保留用于历史签名验证。 |
| **份额丢失可恢复** | BACKUP 仪式：存活者用旧承诺验证并提交份额（至少门限份），在**同一常数项**上重新随机化多项式，向恢复后名册分发新份额；`C0` 不变（绑定同一密钥），高次承诺全部更新，签名身份不变。 |
| **参与者掉线/永久丢失可恢复** | GENERATE/ROTATE/DESTROY 要求**全员到场**，掉线则本轮无法推进（可废弃重开）。永久丢失参与者时 BACKUP 可声明 `lost_participants` + 1:1 同角色替补（必须 `replaces` 指定丢失槽位），存活者 ≥ 门限即可；丢失超过 `n-t` 则按策略不可恢复。 |
| **重复确认可恢复** | 同一设备重复确认是幂等拒绝（`DUPLICATE_ACTION`），不改变状态；相同动作信封重放也是幂等拒绝。 |
| **轮换发布竞态不产生两个当前密钥** | 所有状态变更在跨线程 RLock + 跨进程 flock + 状态加载均在锁内的事务中；发布走 CAS。并发发布者恰好一个成功，其余得到 `409 RACE_LOST`，可用新的当前指针安全重试（成功方重试为幂等）。每个 purpose 任何时刻恰有一个 ACTIVE。 |
| **可验证记录导出** | `export.json`（策略快照、全部公钥版本、仪式、设备、参与者、完整审计）+ `audit.txt` + `SHA256SUMS`。导出整体由服务身份 Ed25519 签名；审计条目逐条哈希链接（`SHA256(prev ‖ payload ‖ ts ‖ seq)`）并逐条服务签名。离线校验器检查签名、哈希链、密钥生命周期溯源（每个版本都来自 COMPLETED 仪式）、销毁版本无私钥、单一 ACTIVE 不变量、交接一致性。 |

审计中**只出现**承诺、公钥、身份与哈希，份额明文、签名种子、恢复入站份额从不入审计。

---

## 1.5 值班员会话与四眼授权（HTTP 控制台层）

编排库（`Orchestrator`）之上叠加了一个 **WatchDesk** 策略层，仅强制于 HTTP
边界；脚本/测试仍然可以**直接 import 并调用编排库**，不经过任何会话。

| 需求 | 实现 |
|---|---|
| **受注册终端证明约束的值班会话** | 登录走一次完整设备远程证明：服务器发一次性挑战随机数，终端用身份密钥对 `(挑战, 当前度量, 封装公钥, 时间戳)` 签名报价。校验签名/度量/封装钥/时间窗后颁发 Bearer 令牌。令牌记录 `token_id`（令牌本身只存哈希），**绑定人员、登录时职责快照、终端、度量/封装钥与证明时效**（默认 30 分钟）。之后每次请求都重验：超时、登出、终端撤销、终端度量或封装钥漂移、终端改绑他人都会令令牌失效（`SESSION_INVALID 401`）。 |
| **查询按职责放行** | 职责（与仪式上的持股角色分开）授予只读 scope（`policies/ceremonies/keys/participants/audit`）。缺 scope 返回 `FORBIDDEN 403`；只读审计员 `erin` 可看审计但不能开仪式/签名。 |
| **敏感修改必须四眼** | 四类受护动作不能直接调用（`POST /api/policies`、`/publish`、`/abort`、DESTROY 的 `commit` 直接命中返回 403 `GUARDED_ACTION`）：`POLICY_REVISE`（修改规则）、`FLOW_ABORT`（终止活动流程）、`PUBLISH`（发布新一代）、`OP_PURGE`（清除退役材料=DESTROY commit）。必须先 `POST /api/orders` 创建**授权单**，再由**另一人员、另一终端、持互补职责**者批准后才原子执行。 |
| **互补职责对（职责分离）** | 请求方↔批准方：`RULES_AUTHOR↔RULES_GOVERNOR`、`FLOW_CONTROLLER↔FLOW_SUPERVISOR`、`RELEASE_MANAGER↔RELEASE_VERIFIER`、`MATERIAL_CUSTODIAN↔MATERIAL_AUDITOR`。同一人不可能同时持有一对职责（授予时强校验）。引导配置中 alice 持所有请求方职责，bruno 持全部互补批准方职责。 |
| **冻结规范化载荷摘要 + 截止时间** | 授权单创建时把载荷投影到该操作允许的字段、规范化排序，冻结 `SHA256` 摘要与 10 分钟截止时间。批准时逐字段重算比对；摘要不符（`claimed_digest` 不一致或存储载荷被改）以 `PAYLOAD_DRIFT` 关单。 |
| **重复提交返回原单** | 同一人员+终端+操作+摘要的重复创建幂等返回原授权单；同一目标的不同摘要请求冲突拒绝。 |
| **并发批准最多执行一次** | 批准在跨线程/跨进程锁内：先落 APPROVE 决策再执行；重复批准得到 `DUPLICATE_ACTION`，底层发布另有 CAS 兜底，任何时刻一个 purpose 只有一个 ACTIVE。 |
| **失败即关单、不落半成品** | 批准前重验：双方令牌有效、双方终端未撤销、四眼（人/终端/职责）、摘要、目标状态预检。任一失败 → 授权单置 `CLOSED`（原因：`DUTY_CONFLICT/PAYLOAD_DRIFT/REQUESTER_SESSION_INVALID/TERMINAL_REVOKED/TARGET_STATE_CHANGED/DEADLINE_EXPIRED`）并落审计，**不执行**。执行中若目标状态已变（CAS 失败等），同样回退为 CLOSED 且无 `result`。 |
| **终端撤销联动** | `RULES_GOVERNOR` 撤销终端会立即吊销其全部会话并关闭其作为请求方的开放授权单。 |
| **重新登录继续** | 同人同终端重新登录会把其 OPEN 授权单重新绑定到新令牌（批准时仍重验冻结的请求方约束）。 |
| **网页** | 控制台展示登录身份（人员/角色/终端/职责/证明倒计时/token 标识）、**可执行动作**（可发起/可批准/可读）和授权单表（状态、冻结摘要、双方身份与终端、决策链、执行结果/关单原因），支持登录/登出、发起、批准、拒绝、撤回，并在 401 时提示重新登录。 |
| **导出/离线核验** | 导出包（`kc-export-v2`）新增 `duty_grants / sessions / orders`：每张授权单记录**双方身份、双方令牌标识、冻结摘要、完整决策链（逐条哈希链接）与执行结果**。离线核验器新增 `four_eyes_orders_ok` 与 `duty_separation_ok`：重算载荷摘要、验决策链、把每条决策与服务签名审计条目交叉比对、校验 APPROVED 单确实满足“不同人+不同终端+互补职责+令牌在册”且在目标状态上留下执行足迹，而 CLOSED/REJECTED/WITHDRAWN 单不得有 `result`。删改任一部分均可离线发现。 |

### 四眼操作 HTTP 流程

```bash
# 0) 终端登录（设备钱包在服务端模拟 HSM 出 quote；真实部署由终端硬件签名）
curl -s -XPOST localhost:8080/api/devices/prepare-login-quote \
  -d '{"device_id":"dev_alice"}'                 # -> challenge + quote
curl -s -XPOST localhost:8080/api/login \
  -d '{"device_id":"dev_alice","quote":{...}}'   # -> token

TOK_A="..."; TOK_B="..."   # alice=请求方终端, bruno=另一终端/互补职责
# 1) 请求方创建授权单（冻结摘要 + 截止时间）
curl -s -XPOST localhost:8080/api/orders -H "Authorization: Bearer $TOK_A" -d '{
  "op":"PUBLISH",
  "payload":{"ceremony_id":"cer_...","expected_active":"kv_..."}}'
# 2) 另一人员/另一终端/互补职责批准（携带自己看到的摘要）
curl -s -XPOST localhost:8080/api/orders/ord_.../approve \
  -H "Authorization: Bearer $TOK_B" -d '{"digest":"<frozen digest>"}'
# 请求方撤回 / 批准方拒绝：
#   POST /api/orders/{id}/withdraw  {"reason":...}
#   POST /api/orders/{id}/reject    {"reason":...}
```

引导新增第五个终端 `dev_erin`（只读 `AUDIT_READ`），用于演示按职责的 403。

---

## 2. 目录结构

```
kc/
  ed25519.py      纯 Python Ed25519（RFC 8032 向量验证）
  crypto.py       MODP-14 Feldman VSS、Shamir/Lagrange、KEM+AEAD 封装、HKDF、规范 JSON
  policy.py       固定角色、策略不可变快照、法定人数规则、阶段常量
  attestation.py  设备钱包（模拟 HSM）、注册记录、报价生成与校验
  ceremony.py     编排器：四仪式 × 六阶段状态机、恢复数学、CAS 发布
  directory.py    密钥版本目录：STAGED/ACTIVE/RETIRING/DESTROYED、签名与验证
  storage.py      文件锁（跨线程可重入 RLock + flock）、原子状态、哈希链审计
  console.py      设备侧代理：证明→取件→验份额→签名确认
  fleet.py        模拟设备机群（每台设备一个 0600 钱包文件）
  desk.py         值班台：职责授予、终端证明登录会话、四眼授权单与决策链
  export.py       记录导出与离线验证（含会话/授权单/决策链交叉核验）
  server.py       HTTP API + 控制台（ThreadingHTTPServer，WatchDesk 门禁）
  console.html    值班控制台 UI（登录身份/动作/授权单）
  bootstrap.py    一键引导固定角色/设备/策略/互补职责（含只读审计员 erin）
  verify_export.py 导出/离线校验 CLI
tests/
  smoke_e2e.py        端到端冒烟
  test_ceremonies.py  21 个场景测试（证明、顺序、恢复、竞态、销毁、篡改检测…）
  test_edge.py        8 个边界测试（超时、VSS 失败、吊销、策略护栏、多用途、并发）
  test_desk.py        30 个值班台测试（会话绑定、四眼关单、漂移/失效/竞态、继续审批…）
  http_e2e.py         HTTP 全流程（门禁、四类授权单、并发批准只执行一次、导出核验）
```

## 3. 快速开始

```bash
# 1) 引导：4 个固定角色 + 设备钱包 + 3-of-4 策略 + 互补值班职责（含只读审计员）
python3 -m kc.bootstrap --root ./kc-data
# 2) 启动控制台/API（不带 --no-bootstrap 时会自动幂等引导）
python3 -m kc.server --root ./kc-data --port 8080
# 浏览器打开 http://127.0.0.1:8080/
```

控制台右上角选择终端（如 `dev_alice`）→ **login (terminal attestation)**
即完成证明登录；页面顶部显示身份/职责/证明时效与可执行动作。发布新一代、
终止流程、清除退役材料、改规则都在“授权单”面板发起，并需另一终端的互补
职责批准（演示：alice 发起、bruno 批准）。

## 4. 一次完整仪式的操作顺序

GENERATE / ROTATE（DESTROY 无投递阶段；BACKUP 见第 6 节）：

1. `POST /api/ceremonies/open` — 冻结策略快照；同 purpose 不允许第二个打开中仪式。
2. 每台设备依次 `POST /api/ceremonies/{id}/attest`（全员，因为这三类仪式要求全员）。
   最后一份证明成功后阶段自动进入 `ATTESTED`，编排器随即分份并进入 `DELIVERED`。
3. 每台设备 `receive`：拉取**仅发给自己**的密封信封 → 设备内解封 → 对照公开
   Feldman 承诺验证份额。失败则设备拒绝确认（`vss_ok=false` 会被策略拒绝）。
4. 至少 **门限个不同参与者**确认，且**必须含 ROOT_OWNER**；到齐后进入 `CONFIRMED`。
   重复确认返回 `DUPLICATE_ACTION`，不影响继续。
5. `commit`：
   - GENERATE/ROTATE 物化密钥版本（GENERATE 直接 ACTIVE；ROTATE 先 STAGED）；
   - DESTROY 零化目标 RETIRING 版本的私钥材料。
6. ROTATE 额外 `publish`（带 `expected_active` 的 CAS）：旧版 → RETIRING，
   新版 → ACTIVE，交接窗口开始。竞态失败返回 `RACE_LOST`，刷新当前指针重试。
   **HTTP 控制台上第 6 步不能直接调用**：先由 RELEASE_MANAGER 终端创建
   `PUBLISH` 授权单，再由另一终端的 RELEASE_VERIFIER 批准（编排库直连仍可
   直接 `publish_rotation`）。DESTROY 的 `commit`（清除退役材料）同理走
   `OP_PURGE` 四眼授权单。

## 5. 签名测试接口

```bash
curl -s -XPOST localhost:8080/api/sign   -d '{"purpose":"root-signing","message":"hello"}'
curl -s -XPOST localhost:8080/api/verify -d '{"purpose":"root-signing","message":"hello","sig":"..."}'
```

- 签名响应带 `version_id/version/status/fingerprint`；只有 ACTIVE 可签。
- 验证接受该 purpose 全部历史版本，返回匹配版本状态（`active:true/false`）；
  对 DESTROYED 版本的历史签名依然返回 `valid:true,status:DESTROYED`。

## 6. 份额丢失 / 参与者丢失恢复

```jsonc
// 打开 BACKUP：bruno 永久丢失，finn 以同角色替补
POST /api/ceremonies/open
{"kind":"BACKUP","policy_id":"pol-root-v1","purpose":"root-signing","actor":"alice",
 "lost_participants":["bruno"],
 "replacement_specs":[{"participant_id":"finn","role":"KEY_STEWARD",
                       "device_id":"dev_finn","replaces":"bruno"}]}
```

- 恢复名册（存活者+替补）全员 attest；
- 仅**存活者**（≥ 门限）用各自持有的旧仪式份额 `submit-share`，编排端逐份用
  当前密钥承诺校验，入站份额仅以服务包装密文短暂存放、完成后清除；
- 门限到达后在同一秘密上重建并重新分份（新随机多项式）；
- 恢复名册全员 receive、验份额、门限确认（含 owner）→ commit；
- 密钥 id 与签名公钥不变，承诺列更新、`share_meta` 指向新持有者。

纯粹的份额丢失（人还在、HSM 被擦）则 `lost_participants` 留空，全员提交/领取即可。

## 7. 可验证记录导出

```bash
# 从状态目录导出
python3 -m kc.verify_export --from-store ./kc-data --outdir ./export
# 在任意机器上离线核验（不需要状态目录或任何秘密）
python3 -m kc.verify_export ./export/export.json
# 也可 GET /api/export 获取签名包；GET /api/audit 查看链验证结果
```

输出 `[PASS] bundle_signature_ok / audit_chain_ok /
single_active_per_purpose / handover_consistent`。

## 8. HTTP API 摘要

除 `/health`、控制台页面与登录握手外，所有接口都需要
`Authorization: Bearer <token>`（终端证明登录获得）。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/devices/prepare-login-quote` | 演示辅助：服务端钱包代终端出登录报价 |
| POST | `/api/login/challenge` `/api/login` | 登录挑战 / 报价换令牌（证明绑定） |
| POST | `/api/logout` | 登出（令牌立即失效） |
| GET | `/api/me` | 当前登录身份 + 可发起/可批准动作 + 可读 scopes |
| GET | `/api/orders` `/api/orders/{id}` | 授权单列表/详情（冻结摘要、决策链、结果） |
| POST | `/api/orders` | 发起授权单（`op` ∈ POLICY_REVISE/FLOW_ABORT/PUBLISH/OP_PURGE） |
| POST | `/api/orders/{id}/approve` `/reject` `/withdraw` | 互补职责批准（原子执行）/拒绝/请求方撤回 |
| POST | `/api/devices/revoke` | 撤销终端（RULES_GOVERNOR；杀会话、关开放单） |
| POST | `/api/duty-grants` | 调整职责授予（RULES_GOVERNOR，禁止持有同一对互补职责） |
| POST | `/api/participants` | 注册参与者并配发设备（RULES_GOVERNOR） |
| POST | `/api/ceremonies/open` | 开仪式（CEREMONY_EXEC，动作人取自会话） |
| POST | `/api/ceremonies/{id}/attest` `/receive` `/confirm` `/submit-share` | 设备步骤（CEREMONY_EXEC，**必须本会话绑定终端**） |
| POST | `/api/ceremonies/{id}/commit` | 提交（DESTROY 的 commit 受护：改走 OP_PURGE 授权单） |
| — | `/api/policies`、`/publish`、`/abort` | **直接调用一律 403 GUARDED_ACTION**，改走授权单 |
| POST | `/api/sign` `/api/verify` | 签名（CEREMONY_EXEC）/ 验签（keys 只读即可） |
| GET | `/api/keys` `/api/ceremonies` `/api/policies` `/api/participants` `/api/audit` `/api/export` | 只读视图（按职责 scope 放行） |

错误码：`POLICY_VIOLATION(422)`、`CONFLICT_STATE/DUPLICATE_ACTION/REPLAY_DETECTED/RACE_LOST/ORDER_DECIDED(409)`、
`ATTESTATION_FAILED/SESSION_INVALID/AUTH_FAILED(401)`、`FORBIDDEN(403)`、
`NOT_FOUND(404)`、`TAMPER_DETECTED(409)`。
关单原因：`DUTY_CONFLICT / PAYLOAD_DRIFT / REQUESTER_SESSION_INVALID /
TERMINAL_REVOKED / TARGET_STATE_CHANGED / DEADLINE_EXPIRED`。

## 9. 持久化与并发模型

- `state.json`：所有可变记录，锁内加载、原子临时文件 rename 落盘。
- `audit.log`：每行一个 JSON，追加写 + `fsync`，哈希链 + 服务签名。
- `.lock`：跨进程 flock；进程内按数据目录共享一把可重入 RLock。
  HTTP 服务多线程、多进程部署都被串行化，且每个请求在**锁内**读取最新状态。
- 重启后状态、密封私钥、审计链均可恢复；`tests/smoke_e2e.py` 覆盖重启验证。

## 10. 密码学说明（生产化注意）

本实现是**完整可运行的参考实现**，数学与协议真实（Ed25519 通过 RFC 8032 向量、
Feldman VSS 逐份验证、安全素数群子群一致性）。生产部署时建议：

- 份额多项式生成与签名运算放入真实 HSM/飞地；本系统的 `DeviceWallet` 是其软件模型；
- 用 FIPS 验证的模块化指数实现（当前为教学级纯 Python 2048 位运算）；
- 服务主包装密钥换成 KMS/HSM LMK；设备证明对接 TPM Quote/Nitro/TPM 证书链；
- mTLS/网络层加固：当前控制台绑定 `127.0.0.1`，身份控制由终端证明会话 +
  四眼授权单承担（令牌不透明、按请求重验终端状态）；跨机部署应在其外再叠加
  mTLS。`/api/devices/prepare-login-quote` 是演示辅助（模拟 HSM 出 quote），
  生产中报价必须由终端硬件产生并经 TPM/HSM 证书链校验。

## 11. 测试

```bash
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge tests.test_desk -v
python3 tests/http_e2e.py 8211     # 门禁 + 四类四眼授权单 + 并发批准
```
