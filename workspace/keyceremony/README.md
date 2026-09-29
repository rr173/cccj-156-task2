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
  export.py       记录导出与离线验证
  server.py       HTTP API + 控制台（ThreadingHTTPServer）
  console.html    仪式控制台 UI
  bootstrap.py    一键引导固定角色/设备/策略
  verify_export.py 导出/离线校验 CLI
tests/
  smoke_e2e.py        端到端冒烟
  test_ceremonies.py  21 个场景测试（证明、顺序、恢复、竞态、销毁、篡改检测…）
  test_edge.py        8 个边界测试（超时、VSS 失败、吊销、策略护栏、多用途、并发）
  http_e2e.py         HTTP 全流程含 8 路并发发布竞态
```

## 3. 快速开始

```bash
# 1) 引导：4 个固定角色 + 设备钱包 + 3-of-4 策略
python3 -m kc.bootstrap --root ./kc-data
# 2) 启动控制台/API
python3 -m kc.server --root ./kc-data --port 8080
# 浏览器打开 http://127.0.0.1:8080/
```

控制台按钮对应一次仪式一步（每台设备独立证明、取件、验份额、确认）。

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

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/participants` | 注册参与者并自动配发设备钱包 |
| POST | `/api/participants` / `/api/policies` | 参与者 / 不可变策略 |
| POST | `/api/ceremonies/open` | 开仪式（GENERATE/ROTATE/BACKUP/DESTROY） |
| POST | `/api/ceremonies/{id}/attest` | 设备证明 |
| POST | `/api/ceremonies/{id}/receive` | 取密封份额（设备内验证） |
| POST | `/api/ceremonies/{id}/confirm` | 门限确认（必须含 owner） |
| POST | `/api/ceremonies/{id}/submit-share` | BACKUP 存活者提交旧份额 |
| POST | `/api/ceremonies/{id}/commit` | 法定人数齐备后提交 |
| POST | `/api/ceremonies/{id}/publish` | ROTATE CAS 发布 |
| POST | `/api/ceremonies/{id}/abort` | 废弃本轮（审计保留） |
| POST | `/api/sign` `/api/verify` | 签名测试接口 |
| GET | `/api/keys` `/api/ceremonies` `/api/audit` `/api/export` | 只读视图 |

错误码：`POLICY_VIOLATION(422)`、`CONFLICT_STATE/DUPLICATE_ACTION/REPLAY_DETECTED/RACE_LOST(409)`、
`ATTESTATION_FAILED/AUTH_FAILED(401)`、`NOT_FOUND(404)`、`TAMPER_DETECTED(409)`。

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
- mTLS + 操作员身份认证（当前 API 信任本地调用者，动作信封层已防伪造与重放）。

## 11. 测试

```bash
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge -v
python3 tests/http_e2e.py 8211     # 含 8 路并发轮换发布
```
