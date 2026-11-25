# leakguard · 防敏感字段泄漏的离线导出与独立验证器

纯 **原生 Windows + Python 3.12 标准库** 实现；输入全部为本地合成数据，无第三方依赖、无网络。

一条命令完成全部题面要求并给出可判定的通过/失败报告：

```bat
python run_all.py
```

成功时退出码 `0`，并生成 `artifacts/RUN_REPORT.json`；任一硬性性质不满足则退出码 `1`。

单独运行**独立验证器**（单文件、不导入本包、只扫描磁盘上的实际发布文件）：

```bat
python verify_release.py artifacts\main\release --require-manifest --canaries artifacts\main\canaries.json
```

单元测试：

```bat
python -m unittest discover -s tests -v
```

---

## 题面要求 ↔ 实现位置

| 要求 | 实现 |
| --- | --- |
| 每份索引绑定**接收租户 / 用途 / 策略代号 / 实际内容摘要** | `leakguard/publisher.py: build_envelope`，信封 `bindings{tenant,purpose,policy,content_digest}`；摘要为正文规范化 JSON 的 SHA-256，另有 `source_digest` 绑定原始对象 |
| **同源批准不得算两份** | `leakguard/approvals.py` 以 `source_key` 幂等；`grant()` 重复提交返回 `created=False`；场景 D 用两个真实线程并发提交同一来源，计数仍为 1，重启重放仍为 1 |
| **撤销一组不影响另一组独立授权** | 批准按 `group_id` 归属，`revoke_group()` 只写该组墓碑；主演示撤销 `grp-alpha` 后 A1–A3 回退，`grp-beta` 的 B1/B2 仍 `allowed` 且保持发布 |
| **屏障 + 两个真实线程复现：撤销先写 / 字段落盘但回执丢失 / 同号异摘要** | `leakguard/lab.py`，每个场景均为两个 `threading.Thread` + `threading.Barrier(2)`（A 另用 `Event` 固定“首次授权→撤销先写→过屏障复检”的顺序） |
| **重启后报告历史可见索引与当前可见集合** | 丢弃内存对象，用 `ApprovalLedger.load` + 新 `Publisher(...).recover()` 从磁盘重放；`visibility_report()` 给出 `history_visible_ids` 与 `current_visible_ids` |
| **不同标记置入嵌套列表 / 跨页重复字典 / 空字段** | `leakguard/synthdata.py`：`ZMARK-NESTED-*` 置于深层嵌套列表，`ZMARK-XPAGE-*` 置于 A1/A2 共享并跨页重复的 `party` 字典，`ZMARK-EMPTY-*` 置于被策略重建为空串的 `legal_hold`；负例另把标记放进“空值的键名”和“空字符串键”之下 |
| **独立验证器扫描实际发布文件** | 根目录 `verify_release.py`：递归字典键+值、嵌套列表、不跳过 `"" / [] / {} / None`；原始文本正则兜底；校验四绑定与摘要；识别同号异摘要；复核 manifest 哈希与未登记文件 |
| **6 万本地对象计数 + 复核一次更新的实际读取/改写范围** | `leakguard/bench.py`：128 分片 JSONL；计量器记录实际读/写文件、字节、编解码对象数；再用独立的全树文件哈希与全对象摘要前后差分复核：仅目标分片被读/写、磁盘仅 1 个分片变化、仅 1 个对象摘要变化 |

## 发布/恢复状态机（崩溃一致性）

```
0. 首次授权判定
1. [屏障] 提交前从磁盘 reload 账本并再次授权      —— 撤销先写 => PUBLISH_DENIED
2. 同号异摘要 CAS（current.json 中的 content_digest）—— 冲突 => release/conflicts/
3. journal: PUBLISH_INTENT
4. 最终字段原子落盘 release/indices/<id>.json（临时文件 + fsync + os.replace）
5. journal: MATERIALIZED（此刻起“历史可见”）
6. 可注入崩溃：字段已 durable，但回执/current 尚未写
7. 原子写回执 release/receipts/<id>.receipt.json
8. 原子更新 current.json（当前可见集合）
9. journal: PUBLISH_COMMIT
```

重启 `recover()` 对“有字段、无 current/回执”的文件，依据 **journal 来源 + 当前授权 + 摘要一致**
幂等补提交；授权已失效则移入 `withdrawn/`；无来源或摘要不符则移入 `quarantine/`；
`release/conflicts/` 候选在重启后隔离保全，当前集合只保留 CAS 胜者。重复恢复不产生第二次提交。

## 目录与产物

```
verify_release.py          # 独立验证器（不 import leakguard）
run_all.py                 # 端到端：导出→验证→撤销→重启→负例→屏障实验→60k 复核
leakguard/                 # 导出/账本/状态机/分页/基准/屏障实验
tests/                     # unittest 关键不变量
artifacts/                 # 运行后生成（.gitignore 已忽略）
  main/release/            # 真正被验证器扫描的实际发布树（indices/pages/receipts/manifest）
  lab/A_*/ B_*/ C_*/ D_*/  # 三场景+并发去重的磁盘现场与重启报告
  negative/                # 证明验证器“有牙齿”的带毒夹具
  bench/store/             # 60000 个分片对象
  reports/                 # 各次独立验证器的 JSON 报告
  RUN_REPORT.json          # 汇总断言（success / passed_checks / lab / bench ...）
```

## 安全说明

所有证件号、卡号、密钥字面量与 `ZMARK-*` 均为本地人造金丝雀样本，不对应任何真实主体。
策略层默认拒绝（仅白名单字段进入索引正文），随后做递归敏感键清理与标记模式替换；
独立验证器使用一份**刻意分开维护**的规则，避免与导出器共享同一盲点。
