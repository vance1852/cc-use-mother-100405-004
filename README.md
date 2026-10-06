# 编排关键技术攻关路线协作基础服务

本项目提供科技创新协作场景共用的服务端基础能力，用于登记科研机构、创新节点、操作者和结构化业务资料，并提供角色权限、请求幂等、SQLite 事务与哈希串联审计。重大项目、科研证据、成果转化和国际合作等领域可以在这些稳定边界上扩展自己的状态、规则和接口。

在此之上，本项目还实现了关键技术堵点与攻关路线服务（`roadmap.py`）：把目标指标、部件依赖、候选方案、试验批次、证据有效期、保密级别、团队承诺和设施窗口编成可计算的攻关路线图。

- 部件依赖在写入时识别并拒绝循环依赖；堵点来源名称归一化后，伪装成不同名称的同源堵点自动归并到同一根堵点；
- 只有满足入口证据（未过期）的启用方案才能获得限时资源租约；多个团队并发确认资源时，通过原子状态迁移保证只有一个成功结果；
- 租约释放或到期后，候补队列按释放瞬间冻结的顺序推进，未在确认期限内确认的裁定自动落空并顺次推进；
- 试验失败、指标降级、替代路线启用和证据过期只重算尚未完成的路径；已经形成的试验事实（`test_batches` 与 `resolutions`）不可删除、不可改写；
- 总师（`chief_engineer`）与课题负责人（`project_lead`）通过权限不同的接口分别查看关键路径、等待原因、方案切换代价和可披露证据（负责人看不到 `confidential` 级证据，且只能看到本团队相关的堵点）；
- 租约与未决裁定持久化在 SQLite 中，服务重启后通过 `GET /roadmap/recovery` 恢复，`POST /roadmap/sweep` 可恢复推进到期的租约与裁定。

## 目录

- `src/science_strategy_foundation/`：领域模型、SQLite 存储、权限服务、审计链、攻关路线服务、HTTP 路由和离线验收；
- `tests/`：基础规则、事务边界、接口路由、攻关路线规则和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.acceptance
PYTHONPATH=src python3 -m science_strategy_foundation.roadmap_acceptance
```

第一条命令在临时 SQLite 数据库中登记科研机构、操作者、创新节点和业务资料，核对幂等回执与审计链；第二条命令走一遍完整攻关链（同源堵点归并、循环依赖拒绝、入口证据门控、候补冻结推进、试验事实冻结、未完成路径重算、重启恢复和权限化视图）。两条命令成功时都输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.api --database science_strategy.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。写入接口通过 `X-Actor-Id` 标识操作者，服务重启后 SQLite 中的业务状态和审计历史继续保留。

攻关路线接口统一挂在 `/roadmap` 前缀下，主要包括：

- 写入：`POST /roadmap/bottlenecks`、`/roadmap/dependencies`、`/roadmap/metrics`、`/roadmap/metrics/degrade`、`/roadmap/solutions`、`/roadmap/solutions/activate`、`/roadmap/evidence`、`/roadmap/evidence/expire-sweep`、`/roadmap/commitments`、`/roadmap/commitments/fulfill`、`/roadmap/windows`、`/roadmap/leases`、`/roadmap/leases/release`、`/roadmap/waitlist`、`/roadmap/adjudications/confirm`、`/roadmap/test-batches`、`/roadmap/test-batches/record`、`/roadmap/sweep`；
- 视图：`GET /roadmap/bottlenecks`、`/roadmap/bottlenecks/detail`、`/roadmap/critical-path`、`/roadmap/wait-reasons`、`/roadmap/switch-costs`、`/roadmap/evidence`、`/roadmap/recompute-events`、`/roadmap/recovery`。

所有写入接口都接受 `request_id` 做幂等；同一 `request_id` 重放返回首次结果，内容不同则返回 409。
