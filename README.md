# 编排关键技术攻关路线协作基础服务

本项目提供科技创新协作场景共用的服务端基础能力，用于登记科研机构、创新节点、操作者和结构化业务资料，并提供角色权限、请求幂等、SQLite 事务与哈希串联审计。重大项目、科研证据、成果转化和国际合作等领域可以在这些稳定边界上扩展自己的状态、规则和接口。

在此之上实现了**关键技术堵点与攻关路线服务**：把目标指标、部件依赖、候选方案、试验批次、证据有效期、保密级别、团队承诺和设施窗口编成可计算的攻关路线图。

## 攻关路线规则

- **同源识别**：堵点登记时按源头键归一化（大小写、全半角、空格、标点不敏感），伪装成不同名称的同源堵点被归为一组并自动发起 `alias_merge` 待决裁定；裁定批准后指定基准堵点。
- **循环依赖**：写入部件依赖时沿依赖图检测环路，成环即拒绝。
- **入口证据门禁**：只有候选方案要求的入口证据全部在有效期内的团队才能获得限时设施租约；同一窗口的并发确认由数据库唯一约束保证只有一个成功，其余按优先级进入候补。
- **冻结候补**：窗口到达冻结时点后候补顺序固定，之后加入者一律追加队尾；租约释放或到期时按冻结顺序推进，证据已失效的候补被跳过。
- **只重算未完成路径**：试验失败（方案挂起）、指标降级（留修订记录）、替代路线启用（记录切换代价）和证据过期只触发未验证堵点的状态重算；试验批次由数据库触发器保证只增不改，已验证堵点不受影响。
- **分级可见**：总师（chief）查看关键路径、全部等待原因与涉密证据细节；课题负责人（lead）只看本团队堵点，证据按密级打码，跨团队访问被拒绝。
- **重启恢复**：租约、候补与未决裁定持久化在 SQLite，服务启动时自动推进到期租约并恢复待办裁定。

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

第一条命令验收基础登记链与幂等回执；第二条命令演练完整攻关场景：三团队同源堵点识别、循环依赖拒绝、证据门禁、并发确认唯一成功、冻结候补推进、试验失败启用替代路线、指标降级、证据按密级披露以及重启恢复。成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.api --database science_strategy.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。写入接口通过 `X-Actor-Id` 标识操作者，服务重启后 SQLite 中的业务状态和审计历史继续保留。

攻关路线接口（写入均需要 `request_id` 幂等键）：

- `POST /roadmap/bottlenecks`、`/roadmap/dependencies`、`/roadmap/commitments`、`/roadmap/solutions`、`/roadmap/solution-activations`、`/roadmap/evidence`、`/roadmap/facilities`、`/roadmap/windows`：登记路线图要素；
- `POST /roadmap/resource-confirmations`、`/roadmap/lease-releases`：确认限时资源、释放租约并推进候补；
- `POST /roadmap/test-batches`、`/roadmap/metric-downgrades`、`/roadmap/adjudication-resolutions`：记录试验事实、指标降级与裁定结案；
- `GET /roadmap/roadmap`、`/roadmap/critical-path`、`/roadmap/waiting-reasons`、`/roadmap/switch-cost`、`/roadmap/evidence`、`/roadmap/leases`、`/roadmap/adjudications`、`/roadmap/same-origin`：按角色过滤的路线图视图。
