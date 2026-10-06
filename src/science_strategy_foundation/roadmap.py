"""关键技术堵点与攻关路线服务。

把目标指标、部件依赖、候选方案、试验批次、证据有效期、保密级别、
团队承诺和设施窗口编成可计算的攻关路线图：

- 依赖图在写入时识别并拒绝循环依赖；
- 堵点来源名称归一化，伪装成不同名称的同源堵点归并到同一根堵点；
- 只有满足入口证据（未过期）的启用方案才能获得限时资源租约；
- 试验失败、指标降级、替代路线启用和证据过期只重算尚未完成的路径，
  已经形成的试验事实（resolutions 与 test_batches）不可删除、不可改写；
- 多个团队并发确认资源时，通过原子状态迁移保证只有一个成功结果；
- 租约释放或到期后，候补队列按释放瞬间冻结的顺序推进；
- 总师与课题负责人通过权限不同的视图分别看到关键路径、等待原因、
  方案切换代价和可披露证据；
- 租约与未决裁定持久化在 SQLite 中，服务重启后仍可恢复。
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import parse_qs

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import Actor
from .storage import Database

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
SOURCE_KEY_NOISE = re.compile(r"[\s\-_·•,，、/\\()（）\[\]【】{}:：]+")

CHIEF_ROLES = ("chief_engineer", "admin")
LEAD_ROLE = "project_lead"
VIEW_ROLES = ("chief_engineer", "admin", "project_lead")
CONFIDENTIALITY_LEVELS = ("open", "internal", "confidential")
LEAD_VISIBLE_LEVELS = ("open", "internal")
METRIC_DIRECTIONS = ("at_least", "at_most")
TEST_RESULTS = ("passed", "failed")

# 方案切换代价 = 备选方案基础代价 + 当前方案有效租约数 * LEASE_PENALTY
#                + 当前方案在途试验批次数 * BATCH_PENALTY
LEASE_PENALTY = 1.0
BATCH_PENALTY = 0.5


def normalize_source_key(source_name: str) -> str:
    """归一化堵点来源名称，让伪装成不同名称的同源堵点落到同一个键上。"""

    text = unicodedata.normalize("NFKC", str(source_name)).lower()
    text = SOURCE_KEY_NOISE.sub("", text)
    if not text:
        raise ValidationError("source_name 归一化后不能为空")
    return text


class RoadmapService:
    """协调攻关路线的登记、门控、租约、候补、裁定和重算规则。"""

    def __init__(self, database: Database, clock: Clock | None = None, *,
                 confirm_ttl_seconds: int = 3600) -> None:
        self.database = database
        self.clock = clock or SystemClock()
        if not isinstance(confirm_ttl_seconds, int) or confirm_ttl_seconds <= 0:
            raise ValueError("confirm_ttl_seconds 必须是正整数")
        self.confirm_ttl_seconds = confirm_ttl_seconds

    # ---------- 基础工具 ----------

    def _now_dt(self) -> datetime:
        return self.clock.now().astimezone(timezone.utc).replace(microsecond=0)

    def _now(self) -> str:
        return self._now_dt().isoformat().replace("+00:00", "Z")

    def _after(self, seconds: int) -> str:
        return (self._now_dt() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def _parse_time(self, value: str, field: str) -> str:
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} 时间格式无效") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 200) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _number(self, value: Any, field: str) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"{field} 必须是数字") from exc
        if math.isnan(result) or math.isinf(result):
            raise ValidationError(f"{field} 必须是有限数字")
        return result

    def _non_negative_int(self, value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationError(f"{field} 必须是非负整数")
        return value

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"], row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _require(self, actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _require_team(self, actor: Actor, team_id: str) -> None:
        if actor.role in CHIEF_ROLES:
            return
        if actor.role == LEAD_ROLE and actor.organization_id == team_id:
            return
        raise PermissionDenied("课题负责人只能操作本团队的资源")

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any], create: Callable[[], tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute("SELECT * FROM request_receipts WHERE request_id=?", (request_id,)).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            response = json.loads(row["response_json"])
            response["replayed"] = True
            return response
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,response_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id, canonical_json(response), self._now()),
        )
        response["replayed"] = False
        return response

    # ---------- 堵点与同源归并 ----------

    def _root_bottleneck(self, connection, bottleneck_id: str):
        row = connection.execute("SELECT * FROM bottlenecks WHERE bottleneck_id=?", (bottleneck_id,)).fetchone()
        if row is None:
            raise NotFoundError("堵点不存在")
        if row["root_bottleneck_id"]:
            row = connection.execute(
                "SELECT * FROM bottlenecks WHERE bottleneck_id=?", (row["root_bottleneck_id"],)
            ).fetchone()
        return row

    def _is_resolved(self, connection, bottleneck_id: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM resolutions WHERE bottleneck_id=?", (bottleneck_id,)
        ).fetchone() is not None

    def _stakeholder_team_ids(self, connection, root_id: str) -> set[str]:
        rows = connection.execute(
            "SELECT owner_team_id FROM bottlenecks WHERE bottleneck_id=? OR root_bottleneck_id=?",
            (root_id, root_id),
        ).fetchall()
        return {row["owner_team_id"] for row in rows}

    def _require_stakeholder(self, connection, actor: Actor, root_id: str) -> None:
        if actor.role in CHIEF_ROLES:
            return
        if actor.role == LEAD_ROLE and actor.organization_id in self._stakeholder_team_ids(connection, root_id):
            return
        raise PermissionDenied("只能操作本团队相关的堵点")

    def register_bottleneck(self, *, request_id: str, actor_id: str, site_id: str, name: str,
                            source_name: str, owner_team_id: str, confidentiality: str = "internal",
                            estimate_days: int = 0) -> dict[str, Any]:
        """登记堵点；来源名称归一化后相同的堵点自动归并到既有根堵点。"""

        payload = {"actor_id": actor_id, "site_id": site_id, "name": name, "source_name": source_name,
                   "owner_team_id": owner_team_id, "confidentiality": confidentiality,
                   "estimate_days": estimate_days}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            if connection.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone() is None:
                raise NotFoundError("场所不存在")
            owner_team_id = self._identifier(owner_team_id, "owner_team_id")
            if connection.execute(
                "SELECT 1 FROM organizations WHERE organization_id=?", (owner_team_id,)
            ).fetchone() is None:
                raise NotFoundError("负责团队不存在")
            if actor.role == LEAD_ROLE and actor.organization_id != owner_team_id:
                raise PermissionDenied("课题负责人只能为本团队登记堵点")
            name = self._text(name, "name")
            source_key = normalize_source_key(self._text(source_name, "source_name"))
            if confidentiality not in CONFIDENTIALITY_LEVELS:
                raise ValidationError("confidentiality 不在允许范围内")
            estimate_days = self._non_negative_int(estimate_days, "estimate_days")

            def create() -> tuple[str, str, dict[str, Any]]:
                root = connection.execute(
                    "SELECT * FROM bottlenecks WHERE site_id=? AND source_key=? AND root_bottleneck_id IS NULL",
                    (site_id, source_key),
                ).fetchone()
                bottleneck_id = uuid.uuid4().hex
                now = self._now()
                if root is not None:
                    connection.execute(
                        "INSERT INTO bottlenecks(bottleneck_id,site_id,name,source_key,root_bottleneck_id,"
                        "owner_team_id,confidentiality,estimate_days,status,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (bottleneck_id, site_id, name, source_key, root["bottleneck_id"], owner_team_id,
                         confidentiality, estimate_days, "merged", actor_id, now),
                    )
                    append_event(connection, actor_id=actor_id, action="roadmap.bottleneck.merged",
                                 resource_type="bottleneck", resource_id=bottleneck_id,
                                 detail={"name": name, "source_key": source_key,
                                         "root_bottleneck_id": root["bottleneck_id"],
                                         "owner_team_id": owner_team_id}, occurred_at=now)
                    return "bottleneck", bottleneck_id, {
                        "bottleneck_id": bottleneck_id, "root_bottleneck_id": root["bottleneck_id"],
                        "root_name": root["name"], "merged": True, "source_key": source_key}
                connection.execute(
                    "INSERT INTO bottlenecks(bottleneck_id,site_id,name,source_key,root_bottleneck_id,"
                    "owner_team_id,confidentiality,estimate_days,status,created_by,created_at) "
                    "VALUES(?,?,?,?,NULL,?,?,?,?,?,?)",
                    (bottleneck_id, site_id, name, source_key, owner_team_id,
                     confidentiality, estimate_days, "open", actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.bottleneck.registered",
                             resource_type="bottleneck", resource_id=bottleneck_id,
                             detail={"name": name, "source_key": source_key, "owner_team_id": owner_team_id},
                             occurred_at=now)
                return "bottleneck", bottleneck_id, {
                    "bottleneck_id": bottleneck_id, "root_bottleneck_id": bottleneck_id,
                    "root_name": name, "merged": False, "source_key": source_key}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_bottleneck", payload=payload, create=create)

    # ---------- 部件依赖与循环识别 ----------

    def _depends_on_parents(self, connection, start_id: str) -> dict[str, str | None]:
        """沿“依赖于”方向遍历，返回每个可达节点的父指针（用于还原循环路径）。"""

        parents: dict[str, str | None] = {start_id: None}
        stack = [start_id]
        while stack:
            node = stack.pop()
            rows = connection.execute(
                "SELECT upstream_id FROM dependencies WHERE downstream_id=?", (node,)
            ).fetchall()
            for row in rows:
                upstream = row["upstream_id"]
                if upstream not in parents:
                    parents[upstream] = node
                    stack.append(upstream)
        return parents

    def add_dependency(self, *, request_id: str, actor_id: str,
                       upstream_id: str, downstream_id: str) -> dict[str, Any]:
        """登记部件依赖：downstream 的攻关依赖 upstream 先完成；写入时识别循环依赖。"""

        payload = {"actor_id": actor_id, "upstream_id": upstream_id, "downstream_id": downstream_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)
            upstream = self._root_bottleneck(connection, upstream_id)
            downstream = self._root_bottleneck(connection, downstream_id)
            if upstream["bottleneck_id"] == downstream["bottleneck_id"]:
                raise ValidationError("堵点不能依赖自身")
            if upstream["site_id"] != downstream["site_id"]:
                raise ValidationError("不能跨场所建立部件依赖")
            parents = self._depends_on_parents(connection, upstream["bottleneck_id"])
            if downstream["bottleneck_id"] in parents:
                cycle = [downstream["bottleneck_id"]]
                node = parents[downstream["bottleneck_id"]]
                while node is not None:
                    cycle.append(node)
                    node = parents[node]
                cycle.reverse()
                cycle.append(downstream["bottleneck_id"])
                raise ConflictError("部件依赖形成循环: " + " -> ".join(cycle))

            def create() -> tuple[str, str, dict[str, Any]]:
                existing = connection.execute(
                    "SELECT 1 FROM dependencies WHERE upstream_id=? AND downstream_id=?",
                    (upstream["bottleneck_id"], downstream["bottleneck_id"]),
                ).fetchone()
                if existing:
                    raise ConflictError("依赖关系已存在")
                dependency_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO dependencies(dependency_id,site_id,upstream_id,downstream_id,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (dependency_id, upstream["site_id"], upstream["bottleneck_id"],
                     downstream["bottleneck_id"], actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.dependency.added",
                             resource_type="dependency", resource_id=dependency_id,
                             detail={"upstream_id": upstream["bottleneck_id"],
                                     "downstream_id": downstream["bottleneck_id"]}, occurred_at=now)
                return "dependency", dependency_id, {
                    "dependency_id": dependency_id,
                    "upstream_id": upstream["bottleneck_id"],
                    "downstream_id": downstream["bottleneck_id"]}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.add_dependency", payload=payload, create=create)

    # ---------- 目标指标 ----------

    def register_metric(self, *, request_id: str, actor_id: str, bottleneck_id: str, name: str,
                        unit: str, target_value: Any, direction: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id, "name": name, "unit": unit,
                   "target_value": target_value, "direction": direction}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)
            root = self._root_bottleneck(connection, bottleneck_id)
            name = self._text(name, "name", 80)
            unit = self._text(unit, "unit", 40)
            target = self._number(target_value, "target_value")
            if direction not in METRIC_DIRECTIONS:
                raise ValidationError("direction 必须是 at_least 或 at_most")

            def create() -> tuple[str, str, dict[str, Any]]:
                metric_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO target_metrics(metric_id,bottleneck_id,name,unit,direction,target_value,"
                    "degraded,version,created_by,created_at) VALUES(?,?,?,?,?,?,0,1,?,?)",
                    (metric_id, root["bottleneck_id"], name, unit, direction, target, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.metric.registered",
                             resource_type="metric", resource_id=metric_id,
                             detail={"bottleneck_id": root["bottleneck_id"], "name": name,
                                     "target_value": target, "direction": direction}, occurred_at=now)
                return "metric", metric_id, {"metric_id": metric_id,
                                             "bottleneck_id": root["bottleneck_id"], "version": 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_metric", payload=payload, create=create)

    def degrade_metric(self, *, request_id: str, actor_id: str, metric_id: str,
                       new_target_value: Any) -> dict[str, Any]:
        """指标降级：只触发尚未完成路径的重算，已完成的堵点不允许降级。"""

        payload = {"actor_id": actor_id, "metric_id": metric_id, "new_target_value": new_target_value}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)
            metric = connection.execute(
                "SELECT * FROM target_metrics WHERE metric_id=?", (metric_id,)
            ).fetchone()
            if metric is None:
                raise NotFoundError("指标不存在")
            root_id = metric["bottleneck_id"]
            if self._is_resolved(connection, root_id):
                raise ConflictError("堵点已完成，指标不能降级")
            new_target = self._number(new_target_value, "new_target_value")
            old_target = metric["target_value"]
            if metric["direction"] == "at_least" and not new_target < old_target:
                raise ValidationError("降级后的指标必须低于原目标")
            if metric["direction"] == "at_most" and not new_target > old_target:
                raise ValidationError("降级后的指标必须高于原目标上限")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                connection.execute(
                    "UPDATE target_metrics SET target_value=?, degraded=1, version=version+1 WHERE metric_id=?",
                    (new_target, metric_id),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.metric.degraded",
                             resource_type="metric", resource_id=metric_id,
                             detail={"bottleneck_id": root_id, "old_target": old_target,
                                     "new_target": new_target}, occurred_at=now)
                affected = self._recompute(connection, trigger="metric_degraded",
                                           origin_ids=[root_id], actor_id=actor_id)
                return "metric", metric_id, {"metric_id": metric_id, "target_value": new_target,
                                             "version": metric["version"] + 1, "recomputed": affected}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.degrade_metric", payload=payload, create=create)

    # ---------- 候选方案 ----------

    def register_solution(self, *, request_id: str, actor_id: str, bottleneck_id: str, name: str,
                          required_evidence: Any = (), priority: int = 0,
                          switch_cost: Any = 0.0) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id, "name": name,
                   "required_evidence": list(required_evidence), "priority": priority,
                   "switch_cost": switch_cost}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            root = self._root_bottleneck(connection, bottleneck_id)
            self._require_stakeholder(connection, actor, root["bottleneck_id"])
            if self._is_resolved(connection, root["bottleneck_id"]):
                raise ConflictError("堵点已完成，不能新增方案")
            name = self._text(name, "name")
            if not isinstance(required_evidence, (list, tuple)):
                raise ValidationError("required_evidence 必须是数组")
            evidence_types: list[str] = []
            for item in required_evidence:
                text = self._text(item, "required_evidence", 80)
                if text not in evidence_types:
                    evidence_types.append(text)
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValidationError("priority 必须是整数")
            cost = self._number(switch_cost, "switch_cost")
            if cost < 0:
                raise ValidationError("switch_cost 不能为负数")

            def create() -> tuple[str, str, dict[str, Any]]:
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM solutions WHERE bottleneck_id=?",
                    (root["bottleneck_id"],),
                ).fetchone()["count"]
                status = "active" if count == 0 else "standby"
                solution_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO solutions(solution_id,bottleneck_id,name,required_evidence_json,priority,"
                    "switch_cost,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (solution_id, root["bottleneck_id"], name, canonical_json(evidence_types),
                     priority, cost, status, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.solution.registered",
                             resource_type="solution", resource_id=solution_id,
                             detail={"bottleneck_id": root["bottleneck_id"], "name": name,
                                     "required_evidence": evidence_types, "status": status}, occurred_at=now)
                return "solution", solution_id, {"solution_id": solution_id,
                                                 "bottleneck_id": root["bottleneck_id"],
                                                 "status": status}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_solution", payload=payload, create=create)

    def activate_solution(self, *, request_id: str, actor_id: str, solution_id: str) -> dict[str, Any]:
        """启用替代路线：原启用方案转为被替代，只重算尚未完成的路径。"""

        payload = {"actor_id": actor_id, "solution_id": solution_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)
            solution = connection.execute(
                "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
            ).fetchone()
            if solution is None:
                raise NotFoundError("候选方案不存在")
            root_id = solution["bottleneck_id"]
            if self._is_resolved(connection, root_id):
                raise ConflictError("堵点已完成，不能切换方案")
            if solution["status"] == "failed":
                raise ValidationError("已失败的方案不能启用")
            if solution["status"] == "active":
                raise ConflictError("方案已处于启用状态")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                connection.execute(
                    "UPDATE solutions SET status='replaced' WHERE bottleneck_id=? AND status='active'",
                    (root_id,),
                )
                connection.execute("UPDATE solutions SET status='active' WHERE solution_id=?", (solution_id,))
                append_event(connection, actor_id=actor_id, action="roadmap.solution.activated",
                             resource_type="solution", resource_id=solution_id,
                             detail={"bottleneck_id": root_id}, occurred_at=now)
                affected = self._recompute(connection, trigger="route_activated",
                                           origin_ids=[root_id], actor_id=actor_id)
                return "solution", solution_id, {"solution_id": solution_id, "status": "active",
                                                 "recomputed": affected}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.activate_solution", payload=payload, create=create)

    # ---------- 证据与有效期 ----------

    def register_evidence(self, *, request_id: str, actor_id: str, bottleneck_id: str,
                          evidence_type: str, confidentiality: str, expires_at: str,
                          payload: Any = None, solution_id: str | None = None) -> dict[str, Any]:
        evidence_payload = payload if payload is not None else {}
        idem_payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id,
                        "evidence_type": evidence_type, "confidentiality": confidentiality,
                        "expires_at": expires_at, "payload": evidence_payload,
                        "solution_id": solution_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            root = self._root_bottleneck(connection, bottleneck_id)
            self._require_stakeholder(connection, actor, root["bottleneck_id"])
            evidence_type = self._text(evidence_type, "evidence_type", 80)
            if confidentiality not in CONFIDENTIALITY_LEVELS:
                raise ValidationError("confidentiality 不在允许范围内")
            expires = self._parse_time(expires_at, "expires_at")
            if expires <= self._now():
                raise ValidationError("证据有效期必须晚于当前时间")
            if not isinstance(evidence_payload, dict):
                raise ValidationError("payload 必须是对象")
            if solution_id is not None:
                solution = connection.execute(
                    "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
                ).fetchone()
                if solution is None or solution["bottleneck_id"] != root["bottleneck_id"]:
                    raise ValidationError("方案不属于该堵点")

            def create() -> tuple[str, str, dict[str, Any]]:
                evidence_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO evidence_items(evidence_id,bottleneck_id,solution_id,evidence_type,"
                    "confidentiality,payload_json,expires_at,expired_notified,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,0,?,?)",
                    (evidence_id, root["bottleneck_id"], solution_id, evidence_type, confidentiality,
                     canonical_json(evidence_payload), expires, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.evidence.registered",
                             resource_type="evidence", resource_id=evidence_id,
                             detail={"bottleneck_id": root["bottleneck_id"], "evidence_type": evidence_type,
                                     "confidentiality": confidentiality, "expires_at": expires},
                             occurred_at=now)
                return "evidence", evidence_id, {"evidence_id": evidence_id,
                                                 "bottleneck_id": root["bottleneck_id"],
                                                 "expires_at": expires}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_evidence", payload=idem_payload, create=create)

    def _missing_evidence(self, connection, solution, now: str) -> list[str]:
        """计算方案当前缺少的入口证据类型（过期证据不计入）。"""

        required = json.loads(solution["required_evidence_json"])
        if not required:
            return []
        rows = connection.execute(
            "SELECT DISTINCT evidence_type FROM evidence_items "
            "WHERE bottleneck_id=? AND (solution_id IS NULL OR solution_id=?) AND expires_at > ?",
            (solution["bottleneck_id"], solution["solution_id"], now),
        ).fetchall()
        available = {row["evidence_type"] for row in rows}
        return [item for item in required if item not in available]

    def expire_evidence_sweep(self, *, request_id: str, actor_id: str) -> dict[str, Any]:
        """把已过期的证据标记出来，并只重算受影响的未完成路径。"""

        payload = {"actor_id": actor_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                rows = connection.execute(
                    "SELECT * FROM evidence_items WHERE expires_at <= ? AND expired_notified=0", (now,)
                ).fetchall()
                expired_ids: list[str] = []
                origins: set[str] = set()
                for row in rows:
                    connection.execute(
                        "UPDATE evidence_items SET expired_notified=1 WHERE evidence_id=?",
                        (row["evidence_id"],),
                    )
                    append_event(connection, actor_id=actor_id, action="roadmap.evidence.expired",
                                 resource_type="evidence", resource_id=row["evidence_id"],
                                 detail={"bottleneck_id": row["bottleneck_id"],
                                         "evidence_type": row["evidence_type"],
                                         "expires_at": row["expires_at"]}, occurred_at=now)
                    expired_ids.append(row["evidence_id"])
                    origins.add(row["bottleneck_id"])
                affected = self._recompute(connection, trigger="evidence_expired",
                                           origin_ids=sorted(origins), actor_id=actor_id) if origins else []
                return "evidence_sweep", "evidence_sweep", {"expired": expired_ids, "recomputed": affected}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.expire_evidence_sweep", payload=payload, create=create)

    # ---------- 团队承诺 ----------

    def register_commitment(self, *, request_id: str, actor_id: str, bottleneck_id: str,
                            team_id: str, promise_date: str, note: str = "") -> dict[str, Any]:
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id, "team_id": team_id,
                   "promise_date": promise_date, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            root = self._root_bottleneck(connection, bottleneck_id)
            team_id = self._identifier(team_id, "team_id")
            if connection.execute(
                "SELECT 1 FROM organizations WHERE organization_id=?", (team_id,)
            ).fetchone() is None:
                raise NotFoundError("承诺团队不存在")
            self._require_team(actor, team_id)
            promise = self._parse_time(promise_date, "promise_date")
            note = str(note or "").strip()[:500]

            def create() -> tuple[str, str, dict[str, Any]]:
                commitment_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO commitments(commitment_id,bottleneck_id,team_id,promise_date,note,status,"
                    "created_by,created_at) VALUES(?,?,?,?,?,'active',?,?)",
                    (commitment_id, root["bottleneck_id"], team_id, promise, note, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.commitment.registered",
                             resource_type="commitment", resource_id=commitment_id,
                             detail={"bottleneck_id": root["bottleneck_id"], "team_id": team_id,
                                     "promise_date": promise}, occurred_at=now)
                return "commitment", commitment_id, {"commitment_id": commitment_id,
                                                     "bottleneck_id": root["bottleneck_id"],
                                                     "team_id": team_id, "status": "active"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_commitment", payload=payload, create=create)

    def fulfill_commitment(self, *, request_id: str, actor_id: str, commitment_id: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "commitment_id": commitment_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            commitment = connection.execute(
                "SELECT * FROM commitments WHERE commitment_id=?", (commitment_id,)
            ).fetchone()
            if commitment is None:
                raise NotFoundError("承诺不存在")
            self._require_team(actor, commitment["team_id"])

            def create() -> tuple[str, str, dict[str, Any]]:
                cursor = connection.execute(
                    "UPDATE commitments SET status='fulfilled' WHERE commitment_id=? AND status='active'",
                    (commitment_id,),
                )
                if cursor.rowcount == 0:
                    raise ConflictError("承诺已履行")
                append_event(connection, actor_id=actor_id, action="roadmap.commitment.fulfilled",
                             resource_type="commitment", resource_id=commitment_id,
                             detail={"bottleneck_id": commitment["bottleneck_id"],
                                     "team_id": commitment["team_id"]}, occurred_at=self._now())
                return "commitment", commitment_id, {"commitment_id": commitment_id, "status": "fulfilled"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.fulfill_commitment", payload=payload, create=create)

    # ---------- 设施窗口与限时租约 ----------

    def register_window(self, *, request_id: str, actor_id: str, facility_id: str, site_id: str,
                        starts_at: str, ends_at: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "facility_id": facility_id, "site_id": site_id,
                   "starts_at": starts_at, "ends_at": ends_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)
            if connection.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone() is None:
                raise NotFoundError("场所不存在")
            facility_id = self._identifier(facility_id, "facility_id")
            starts = self._parse_time(starts_at, "starts_at")
            ends = self._parse_time(ends_at, "ends_at")
            if not starts < ends:
                raise ValidationError("窗口开始时间必须早于结束时间")

            def create() -> tuple[str, str, dict[str, Any]]:
                overlap = connection.execute(
                    "SELECT 1 FROM facility_windows WHERE facility_id=? AND status IN ('open','offered','leased') "
                    "AND NOT (ends_at <= ? OR starts_at >= ?)",
                    (facility_id, starts, ends),
                ).fetchone()
                if overlap:
                    raise ConflictError("设施窗口时间重叠")
                window_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO facility_windows(window_id,facility_id,site_id,starts_at,ends_at,status,"
                    "created_by,created_at) VALUES(?,?,?,?,?,'open',?,?)",
                    (window_id, facility_id, site_id, starts, ends, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.window.registered",
                             resource_type="facility_window", resource_id=window_id,
                             detail={"facility_id": facility_id, "starts_at": starts, "ends_at": ends},
                             occurred_at=now)
                return "window", window_id, {"window_id": window_id, "facility_id": facility_id,
                                             "starts_at": starts, "ends_at": ends, "status": "open"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_window", payload=payload, create=create)

    def acquire_lease(self, *, request_id: str, actor_id: str, window_id: str, solution_id: str,
                      team_id: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        """申请限时资源：只有满足入口证据的启用方案才能获得租约，并发占用只有一个成功。"""

        payload = {"actor_id": actor_id, "window_id": window_id, "solution_id": solution_id,
                   "team_id": team_id, "ttl_seconds": ttl_seconds}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            team_id = self._identifier(team_id, "team_id")
            self._require_team(actor, team_id)
            window = connection.execute(
                "SELECT * FROM facility_windows WHERE window_id=?", (window_id,)
            ).fetchone()
            if window is None:
                raise NotFoundError("设施窗口不存在")
            now = self._now()
            if window["ends_at"] <= now:
                raise ConflictError("设施窗口已结束")
            solution = connection.execute(
                "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
            ).fetchone()
            if solution is None:
                raise NotFoundError("候选方案不存在")
            if self._is_resolved(connection, solution["bottleneck_id"]):
                raise ConflictError("堵点已完成，无需申请资源")
            if solution["status"] != "active":
                raise ConflictError("只有启用中的方案可以申请限时资源")
            missing = self._missing_evidence(connection, solution, now)
            if missing:
                raise ConflictError("入口证据未满足: " + ",".join(missing))
            ttl = None
            if ttl_seconds is not None:
                if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
                    raise ValidationError("ttl_seconds 必须是正整数")
                ttl = ttl_seconds

            def create() -> tuple[str, str, dict[str, Any]]:
                cursor = connection.execute(
                    "UPDATE facility_windows SET status='leased' WHERE window_id=? AND status='open'",
                    (window_id,),
                )
                if cursor.rowcount == 0:
                    raise ConflictError("设施窗口已被占用")
                lease_id = uuid.uuid4().hex
                acquired = self._now()
                expires_at = window["ends_at"] if ttl is None else min(window["ends_at"], self._after(ttl))
                connection.execute(
                    "INSERT INTO leases(lease_id,window_id,solution_id,team_id,status,acquired_at,expires_at,"
                    "created_by) VALUES(?,?,?,?,'active',?,?,?)",
                    (lease_id, window_id, solution_id, team_id, acquired, expires_at, actor_id),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.lease.acquired",
                             resource_type="lease", resource_id=lease_id,
                             detail={"window_id": window_id, "solution_id": solution_id,
                                     "team_id": team_id, "expires_at": expires_at}, occurred_at=acquired)
                return "lease", lease_id, {"lease_id": lease_id, "window_id": window_id,
                                           "solution_id": solution_id, "team_id": team_id,
                                           "expires_at": expires_at, "status": "active"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.acquire_lease", payload=payload, create=create)

    def release_lease(self, *, request_id: str, actor_id: str, lease_id: str) -> dict[str, Any]:
        """释放租约：候补队列按释放瞬间冻结的顺序推进。"""

        payload = {"actor_id": actor_id, "lease_id": lease_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            lease = connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if lease is None:
                raise NotFoundError("租约不存在")
            self._require_team(actor, lease["team_id"])

            def create() -> tuple[str, str, dict[str, Any]]:
                cursor = connection.execute(
                    "UPDATE leases SET status='released' WHERE lease_id=? AND status='active'", (lease_id,)
                )
                if cursor.rowcount == 0:
                    raise ConflictError("租约不在有效状态")
                now = self._now()
                append_event(connection, actor_id=actor_id, action="roadmap.lease.released",
                             resource_type="lease", resource_id=lease_id,
                             detail={"window_id": lease["window_id"], "team_id": lease["team_id"]},
                             occurred_at=now)
                adjudication = self._promote_waitlist(connection, lease["window_id"], actor_id)
                response: dict[str, Any] = {"lease_id": lease_id, "status": "released",
                                            "window_id": lease["window_id"]}
                if adjudication is not None:
                    response["adjudication"] = adjudication
                return "lease", lease_id, response

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.release_lease", payload=payload, create=create)

    # ---------- 候补队列与裁定 ----------

    def join_waitlist(self, *, request_id: str, actor_id: str, window_id: str, solution_id: str,
                      team_id: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "window_id": window_id, "solution_id": solution_id,
                   "team_id": team_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            team_id = self._identifier(team_id, "team_id")
            self._require_team(actor, team_id)
            window = connection.execute(
                "SELECT * FROM facility_windows WHERE window_id=?", (window_id,)
            ).fetchone()
            if window is None:
                raise NotFoundError("设施窗口不存在")
            if window["status"] == "open":
                raise ConflictError("设施窗口空闲，请直接申请租约")
            if window["status"] == "closed" or window["ends_at"] <= self._now():
                raise ConflictError("设施窗口已结束")
            solution = connection.execute(
                "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
            ).fetchone()
            if solution is None:
                raise NotFoundError("候选方案不存在")
            if solution["status"] != "active":
                raise ConflictError("只有启用中的方案可以排队候补")
            if self._is_resolved(connection, solution["bottleneck_id"]):
                raise ConflictError("堵点已完成，无需排队候补")

            def create() -> tuple[str, str, dict[str, Any]]:
                duplicate = connection.execute(
                    "SELECT 1 FROM waitlist_entries WHERE window_id=? AND team_id=? "
                    "AND status IN ('waiting','frozen','promoted')",
                    (window_id, team_id),
                ).fetchone()
                if duplicate:
                    raise ConflictError("该团队已在候补队列中")
                position = connection.execute(
                    "SELECT COALESCE(MAX(position),0)+1 AS next FROM waitlist_entries WHERE window_id=?",
                    (window_id,),
                ).fetchone()["next"]
                entry_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO waitlist_entries(entry_id,window_id,solution_id,team_id,position,status,"
                    "frozen_seq,created_by,created_at) VALUES(?,?,?,?,?,'waiting',NULL,?,?)",
                    (entry_id, window_id, solution_id, team_id, position, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.waitlist.joined",
                             resource_type="waitlist_entry", resource_id=entry_id,
                             detail={"window_id": window_id, "solution_id": solution_id,
                                     "team_id": team_id, "position": position}, occurred_at=now)
                return "waitlist_entry", entry_id, {"entry_id": entry_id, "window_id": window_id,
                                                    "position": position, "status": "waiting"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.join_waitlist", payload=payload, create=create)

    def _gate_waitlist_entry(self, connection, entry, now: str) -> list[str] | None:
        """检查候补条目是否仍满足推进条件；返回缺失项列表，满足时返回 None。"""

        solution = connection.execute(
            "SELECT * FROM solutions WHERE solution_id=?", (entry["solution_id"],)
        ).fetchone()
        if solution is None or solution["status"] != "active":
            return ["active_solution"]
        return self._missing_evidence(connection, solution, now) or None

    def _offer_entry(self, connection, entry, window_id: str, freeze_seq: int,
                     actor_id: str) -> dict[str, Any]:
        adjudication_id = uuid.uuid4().hex
        now = self._now()
        confirm_by = self._after(self.confirm_ttl_seconds)
        connection.execute(
            "UPDATE waitlist_entries SET status='promoted' WHERE entry_id=?", (entry["entry_id"],)
        )
        connection.execute(
            "INSERT INTO adjudications(adjudication_id,window_id,entry_id,solution_id,team_id,freeze_seq,"
            "status,offered_at,confirm_by,confirmed_at) VALUES(?,?,?,?,?,?,'pending',?,?,NULL)",
            (adjudication_id, window_id, entry["entry_id"], entry["solution_id"], entry["team_id"],
             freeze_seq, now, confirm_by),
        )
        connection.execute(
            "UPDATE facility_windows SET status='offered' WHERE window_id=?", (window_id,)
        )
        append_event(connection, actor_id=actor_id, action="roadmap.waitlist.promoted",
                     resource_type="adjudication", resource_id=adjudication_id,
                     detail={"window_id": window_id, "entry_id": entry["entry_id"],
                             "team_id": entry["team_id"], "freeze_seq": freeze_seq,
                             "confirm_by": confirm_by}, occurred_at=now)
        return {"adjudication_id": adjudication_id, "window_id": window_id,
                "entry_id": entry["entry_id"], "solution_id": entry["solution_id"],
                "team_id": entry["team_id"], "freeze_seq": freeze_seq,
                "confirm_by": confirm_by, "status": "pending"}

    def _promote_waitlist(self, connection, window_id: str, actor_id: str) -> dict[str, Any] | None:
        """租约释放后按冻结规则推进候补：冻结当前队列快照，队首且满足入口证据者获得限时裁定。"""

        entries = connection.execute(
            "SELECT * FROM waitlist_entries WHERE window_id=? AND status='waiting' ORDER BY position, entry_id",
            (window_id,),
        ).fetchall()
        if not entries:
            connection.execute(
                "UPDATE facility_windows SET status='open' WHERE window_id=?", (window_id,)
            )
            return None
        freeze_seq = connection.execute(
            "SELECT COALESCE(MAX(freeze_seq),0)+1 AS seq FROM adjudications WHERE window_id=?",
            (window_id,),
        ).fetchone()["seq"]
        now = self._now()
        for entry in entries:
            connection.execute(
                "UPDATE waitlist_entries SET status='frozen', frozen_seq=? WHERE entry_id=?",
                (freeze_seq, entry["entry_id"]),
            )
        for entry in entries:
            missing = self._gate_waitlist_entry(connection, entry, now)
            if missing is not None:
                connection.execute(
                    "UPDATE waitlist_entries SET status='lapsed' WHERE entry_id=?", (entry["entry_id"],)
                )
                append_event(connection, actor_id=actor_id, action="roadmap.waitlist.lapsed",
                             resource_type="waitlist_entry", resource_id=entry["entry_id"],
                             detail={"window_id": window_id, "missing": missing}, occurred_at=now)
                continue
            return self._offer_entry(connection, entry, window_id, freeze_seq, actor_id)
        connection.execute(
            "UPDATE facility_windows SET status='open' WHERE window_id=?", (window_id,)
        )
        return None

    def _advance_frozen(self, connection, adjudication, actor_id: str) -> dict[str, Any] | None:
        """裁定落空后在同一冻结轮次内推进；没有剩余候补则解冻并重新开放窗口。"""

        window_id = adjudication["window_id"]
        entries = connection.execute(
            "SELECT * FROM waitlist_entries WHERE window_id=? AND status='frozen' AND frozen_seq=? "
            "ORDER BY position, entry_id",
            (window_id, adjudication["freeze_seq"]),
        ).fetchall()
        now = self._now()
        for entry in entries:
            missing = self._gate_waitlist_entry(connection, entry, now)
            if missing is not None:
                connection.execute(
                    "UPDATE waitlist_entries SET status='lapsed' WHERE entry_id=?", (entry["entry_id"],)
                )
                append_event(connection, actor_id=actor_id, action="roadmap.waitlist.lapsed",
                             resource_type="waitlist_entry", resource_id=entry["entry_id"],
                             detail={"window_id": window_id, "missing": missing}, occurred_at=now)
                continue
            return self._offer_entry(connection, entry, window_id,
                                     adjudication["freeze_seq"], actor_id)
        connection.execute(
            "UPDATE facility_windows SET status='open' WHERE window_id=?", (window_id,)
        )
        return None

    def confirm_adjudication(self, *, request_id: str, actor_id: str, adjudication_id: str,
                             team_id: str) -> dict[str, Any]:
        """确认裁定获得租约：并发确认只有一个成功，超过确认期限的裁定先落空再推进候补。"""

        team_id = self._identifier(team_id, "team_id")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            self._require_team(actor, team_id)
            adjudication = connection.execute(
                "SELECT * FROM adjudications WHERE adjudication_id=?", (adjudication_id,)
            ).fetchone()
            if adjudication is None:
                raise NotFoundError("裁定不存在")
            if adjudication["team_id"] != team_id:
                raise PermissionDenied("只有被裁定的团队可以确认资源")
            expired = False
            if adjudication["status"] == "pending" and adjudication["confirm_by"] <= self._now():
                now = self._now()
                connection.execute(
                    "UPDATE adjudications SET status='lapsed' WHERE adjudication_id=?", (adjudication_id,)
                )
                connection.execute(
                    "UPDATE waitlist_entries SET status='lapsed' WHERE entry_id=? AND status='promoted'",
                    (adjudication["entry_id"],),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.adjudication.lapsed",
                             resource_type="adjudication", resource_id=adjudication_id,
                             detail={"window_id": adjudication["window_id"],
                                     "team_id": adjudication["team_id"]}, occurred_at=now)
                self._advance_frozen(connection, adjudication, actor_id)
                expired = True
        if expired:
            raise ConflictError("裁定已过确认期限，候补已按冻结规则推进")

        payload = {"actor_id": actor_id, "adjudication_id": adjudication_id, "team_id": team_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            self._require_team(actor, team_id)
            adjudication = connection.execute(
                "SELECT * FROM adjudications WHERE adjudication_id=?", (adjudication_id,)
            ).fetchone()

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                if adjudication["status"] != "pending":
                    raise ConflictError("裁定已被处理")
                if adjudication["confirm_by"] <= now:
                    raise ConflictError("裁定已过确认期限")
                cursor = connection.execute(
                    "UPDATE adjudications SET status='confirmed', confirmed_at=? "
                    "WHERE adjudication_id=? AND status='pending'",
                    (now, adjudication_id),
                )
                if cursor.rowcount == 0:
                    raise ConflictError("裁定已被处理")
                window = connection.execute(
                    "SELECT * FROM facility_windows WHERE window_id=?",
                    (adjudication["window_id"],),
                ).fetchone()
                connection.execute(
                    "UPDATE facility_windows SET status='leased' WHERE window_id=?",
                    (adjudication["window_id"],),
                )
                lease_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO leases(lease_id,window_id,solution_id,team_id,status,acquired_at,expires_at,"
                    "created_by) VALUES(?,?,?,?,'active',?,?,?)",
                    (lease_id, adjudication["window_id"], adjudication["solution_id"], team_id,
                     now, window["ends_at"], actor_id),
                )
                connection.execute(
                    "UPDATE waitlist_entries SET status='confirmed' WHERE entry_id=?",
                    (adjudication["entry_id"],),
                )
                connection.execute(
                    "UPDATE waitlist_entries SET status='waiting', frozen_seq=NULL "
                    "WHERE window_id=? AND status='frozen' AND frozen_seq=?",
                    (adjudication["window_id"], adjudication["freeze_seq"]),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.adjudication.confirmed",
                             resource_type="adjudication", resource_id=adjudication_id,
                             detail={"window_id": adjudication["window_id"], "team_id": team_id,
                                     "lease_id": lease_id}, occurred_at=now)
                return "lease", lease_id, {"adjudication_id": adjudication_id, "lease_id": lease_id,
                                           "status": "confirmed", "team_id": team_id,
                                           "window_id": adjudication["window_id"],
                                           "expires_at": window["ends_at"]}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.confirm_adjudication", payload=payload, create=create)

    def sweep_expired(self, *, request_id: str, actor_id: str) -> dict[str, Any]:
        """集中处理到期租约与过期裁定；服务重启后也可调用以恢复推进。"""

        payload = {"actor_id": actor_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *CHIEF_ROLES)

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                expired_leases = connection.execute(
                    "SELECT * FROM leases WHERE status='active' AND expires_at <= ?", (now,)
                ).fetchall()
                promotions: list[dict[str, Any]] = []
                for lease in expired_leases:
                    connection.execute(
                        "UPDATE leases SET status='expired' WHERE lease_id=?", (lease["lease_id"],)
                    )
                    append_event(connection, actor_id=actor_id, action="roadmap.lease.expired",
                                 resource_type="lease", resource_id=lease["lease_id"],
                                 detail={"window_id": lease["window_id"], "team_id": lease["team_id"]},
                                 occurred_at=now)
                    window = connection.execute(
                        "SELECT * FROM facility_windows WHERE window_id=?", (lease["window_id"],)
                    ).fetchone()
                    if window["status"] == "leased":
                        adjudication = self._promote_waitlist(connection, lease["window_id"], actor_id)
                        if adjudication is not None:
                            promotions.append(adjudication)
                pending = connection.execute(
                    "SELECT * FROM adjudications WHERE status='pending' AND confirm_by <= ?", (now,)
                ).fetchall()
                lapsed_ids: list[str] = []
                for adjudication in pending:
                    connection.execute(
                        "UPDATE adjudications SET status='lapsed' WHERE adjudication_id=?",
                        (adjudication["adjudication_id"],),
                    )
                    connection.execute(
                        "UPDATE waitlist_entries SET status='lapsed' WHERE entry_id=? AND status='promoted'",
                        (adjudication["entry_id"],),
                    )
                    append_event(connection, actor_id=actor_id, action="roadmap.adjudication.lapsed",
                                 resource_type="adjudication", resource_id=adjudication["adjudication_id"],
                                 detail={"window_id": adjudication["window_id"],
                                         "team_id": adjudication["team_id"]}, occurred_at=now)
                    follow = self._advance_frozen(connection, adjudication, actor_id)
                    if follow is not None:
                        promotions.append(follow)
                    lapsed_ids.append(adjudication["adjudication_id"])
                closed = connection.execute(
                    "UPDATE facility_windows SET status='closed' WHERE status='open' AND ends_at <= ?",
                    (now,),
                ).rowcount
                return "sweep", "sweep", {
                    "expired_leases": [lease["lease_id"] for lease in expired_leases],
                    "lapsed_adjudications": lapsed_ids,
                    "promotions": promotions,
                    "closed_windows": closed}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.sweep_expired", payload=payload, create=create)

    # ---------- 试验批次与不可删除的事实 ----------

    def register_test_batch(self, *, request_id: str, actor_id: str, solution_id: str,
                            lease_id: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "solution_id": solution_id, "lease_id": lease_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            solution = connection.execute(
                "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
            ).fetchone()
            if solution is None:
                raise NotFoundError("候选方案不存在")
            lease = connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if lease is None:
                raise NotFoundError("租约不存在")
            if lease["solution_id"] != solution_id:
                raise ValidationError("租约与方案不匹配")
            if lease["status"] != "active":
                raise ConflictError("租约不在有效状态")
            if lease["expires_at"] <= self._now():
                raise ConflictError("租约已过期")
            self._require_team(actor, lease["team_id"])
            window = connection.execute(
                "SELECT * FROM facility_windows WHERE window_id=?", (lease["window_id"],)
            ).fetchone()

            def create() -> tuple[str, str, dict[str, Any]]:
                batch_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO test_batches(batch_id,solution_id,lease_id,facility_id,result,measured_json,"
                    "recorded_by,recorded_at,created_by,created_at) VALUES(?,?,?,?,'pending',NULL,NULL,NULL,?,?)",
                    (batch_id, solution_id, lease_id, window["facility_id"], actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="roadmap.test_batch.registered",
                             resource_type="test_batch", resource_id=batch_id,
                             detail={"solution_id": solution_id, "lease_id": lease_id,
                                     "facility_id": window["facility_id"]}, occurred_at=now)
                return "test_batch", batch_id, {"batch_id": batch_id, "solution_id": solution_id,
                                                "lease_id": lease_id,
                                                "facility_id": window["facility_id"],
                                                "result": "pending"}

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.register_test_batch", payload=payload, create=create)

    def record_test_result(self, *, request_id: str, actor_id: str, batch_id: str, result: str,
                           measured: Any = None) -> dict[str, Any]:
        """记录试验结果：事实一旦形成不能修改或删除；通过则冻结解决事实，失败则重算未完成路径。"""

        if result not in TEST_RESULTS:
            raise ValidationError("result 必须是 passed 或 failed")
        measured = measured if measured is not None else {}
        if not isinstance(measured, dict):
            raise ValidationError("measured 必须是对象")
        payload = {"actor_id": actor_id, "batch_id": batch_id, "result": result, "measured": measured}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *VIEW_ROLES)
            batch = connection.execute(
                "SELECT * FROM test_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if batch is None:
                raise NotFoundError("试验批次不存在")
            solution = connection.execute(
                "SELECT * FROM solutions WHERE solution_id=?", (batch["solution_id"],)
            ).fetchone()
            lease = connection.execute(
                "SELECT * FROM leases WHERE lease_id=?", (batch["lease_id"],)
            ).fetchone()
            self._require_team(actor, lease["team_id"])
            root_id = solution["bottleneck_id"]

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                cursor = connection.execute(
                    "UPDATE test_batches SET result=?, measured_json=?, recorded_by=?, recorded_at=? "
                    "WHERE batch_id=? AND result='pending'",
                    (result, canonical_json(measured), actor_id, now, batch_id),
                )
                if cursor.rowcount == 0:
                    raise ConflictError("试验事实已经形成，不能修改或删除")
                append_event(connection, actor_id=actor_id, action="roadmap.test.result_recorded",
                             resource_type="test_batch", resource_id=batch_id,
                             detail={"solution_id": batch["solution_id"], "bottleneck_id": root_id,
                                     "result": result}, occurred_at=now)
                response: dict[str, Any] = {"batch_id": batch_id, "result": result,
                                            "solution_id": batch["solution_id"],
                                            "bottleneck_id": root_id}
                if result == "passed":
                    if not self._is_resolved(connection, root_id):
                        connection.execute(
                            "INSERT INTO resolutions(bottleneck_id,solution_id,batch_id,resolved_at) "
                            "VALUES(?,?,?,?)",
                            (root_id, batch["solution_id"], batch_id, now),
                        )
                        append_event(connection, actor_id=actor_id, action="roadmap.bottleneck.resolved",
                                     resource_type="bottleneck", resource_id=root_id,
                                     detail={"solution_id": batch["solution_id"], "batch_id": batch_id},
                                     occurred_at=now)
                        response["resolved"] = True
                    else:
                        response["resolved"] = False
                else:
                    connection.execute(
                        "UPDATE solutions SET status='failed' WHERE solution_id=?",
                        (batch["solution_id"],),
                    )
                    response["recomputed"] = self._recompute(
                        connection, trigger="test_failed", origin_ids=[root_id], actor_id=actor_id)
                return "test_batch", batch_id, response

            return self._idempotent(connection, request_id=request_id,
                                    action="roadmap.record_test_result", payload=payload, create=create)

    # ---------- 只重算未完成路径 ----------

    def _recompute(self, connection, *, trigger: str, origin_ids: list[str],
                   actor_id: str) -> list[str]:
        """从触发堵点沿依赖方向重算；已完成的堵点保持试验事实，不重算也不再向下游传播。"""

        resolved = {
            row["bottleneck_id"]
            for row in connection.execute("SELECT bottleneck_id FROM resolutions").fetchall()
        }
        downstreams: dict[str, list[str]] = {}
        for row in connection.execute("SELECT upstream_id, downstream_id FROM dependencies").fetchall():
            downstreams.setdefault(row["upstream_id"], []).append(row["downstream_id"])
        affected: list[str] = []
        seen: set[str] = set()
        stack = list(origin_ids)
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            if node in resolved:
                continue
            affected.append(node)
            stack.extend(downstreams.get(node, []))
        if affected:
            event_id = uuid.uuid4().hex
            now = self._now()
            connection.execute(
                "INSERT INTO recompute_events(event_id,trigger,affected_json,created_by,created_at) "
                "VALUES(?,?,?,?,?)",
                (event_id, trigger, canonical_json(sorted(affected)), actor_id, now),
            )
            append_event(connection, actor_id=actor_id, action="roadmap.roadmap.recomputed",
                         resource_type="recompute_event", resource_id=event_id,
                         detail={"trigger": trigger, "affected": sorted(affected)}, occurred_at=now)
        return sorted(affected)

    # ---------- 权限化视图 ----------

    def _readonly_actor(self, actor_id: str) -> Actor:
        return self._actor(self.database.connection, actor_id)

    def _visible_roots(self, connection, actor: Actor) -> list:
        rows = connection.execute(
            "SELECT * FROM bottlenecks WHERE root_bottleneck_id IS NULL ORDER BY created_at, bottleneck_id"
        ).fetchall()
        if actor.role in CHIEF_ROLES:
            return list(rows)
        return [row for row in rows
                if actor.organization_id in self._stakeholder_team_ids(connection, row["bottleneck_id"])]

    def list_bottlenecks(self, actor_id: str) -> dict[str, Any]:
        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        items = []
        for root in self._visible_roots(connection, actor):
            aliases = connection.execute(
                "SELECT bottleneck_id, name, owner_team_id FROM bottlenecks WHERE root_bottleneck_id=? "
                "ORDER BY created_at, bottleneck_id",
                (root["bottleneck_id"],),
            ).fetchall()
            active = connection.execute(
                "SELECT solution_id FROM solutions WHERE bottleneck_id=? AND status='active'",
                (root["bottleneck_id"],),
            ).fetchone()
            items.append({
                "bottleneck_id": root["bottleneck_id"],
                "name": root["name"],
                "source_key": root["source_key"],
                "owner_team_id": root["owner_team_id"],
                "confidentiality": root["confidentiality"],
                "estimate_days": root["estimate_days"],
                "resolved": self._is_resolved(connection, root["bottleneck_id"]),
                "active_solution_id": active["solution_id"] if active else None,
                "aliases": [dict(alias) for alias in aliases],
            })
        return {"items": items, "generated_at": self._now()}

    def bottleneck_detail(self, actor_id: str, bottleneck_id: str) -> dict[str, Any]:
        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        root = self._root_bottleneck(connection, bottleneck_id)
        root_id = root["bottleneck_id"]
        self._require_stakeholder(connection, actor, root_id)
        now = self._now()
        aliases = connection.execute(
            "SELECT bottleneck_id, name, owner_team_id FROM bottlenecks WHERE root_bottleneck_id=? "
            "ORDER BY created_at, bottleneck_id", (root_id,),
        ).fetchall()
        metrics = connection.execute(
            "SELECT metric_id, name, unit, direction, target_value, degraded, version FROM target_metrics "
            "WHERE bottleneck_id=? ORDER BY created_at, metric_id", (root_id,),
        ).fetchall()
        solutions = []
        for row in connection.execute(
            "SELECT * FROM solutions WHERE bottleneck_id=? ORDER BY priority, created_at, solution_id",
            (root_id,),
        ).fetchall():
            solutions.append({
                "solution_id": row["solution_id"],
                "name": row["name"],
                "status": row["status"],
                "priority": row["priority"],
                "switch_cost": row["switch_cost"],
                "required_evidence": json.loads(row["required_evidence_json"]),
                "missing_evidence": self._missing_evidence(connection, row, now),
            })
        upstream = connection.execute(
            "SELECT upstream_id FROM dependencies WHERE downstream_id=? ORDER BY upstream_id", (root_id,)
        ).fetchall()
        downstream = connection.execute(
            "SELECT downstream_id FROM dependencies WHERE upstream_id=? ORDER BY downstream_id", (root_id,)
        ).fetchall()
        resolution = connection.execute(
            "SELECT * FROM resolutions WHERE bottleneck_id=?", (root_id,)
        ).fetchone()
        commitments = connection.execute(
            "SELECT commitment_id, team_id, promise_date, note, status FROM commitments "
            "WHERE bottleneck_id=? ORDER BY created_at, commitment_id", (root_id,),
        ).fetchall()
        return {
            "bottleneck_id": root_id,
            "name": root["name"],
            "source_key": root["source_key"],
            "owner_team_id": root["owner_team_id"],
            "confidentiality": root["confidentiality"],
            "estimate_days": root["estimate_days"],
            "resolved": resolution is not None,
            "resolution": dict(resolution) if resolution else None,
            "aliases": [dict(alias) for alias in aliases],
            "metrics": [dict(metric) for metric in metrics],
            "solutions": solutions,
            "dependencies": {
                "upstream": [row["upstream_id"] for row in upstream],
                "downstream": [row["downstream_id"] for row in downstream],
            },
            "commitments": [dict(commitment) for commitment in commitments],
            "generated_at": now,
        }

    def critical_path(self, actor_id: str) -> dict[str, Any]:
        """关键路径：在未完成堵点的依赖子图上计算最长工期链；课题负责人只看本团队相关范围。"""

        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        roots = [row for row in self._visible_roots(connection, actor)
                 if not self._is_resolved(connection, row["bottleneck_id"])]
        ids = {row["bottleneck_id"] for row in roots}
        estimates = {row["bottleneck_id"]: row["estimate_days"] for row in roots}
        names = {row["bottleneck_id"]: row["name"] for row in roots}
        owners = {row["bottleneck_id"]: row["owner_team_id"] for row in roots}
        upstreams: dict[str, list[str]] = {node: [] for node in ids}
        downstreams: dict[str, list[str]] = {node: [] for node in ids}
        for row in connection.execute("SELECT upstream_id, downstream_id FROM dependencies").fetchall():
            if row["upstream_id"] in ids and row["downstream_id"] in ids:
                upstreams[row["downstream_id"]].append(row["upstream_id"])
                downstreams[row["upstream_id"]].append(row["downstream_id"])
        indegree = {node: len(upstreams[node]) for node in ids}
        queue = sorted(node for node in ids if indegree[node] == 0)
        earliest: dict[str, int] = {}
        parent: dict[str, str | None] = {}
        while queue:
            node = queue.pop(0)
            best_upstream: str | None = None
            best_finish = 0
            for upstream in sorted(upstreams[node]):
                if earliest[upstream] > best_finish:
                    best_finish = earliest[upstream]
                    best_upstream = upstream
            earliest[node] = best_finish + estimates[node]
            parent[node] = best_upstream
            for downstream in sorted(downstreams[node]):
                indegree[downstream] -= 1
                if indegree[downstream] == 0:
                    queue.append(downstream)
            queue.sort()
        scope = "global" if actor.role in CHIEF_ROLES else "team"
        if not earliest:
            return {"scope": scope, "path": [], "total_days": 0, "generated_at": self._now()}
        tail = max(sorted(earliest), key=lambda node: earliest[node])
        path_ids: list[str] = []
        node: str | None = tail
        while node is not None:
            path_ids.append(node)
            node = parent[node]
        path_ids.reverse()
        return {
            "scope": scope,
            "path": [{"bottleneck_id": node, "name": names[node], "owner_team_id": owners[node],
                      "estimate_days": estimates[node]} for node in path_ids],
            "total_days": earliest[tail],
            "generated_at": self._now(),
        }

    def wait_reasons(self, actor_id: str) -> dict[str, Any]:
        """等待原因：缺入口证据、上游未完成、无启用方案、裁定待确认、候补排队、承诺未兑现。"""

        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        now = self._now()
        items = []
        for root in self._visible_roots(connection, actor):
            root_id = root["bottleneck_id"]
            if self._is_resolved(connection, root_id):
                continue
            reasons: list[dict[str, Any]] = []
            active = connection.execute(
                "SELECT * FROM solutions WHERE bottleneck_id=? AND status='active'", (root_id,)
            ).fetchone()
            if active is None:
                reasons.append({"type": "no_active_solution"})
            else:
                missing = self._missing_evidence(connection, active, now)
                if missing:
                    reasons.append({"type": "missing_evidence", "missing": missing})
                lease = connection.execute(
                    "SELECT 1 FROM leases WHERE solution_id=? AND status='active' AND expires_at > ?",
                    (active["solution_id"], now),
                ).fetchone()
                if lease is None:
                    adjudication = connection.execute(
                        "SELECT * FROM adjudications WHERE solution_id=? AND status='pending' "
                        "AND confirm_by > ? ORDER BY offered_at LIMIT 1",
                        (active["solution_id"], now),
                    ).fetchone()
                    if adjudication is not None:
                        reasons.append({"type": "adjudication_pending",
                                        "adjudication_id": adjudication["adjudication_id"],
                                        "team_id": adjudication["team_id"],
                                        "confirm_by": adjudication["confirm_by"]})
                    entry = connection.execute(
                        "SELECT * FROM waitlist_entries WHERE solution_id=? AND status IN ('waiting','frozen') "
                        "ORDER BY position LIMIT 1",
                        (active["solution_id"],),
                    ).fetchone()
                    if entry is not None:
                        reasons.append({"type": "waitlist", "window_id": entry["window_id"],
                                        "position": entry["position"], "team_id": entry["team_id"]})
            for row in connection.execute(
                "SELECT upstream_id FROM dependencies WHERE downstream_id=? ORDER BY upstream_id", (root_id,)
            ).fetchall():
                if not self._is_resolved(connection, row["upstream_id"]):
                    upstream = connection.execute(
                        "SELECT name FROM bottlenecks WHERE bottleneck_id=?", (row["upstream_id"],)
                    ).fetchone()
                    reasons.append({"type": "dependency_open", "upstream_id": row["upstream_id"],
                                    "upstream_name": upstream["name"] if upstream else None})
            for row in connection.execute(
                "SELECT * FROM commitments WHERE bottleneck_id=? AND status='active' "
                "ORDER BY promise_date, commitment_id", (root_id,)
            ).fetchall():
                reasons.append({"type": "commitment_pending", "team_id": row["team_id"],
                                "promise_date": row["promise_date"],
                                "overdue": row["promise_date"] <= now})
            if reasons:
                items.append({"bottleneck_id": root_id, "name": root["name"],
                              "owner_team_id": root["owner_team_id"], "reasons": reasons})
        return {"items": items, "generated_at": now}

    def switch_costs(self, actor_id: str) -> dict[str, Any]:
        """方案切换代价：备选基础代价 + 当前方案有效租约与在途试验批次的沉没代价。"""

        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        now = self._now()
        items = []
        for root in self._visible_roots(connection, actor):
            root_id = root["bottleneck_id"]
            if self._is_resolved(connection, root_id):
                continue
            current = connection.execute(
                "SELECT * FROM solutions WHERE bottleneck_id=? AND status='active'", (root_id,)
            ).fetchone()
            alternatives = connection.execute(
                "SELECT * FROM solutions WHERE bottleneck_id=? AND status='standby' "
                "ORDER BY priority, created_at, solution_id", (root_id,),
            ).fetchall()
            if not alternatives:
                continue
            lease_count = 0
            batch_count = 0
            if current is not None:
                lease_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM leases WHERE solution_id=? AND status='active' "
                    "AND expires_at > ?",
                    (current["solution_id"], now),
                ).fetchone()["count"]
                batch_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM test_batches WHERE solution_id=? AND result='pending'",
                    (current["solution_id"],),
                ).fetchone()["count"]
            items.append({
                "bottleneck_id": root_id,
                "name": root["name"],
                "current_solution_id": current["solution_id"] if current else None,
                "active_leases": lease_count,
                "pending_batches": batch_count,
                "alternatives": [{
                    "solution_id": alternative["solution_id"],
                    "name": alternative["name"],
                    "base_cost": alternative["switch_cost"],
                    "active_leases": lease_count,
                    "pending_batches": batch_count,
                    "switch_cost": alternative["switch_cost"]
                    + LEASE_PENALTY * lease_count + BATCH_PENALTY * batch_count,
                } for alternative in alternatives],
            })
        return {"items": items, "generated_at": now}

    def disclosable_evidence(self, actor_id: str, bottleneck_id: str) -> dict[str, Any]:
        """可披露证据：总师可见全部保密级别，课题负责人只能看本团队相关的开放与内部证据。"""

        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        root = self._root_bottleneck(connection, bottleneck_id)
        root_id = root["bottleneck_id"]
        if actor.role in CHIEF_ROLES:
            levels: tuple[str, ...] = CONFIDENTIALITY_LEVELS
        else:
            if actor.organization_id not in self._stakeholder_team_ids(connection, root_id):
                raise PermissionDenied("不能查看其他团队的证据")
            levels = LEAD_VISIBLE_LEVELS
        now = self._now()
        rows = connection.execute(
            "SELECT * FROM evidence_items WHERE bottleneck_id=? ORDER BY created_at, evidence_id",
            (root_id,),
        ).fetchall()
        items = [{
            "evidence_id": row["evidence_id"],
            "evidence_type": row["evidence_type"],
            "confidentiality": row["confidentiality"],
            "solution_id": row["solution_id"],
            "expires_at": row["expires_at"],
            "expired": row["expires_at"] <= now,
            "payload": json.loads(row["payload_json"]),
        } for row in rows if row["confidentiality"] in levels]
        return {"bottleneck_id": root_id, "disclosed_levels": list(levels), "items": items,
                "generated_at": now}

    def recompute_events(self, actor_id: str) -> dict[str, Any]:
        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        items = []
        for row in connection.execute(
            "SELECT * FROM recompute_events ORDER BY created_at, event_id"
        ).fetchall():
            affected = json.loads(row["affected_json"])
            if actor.role not in CHIEF_ROLES:
                affected = [node for node in affected
                            if actor.organization_id in self._stakeholder_team_ids(connection, node)]
                if not affected:
                    continue
            items.append({"event_id": row["event_id"], "trigger": row["trigger"],
                          "affected": affected, "created_at": row["created_at"]})
        return {"items": items, "generated_at": self._now()}

    def recovery_snapshot(self, actor_id: str) -> dict[str, Any]:
        """服务重启后的恢复视图：仍有效的租约与未决裁定。"""

        actor = self._readonly_actor(actor_id)
        self._require(actor, *VIEW_ROLES)
        connection = self.database.connection
        now = self._now()
        leases = connection.execute(
            "SELECT * FROM leases WHERE status='active' ORDER BY acquired_at, lease_id"
        ).fetchall()
        adjudications = connection.execute(
            "SELECT * FROM adjudications WHERE status='pending' ORDER BY offered_at, adjudication_id"
        ).fetchall()
        if actor.role not in CHIEF_ROLES:
            leases = [row for row in leases if row["team_id"] == actor.organization_id]
            adjudications = [row for row in adjudications if row["team_id"] == actor.organization_id]
        return {
            "leases": [{
                "lease_id": row["lease_id"], "window_id": row["window_id"],
                "solution_id": row["solution_id"], "team_id": row["team_id"],
                "status": row["status"], "expires_at": row["expires_at"],
                "effective_status": "expired" if row["expires_at"] <= now else "active",
            } for row in leases],
            "adjudications": [{
                "adjudication_id": row["adjudication_id"], "window_id": row["window_id"],
                "solution_id": row["solution_id"], "team_id": row["team_id"],
                "status": row["status"], "freeze_seq": row["freeze_seq"],
                "confirm_by": row["confirm_by"],
                "effective_status": "lapsed" if row["confirm_by"] <= now else "pending",
            } for row in adjudications],
            "recovered_at": now,
        }


def route_roadmap(service: RoadmapService, method: str, parsed, body: dict[str, Any],
                  actor_id: str) -> tuple[int, dict[str, Any]]:
    """把 /roadmap 前缀的 HTTP 请求分派到攻关路线服务。"""

    path = parsed.path
    query = parse_qs(parsed.query)

    def created(result: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return (200 if result.get("replayed") else 201), result

    if method == "POST" and path == "/roadmap/bottlenecks":
        return created(service.register_bottleneck(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/dependencies":
        return created(service.add_dependency(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/metrics":
        return created(service.register_metric(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/metrics/degrade":
        return created(service.degrade_metric(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/solutions":
        return created(service.register_solution(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/solutions/activate":
        return created(service.activate_solution(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/evidence":
        return created(service.register_evidence(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/evidence/expire-sweep":
        return created(service.expire_evidence_sweep(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/commitments":
        return created(service.register_commitment(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/commitments/fulfill":
        return created(service.fulfill_commitment(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/windows":
        return created(service.register_window(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/leases":
        return created(service.acquire_lease(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/leases/release":
        return created(service.release_lease(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/waitlist":
        return created(service.join_waitlist(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/adjudications/confirm":
        return created(service.confirm_adjudication(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/test-batches":
        return created(service.register_test_batch(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/test-batches/record":
        return created(service.record_test_result(actor_id=actor_id, **body))
    if method == "POST" and path == "/roadmap/sweep":
        return created(service.sweep_expired(actor_id=actor_id, **body))
    if method == "GET" and path == "/roadmap/bottlenecks":
        return 200, service.list_bottlenecks(actor_id)
    if method == "GET" and path == "/roadmap/bottlenecks/detail":
        bottleneck_id = query.get("bottleneck_id", [""])[0]
        if not bottleneck_id:
            raise ValidationError("bottleneck_id 不能为空")
        return 200, service.bottleneck_detail(actor_id, bottleneck_id)
    if method == "GET" and path == "/roadmap/critical-path":
        return 200, service.critical_path(actor_id)
    if method == "GET" and path == "/roadmap/wait-reasons":
        return 200, service.wait_reasons(actor_id)
    if method == "GET" and path == "/roadmap/switch-costs":
        return 200, service.switch_costs(actor_id)
    if method == "GET" and path == "/roadmap/evidence":
        bottleneck_id = query.get("bottleneck_id", [""])[0]
        if not bottleneck_id:
            raise ValidationError("bottleneck_id 不能为空")
        return 200, service.disclosable_evidence(actor_id, bottleneck_id)
    if method == "GET" and path == "/roadmap/recompute-events":
        return 200, service.recompute_events(actor_id)
    if method == "GET" and path == "/roadmap/recovery":
        return 200, service.recovery_snapshot(actor_id)
    return 404, {"error": "route_not_found", "message": "接口不存在"}
