"""关键技术堵点与攻关路线服务。

在基础服务的权限、幂等、事务和审计能力之上，把目标指标、部件依赖、候选方案、
试验批次、证据有效期、保密级别、团队承诺和设施窗口编成可计算的攻关路线图：

- 依赖图拒绝循环依赖，按归一化源头键识别伪装成不同名称的同源堵点并自动发起裁定；
- 只有入口证据全部有效的方案才能获得限时设施租约，同一窗口的并发确认只有一个成功；
- 窗口冻结后候补顺序固定，释放或到期的租约按冻结顺序推进候补，证据失效的候补被跳过；
- 试验失败、指标降级、替代路线启用和证据过期只重算尚未完成的堵点，试验事实只增不改；
- 总师（chief）看到关键路径与全部证据，课题负责人（lead）只看本团队且证据按密级打码；
- 租约与未决裁定持久化在 SQLite，服务重启后由恢复流程继续推进。
"""

from __future__ import annotations

import json
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit import append_event, canonical_json
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .service import DomainService

SECURITY_LEVELS = {"open": 0, "internal": 1, "restricted": 2, "secret": 3}
ROLE_CLEARANCE = {"admin": 3, "chief": 3, "lead": 2, "operator": 1, "reviewer": 1, "auditor": 1}
METRIC_DIRECTIONS = ("gte", "lte")
ADJUDICATION_KINDS = ("alias_merge", "downgrade_review", "waitlist_dispute")
DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UNFROZEN_SEQ = 4611686018427387904


def normalize_key(value: str) -> str:
    """归一化名称，让改写大小写、全半角、空格和标点的同源堵点落到同一个键上。"""

    text = unicodedata.normalize("NFKC", str(value)).casefold()
    return "".join(ch for ch in text if ch.isalnum())


def format_time(value: datetime) -> str:
    """生成固定宽度、可按字典序比较的 UTC 时间文本。"""

    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: Any, field: str) -> str:
    """解析 ISO 时间或日期，缺少时区时拒绝。"""

    text = str(value).strip()
    if DATE_ONLY.fullmatch(text):
        text = f"{text}T00:00:00+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{field} 时间格式无效") from exc
    if moment.tzinfo is None:
        raise ValidationError(f"{field} 必须包含时区")
    return format_time(moment)


class RoadmapService(DomainService):
    """把堵点、方案、证据、设施窗口和裁定组织成可计算、可恢复的攻关路线图。"""

    def __init__(self, database, clock=None) -> None:
        super().__init__(database, clock)
        self._recover()

    # ---------- 基础工具 ----------

    def _now(self) -> str:
        return format_time(self.clock.now())

    def _metric(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValidationError("metric 必须是对象")
        name = self._text(str(value.get("name", "")), "metric.name", 80)
        unit = self._text(str(value.get("unit", "")), "metric.unit", 40)
        direction = value.get("direction")
        if direction not in METRIC_DIRECTIONS:
            raise ValidationError("metric.direction 必须是 gte 或 lte")
        result: dict[str, Any] = {"name": name, "unit": unit, "direction": direction}
        for key in ("baseline", "target"):
            number = value.get(key)
            if isinstance(number, bool) or not isinstance(number, (int, float)):
                raise ValidationError(f"metric.{key} 必须是数值")
            result[key] = float(number)
        return result

    def _bottleneck(self, connection, bottleneck_id: str):
        row = connection.execute(
            "SELECT * FROM bottlenecks WHERE bottleneck_id=?", (bottleneck_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("堵点不存在")
        return row

    def _solution(self, connection, solution_id: str):
        row = connection.execute(
            "SELECT * FROM solutions WHERE solution_id=?", (solution_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("方案不存在")
        return row

    def _window(self, connection, window_id: str):
        row = connection.execute(
            "SELECT * FROM facility_windows WHERE window_id=?", (window_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("设施窗口不存在")
        return row

    def _team_write(self, actor, owner_team: str) -> None:
        if actor.role in ("admin", "chief"):
            return
        if actor.role == "lead" and actor.organization_id == owner_team:
            return
        raise PermissionDenied("只能操作本团队的攻关对象")

    def _visible(self, actor, bottleneck) -> None:
        if actor.role in ("admin", "chief"):
            return
        if actor.role == "lead" and bottleneck["owner_team"] == actor.organization_id:
            return
        raise PermissionDenied("无权查看该堵点")

    # ---------- 登记：堵点、依赖、承诺、方案、证据、设施 ----------

    def register_bottleneck(self, *, request_id: str, actor_id: str, site_id: str, name: str,
                            origin_key: str, security_level: str, metric: dict[str, Any],
                            estimate_days: int, owner_team: str | None = None):
        payload = {"actor_id": actor_id, "site_id": site_id, "name": name, "origin_key": origin_key,
                   "security_level": security_level, "metric": metric,
                   "estimate_days": estimate_days, "owner_team": owner_team}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            site = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if site is None:
                raise NotFoundError("场所不存在")
            team = str(owner_team).strip() if owner_team else actor.organization_id
            if connection.execute(
                "SELECT 1 FROM organizations WHERE organization_id=?", (team,)
            ).fetchone() is None:
                raise NotFoundError("承诺团队不存在")
            self._team_write(actor, team)
            name = self._text(name, "name")
            origin_key = self._text(origin_key, "origin_key")
            if security_level not in SECURITY_LEVELS:
                raise ValidationError("security_level 不在允许范围内")
            metric_value = self._metric(metric)
            if isinstance(estimate_days, bool) or not isinstance(estimate_days, int) or estimate_days < 0:
                raise ValidationError("estimate_days 必须是非负整数")
            now = self._now()

            def create():
                bottleneck_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO bottlenecks(bottleneck_id,site_id,name,normalized_name,origin_key,normalized_origin,"
                    "owner_team,security_level,metric_name,metric_unit,metric_direction,baseline_value,target_value,"
                    "metric_revision,estimate_days,status,canonical_id,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,?,?)",
                    (bottleneck_id, site_id, name, normalize_key(name), origin_key, normalize_key(origin_key),
                     team, security_level, metric_value["name"], metric_value["unit"], metric_value["direction"],
                     metric_value["baseline"], metric_value["target"], 1, estimate_days, actor_id, now),
                )
                connection.execute(
                    "INSERT INTO metric_revisions(bottleneck_id,revision,target_value,reason,created_by,created_at) "
                    "VALUES(?,1,?,'初始指标',?,?)",
                    (bottleneck_id, metric_value["target"], actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="bottleneck.registered",
                             resource_type="bottleneck", resource_id=bottleneck_id,
                             detail={"site_id": site_id, "name": name, "origin_key": origin_key,
                                     "owner_team": team, "security_level": security_level},
                             occurred_at=now)
                self._flag_same_origin(connection, bottleneck_id, normalize_key(origin_key), now)
                return "bottleneck", bottleneck_id, {"bottleneck_id": bottleneck_id, "owner_team": team}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_bottleneck", payload=payload, create=create)

    def add_dependency(self, *, request_id: str, actor_id: str, bottleneck_id: str, depends_on: str):
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id, "depends_on": depends_on}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            if bottleneck_id == depends_on:
                raise ValidationError("堵点不能依赖自身")
            bottleneck = self._bottleneck(connection, bottleneck_id)
            self._bottleneck(connection, depends_on)
            self._team_write(actor, bottleneck["owner_team"])
            if self._would_cycle(connection, bottleneck_id, depends_on):
                raise ConflictError("检测到循环依赖，已拒绝写入")
            now = self._now()

            def create():
                try:
                    connection.execute(
                        "INSERT INTO bottleneck_dependencies(bottleneck_id,depends_on,created_by,created_at) "
                        "VALUES(?,?,?,?)",
                        (bottleneck_id, depends_on, actor_id, now),
                    )
                except Exception as exc:
                    raise ConflictError("依赖关系已经存在") from exc
                append_event(connection, actor_id=actor_id, action="dependency.added",
                             resource_type="bottleneck", resource_id=bottleneck_id,
                             detail={"depends_on": depends_on}, occurred_at=now)
                self._recompute_unfinished(connection, now)
                return "dependency", f"{bottleneck_id}->{depends_on}", {
                    "bottleneck_id": bottleneck_id, "depends_on": depends_on}

            return self._idempotent(connection, request_id=request_id,
                                    action="add_dependency", payload=payload, create=create)

    def commit_team(self, *, request_id: str, actor_id: str, bottleneck_id: str,
                    milestone: str, promised_date: str):
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id,
                   "milestone": milestone, "promised_date": promised_date}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            bottleneck = self._bottleneck(connection, bottleneck_id)
            self._team_write(actor, bottleneck["owner_team"])
            milestone = self._text(milestone, "milestone")
            promised = parse_time(promised_date, "promised_date")
            now = self._now()

            def create():
                commitment_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO commitments(commitment_id,bottleneck_id,team_id,milestone,promised_date,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (commitment_id, bottleneck_id, bottleneck["owner_team"], milestone, promised, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="team.committed",
                             resource_type="bottleneck", resource_id=bottleneck_id,
                             detail={"team_id": bottleneck["owner_team"], "milestone": milestone,
                                     "promised_date": promised}, occurred_at=now)
                return "commitment", commitment_id, {
                    "commitment_id": commitment_id, "team_id": bottleneck["owner_team"]}

            return self._idempotent(connection, request_id=request_id,
                                    action="commit_team", payload=payload, create=create)

    def register_solution(self, *, request_id: str, actor_id: str, bottleneck_id: str, name: str,
                          description: str = "", required_evidence: list[str] | tuple = (),
                          switch_cost: float = 0):
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id, "name": name,
                   "description": description, "required_evidence": list(required_evidence),
                   "switch_cost": switch_cost}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            bottleneck = self._bottleneck(connection, bottleneck_id)
            self._team_write(actor, bottleneck["owner_team"])
            name = self._text(name, "name")
            description = str(description or "").strip()
            if len(description) > 500:
                raise ValidationError("description 不能超过 500 个字符")
            if not isinstance(required_evidence, (list, tuple)):
                raise ValidationError("required_evidence 必须是数组")
            kinds: list[str] = []
            for kind in required_evidence:
                kind = self._identifier(str(kind), "required_evidence")
                if kind not in kinds:
                    kinds.append(kind)
            if isinstance(switch_cost, bool) or not isinstance(switch_cost, (int, float)) or switch_cost < 0:
                raise ValidationError("switch_cost 必须是非负数值")
            now = self._now()

            def create():
                solution_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO solutions(solution_id,bottleneck_id,name,description,required_evidence_json,"
                    "switch_cost,status,created_by,created_at) VALUES(?,?,?,?,?,?,'candidate',?,?)",
                    (solution_id, bottleneck_id, name, description, canonical_json(kinds),
                     float(switch_cost), actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="solution.registered",
                             resource_type="solution", resource_id=solution_id,
                             detail={"bottleneck_id": bottleneck_id, "name": name,
                                     "required_evidence": kinds, "switch_cost": float(switch_cost)},
                             occurred_at=now)
                return "solution", solution_id, {"solution_id": solution_id, "status": "candidate"}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_solution", payload=payload, create=create)

    def activate_solution(self, *, request_id: str, actor_id: str, solution_id: str):
        payload = {"actor_id": actor_id, "solution_id": solution_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._team_write(actor, bottleneck["owner_team"])
            if solution["status"] == "abandoned":
                raise ConflictError("已废弃的方案不能启用")
            now = self._now()

            def create():
                current = connection.execute(
                    "SELECT * FROM solutions WHERE bottleneck_id=? AND status='active' AND solution_id<>?",
                    (solution["bottleneck_id"], solution_id),
                ).fetchone()
                if current is not None:
                    connection.execute("UPDATE solutions SET status='suspended' WHERE solution_id=?",
                                       (current["solution_id"],))
                connection.execute("UPDATE solutions SET status='active' WHERE solution_id=?", (solution_id,))
                cost = self._switch_cost(connection, solution, now)
                append_event(connection, actor_id=actor_id, action="solution.activated",
                             resource_type="solution", resource_id=solution_id,
                             detail={"bottleneck_id": solution["bottleneck_id"],
                                     "previous_solution_id": current["solution_id"] if current else None,
                                     "switch_cost": cost}, occurred_at=now)
                self._recompute_unfinished(connection, now)
                return "solution", solution_id, {"solution_id": solution_id, "status": "active",
                                                 "switch_cost": cost}

            return self._idempotent(connection, request_id=request_id,
                                    action="activate_solution", payload=payload, create=create)

    def register_evidence(self, *, request_id: str, actor_id: str, solution_id: str, kind: str,
                          security_level: str, detail: dict[str, Any],
                          valid_from: str, valid_until: str):
        payload = {"actor_id": actor_id, "solution_id": solution_id, "kind": kind,
                   "security_level": security_level, "detail": detail,
                   "valid_from": valid_from, "valid_until": valid_until}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._team_write(actor, bottleneck["owner_team"])
            kind = self._identifier(kind, "kind")
            if security_level not in SECURITY_LEVELS:
                raise ValidationError("security_level 不在允许范围内")
            if not isinstance(detail, dict) or not detail:
                raise ValidationError("detail 必须是非空对象")
            start = parse_time(valid_from, "valid_from")
            end = parse_time(valid_until, "valid_until")
            if end <= start:
                raise ValidationError("证据失效时间必须晚于生效时间")
            now = self._now()

            def create():
                evidence_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO evidence(evidence_id,solution_id,kind,security_level,detail_json,valid_from,"
                    "valid_until,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (evidence_id, solution_id, kind, security_level, canonical_json(detail),
                     start, end, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="evidence.registered",
                             resource_type="solution", resource_id=solution_id,
                             detail={"evidence_id": evidence_id, "kind": kind,
                                     "security_level": security_level, "valid_until": end},
                             occurred_at=now)
                self._recompute_unfinished(connection, now)
                return "evidence", evidence_id, {"evidence_id": evidence_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_evidence", payload=payload, create=create)

    def register_facility(self, *, request_id: str, actor_id: str, site_id: str, name: str):
        payload = {"actor_id": actor_id, "site_id": site_id, "name": name}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "operator")
            if connection.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone() is None:
                raise NotFoundError("场所不存在")
            name = self._text(name, "name")
            now = self._now()

            def create():
                facility_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO facilities(facility_id,site_id,name,created_at) VALUES(?,?,?,?)",
                    (facility_id, site_id, name, now),
                )
                append_event(connection, actor_id=actor_id, action="facility.registered",
                             resource_type="facility", resource_id=facility_id,
                             detail={"site_id": site_id, "name": name}, occurred_at=now)
                return "facility", facility_id, {"facility_id": facility_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_facility", payload=payload, create=create)

    def register_window(self, *, request_id: str, actor_id: str, facility_id: str,
                        starts_at: str, ends_at: str, freeze_at: str):
        payload = {"actor_id": actor_id, "facility_id": facility_id,
                   "starts_at": starts_at, "ends_at": ends_at, "freeze_at": freeze_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "operator")
            if connection.execute(
                "SELECT 1 FROM facilities WHERE facility_id=?", (facility_id,)
            ).fetchone() is None:
                raise NotFoundError("设施不存在")
            starts = parse_time(starts_at, "starts_at")
            ends = parse_time(ends_at, "ends_at")
            freeze = parse_time(freeze_at, "freeze_at")
            if starts >= ends:
                raise ValidationError("窗口结束时间必须晚于开始时间")
            if not starts <= freeze <= ends:
                raise ValidationError("freeze_at 必须位于窗口区间内")

            def create():
                window_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO facility_windows(window_id,facility_id,starts_at,ends_at,freeze_at,state) "
                    "VALUES(?,?,?,?,?,'open')",
                    (window_id, facility_id, starts, ends, freeze),
                )
                append_event(connection, actor_id=actor_id, action="window.registered",
                             resource_type="facility_window", resource_id=window_id,
                             detail={"facility_id": facility_id, "starts_at": starts,
                                     "ends_at": ends, "freeze_at": freeze}, occurred_at=self._now())
                return "facility_window", window_id, {"window_id": window_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_window", payload=payload, create=create)

    # ---------- 限时资源：确认、释放、候补推进 ----------

    def confirm_resource(self, *, request_id: str, actor_id: str, window_id: str,
                         solution_id: str, priority: int = 0):
        payload = {"actor_id": actor_id, "window_id": window_id,
                   "solution_id": solution_id, "priority": priority}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            now = self._now()
            self._sweep(connection, now)
            window = self._window(connection, window_id)
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._team_write(actor, bottleneck["owner_team"])
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValidationError("priority 必须是整数")
            if window["state"] == "closed" or window["ends_at"] <= now:
                raise ConflictError("设施窗口已关闭")
            if not self._entry_evidence_ok(connection, solution_id, now):
                raise PermissionDenied("入口证据未满足，不能获得限时资源")
            team = bottleneck["owner_team"]

            def create():
                active = connection.execute(
                    "SELECT * FROM leases WHERE window_id=? AND state='active'", (window_id,)
                ).fetchone()
                if active is None:
                    lease_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO leases(lease_id,window_id,solution_id,team_id,state,granted_at,"
                        "expires_at,released_at) VALUES(?,?,?,?,'active',?,?,NULL)",
                        (lease_id, window_id, solution_id, team, now, window["ends_at"]),
                    )
                    append_event(connection, actor_id=actor_id, action="lease.granted",
                                 resource_type="lease", resource_id=lease_id,
                                 detail={"window_id": window_id, "solution_id": solution_id,
                                         "team_id": team, "expires_at": window["ends_at"]},
                                 occurred_at=now)
                    self._recompute_unfinished(connection, now)
                    return "lease", lease_id, {"lease_id": lease_id, "window_id": window_id,
                                               "state": "active", "expires_at": window["ends_at"]}
                entry_id, _ = self._join_waitlist(connection, actor_id, window,
                                                  solution_id, team, priority, now)
                position = self._waitlist_position(connection, entry_id)
                return "waitlist", entry_id, {"entry_id": entry_id, "window_id": window_id,
                                              "state": "waiting", "position": position}

            return self._idempotent(connection, request_id=request_id,
                                    action="confirm_resource", payload=payload, create=create)

    def release_lease(self, *, request_id: str, actor_id: str, lease_id: str):
        payload = {"actor_id": actor_id, "lease_id": lease_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            now = self._now()
            self._sweep(connection, now)
            lease = connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if lease is None:
                raise NotFoundError("租约不存在")
            self._team_write(actor, lease["team_id"])
            if lease["state"] != "active":
                raise ConflictError("租约不在有效状态")

            def create():
                connection.execute("UPDATE leases SET state='released', released_at=? WHERE lease_id=?",
                                   (now, lease_id))
                append_event(connection, actor_id=actor_id, action="lease.released",
                             resource_type="lease", resource_id=lease_id,
                             detail={"window_id": lease["window_id"]}, occurred_at=now)
                promoted = self._promote_next(connection, lease["window_id"], now, actor_id)
                self._recompute_unfinished(connection, now)
                return "lease", lease_id, {"lease_id": lease_id, "state": "released",
                                           "promoted_lease_id": promoted}

            return self._idempotent(connection, request_id=request_id,
                                    action="release_lease", payload=payload, create=create)

    # ---------- 试验事实与路线变更 ----------

    def record_test_batch(self, *, request_id: str, actor_id: str, solution_id: str,
                          lease_id: str, result: str, metrics: dict[str, Any]):
        payload = {"actor_id": actor_id, "solution_id": solution_id, "lease_id": lease_id,
                   "result": result, "metrics": metrics}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            now = self._now()
            self._sweep(connection, now)
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._team_write(actor, bottleneck["owner_team"])
            lease = connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if lease is None:
                raise NotFoundError("租约不存在")
            if lease["solution_id"] != solution_id:
                raise ValidationError("租约与试验方案不匹配")
            if result not in ("passed", "failed"):
                raise ValidationError("result 必须是 passed 或 failed")
            if not isinstance(metrics, dict) or not metrics:
                raise ValidationError("metrics 必须是非空对象")

            def create():
                batch_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO test_batches(batch_id,solution_id,lease_id,result,metrics_json,"
                    "recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?)",
                    (batch_id, solution_id, lease_id, result, canonical_json(metrics), actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="test_batch.recorded",
                             resource_type="test_batch", resource_id=batch_id,
                             detail={"solution_id": solution_id, "lease_id": lease_id, "result": result},
                             occurred_at=now)
                if result == "passed":
                    if solution["status"] == "active":
                        connection.execute("UPDATE bottlenecks SET status='verified' WHERE bottleneck_id=?",
                                           (bottleneck["bottleneck_id"],))
                        append_event(connection, actor_id=actor_id, action="bottleneck.verified",
                                     resource_type="bottleneck", resource_id=bottleneck["bottleneck_id"],
                                     detail={"solution_id": solution_id, "batch_id": batch_id},
                                     occurred_at=now)
                elif solution["status"] == "active":
                    connection.execute("UPDATE solutions SET status='suspended' WHERE solution_id=?",
                                       (solution_id,))
                    append_event(connection, actor_id=actor_id, action="solution.suspended",
                                 resource_type="solution", resource_id=solution_id,
                                 detail={"batch_id": batch_id, "reason": "试验失败"}, occurred_at=now)
                self._recompute_unfinished(connection, now)
                return "test_batch", batch_id, {"batch_id": batch_id, "result": result}

            return self._idempotent(connection, request_id=request_id,
                                    action="record_test_batch", payload=payload, create=create)

    def downgrade_metric(self, *, request_id: str, actor_id: str, bottleneck_id: str,
                         new_target: float, reason: str):
        payload = {"actor_id": actor_id, "bottleneck_id": bottleneck_id,
                   "new_target": new_target, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief")
            bottleneck = self._bottleneck(connection, bottleneck_id)
            if isinstance(new_target, bool) or not isinstance(new_target, (int, float)):
                raise ValidationError("new_target 必须是数值")
            target = float(new_target)
            current = float(bottleneck["target_value"])
            if bottleneck["metric_direction"] == "gte" and not target < current:
                raise ValidationError("新指标不是降级：gte 指标降级必须降低目标值")
            if bottleneck["metric_direction"] == "lte" and not target > current:
                raise ValidationError("新指标不是降级：lte 指标降级必须放宽上限")
            reason = self._text(reason, "reason")
            now = self._now()

            def create():
                revision = bottleneck["metric_revision"] + 1
                connection.execute(
                    "INSERT INTO metric_revisions(bottleneck_id,revision,target_value,reason,created_by,"
                    "created_at) VALUES(?,?,?,?,?,?)",
                    (bottleneck_id, revision, target, reason, actor_id, now),
                )
                connection.execute("UPDATE bottlenecks SET target_value=?, metric_revision=? "
                                   "WHERE bottleneck_id=?", (target, revision, bottleneck_id))
                append_event(connection, actor_id=actor_id, action="metric.downgraded",
                             resource_type="bottleneck", resource_id=bottleneck_id,
                             detail={"from": current, "to": target, "revision": revision,
                                     "reason": reason}, occurred_at=now)
                self._recompute_unfinished(connection, now)
                return "bottleneck", bottleneck_id, {"bottleneck_id": bottleneck_id,
                                                     "metric_revision": revision,
                                                     "target_value": target}

            return self._idempotent(connection, request_id=request_id,
                                    action="downgrade_metric", payload=payload, create=create)

    def resolve_adjudication(self, *, request_id: str, actor_id: str, adjudication_id: str,
                             decision: str, rationale: str = ""):
        payload = {"actor_id": actor_id, "adjudication_id": adjudication_id,
                   "decision": decision, "rationale": rationale}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief")
            adjudication = connection.execute(
                "SELECT * FROM adjudications WHERE adjudication_id=?", (adjudication_id,)
            ).fetchone()
            if adjudication is None:
                raise NotFoundError("裁定不存在")
            if adjudication["status"] != "pending":
                raise ConflictError("裁定已结案")
            if decision not in ("approved", "rejected"):
                raise ValidationError("decision 必须是 approved 或 rejected")
            rationale = str(rationale or "").strip()
            if len(rationale) > 200:
                raise ValidationError("rationale 不能超过 200 个字符")
            now = self._now()

            def create():
                resolution = {"decision": decision, "rationale": rationale}
                connection.execute(
                    "UPDATE adjudications SET status=?, resolution_json=?, resolved_by=?, resolved_at=? "
                    "WHERE adjudication_id=?",
                    (decision, canonical_json(resolution), actor_id, now, adjudication_id),
                )
                subject = json.loads(adjudication["subject_json"])
                canonical = None
                if decision == "approved" and adjudication["kind"] == "alias_merge":
                    ids = list(subject.get("bottleneck_ids", []))
                    if ids:
                        placeholders = ",".join(["?"] * len(ids))
                        row = connection.execute(
                            f"SELECT bottleneck_id FROM bottlenecks WHERE bottleneck_id IN ({placeholders}) "
                            "ORDER BY created_at, bottleneck_id LIMIT 1", ids,
                        ).fetchone()
                        if row is not None:
                            canonical = row["bottleneck_id"]
                            connection.execute(
                                f"UPDATE bottlenecks SET canonical_id=? "
                                f"WHERE bottleneck_id IN ({placeholders})", [canonical, *ids],
                            )
                append_event(connection, actor_id=actor_id, action="adjudication.resolved",
                             resource_type="adjudication", resource_id=adjudication_id,
                             detail={"decision": decision, "kind": adjudication["kind"],
                                     "canonical_id": canonical}, occurred_at=now)
                return "adjudication", adjudication_id, {"adjudication_id": adjudication_id,
                                                         "status": decision,
                                                         "canonical_id": canonical}

            return self._idempotent(connection, request_id=request_id,
                                    action="resolve_adjudication", payload=payload, create=create)

    # ---------- 视图：关键路径、等待原因、切换代价、可披露证据 ----------

    def critical_path(self, actor_id: str, site_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief")
            now = self._now()
            self._sweep(connection, now)
            self._recompute_unfinished(connection, now)
            return self._critical_path(connection, site_id)

    def roadmap(self, actor_id: str, site_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            now = self._now()
            self._sweep(connection, now)
            self._recompute_unfinished(connection, now)
            if actor.role in ("admin", "chief"):
                rows = connection.execute(
                    "SELECT * FROM bottlenecks WHERE site_id=? ORDER BY created_at, bottleneck_id",
                    (site_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM bottlenecks WHERE site_id=? AND owner_team=? "
                    "ORDER BY created_at, bottleneck_id",
                    (site_id, actor.organization_id),
                ).fetchall()
            result: dict[str, Any] = {
                "site_id": site_id,
                "generated_at": now,
                "bottlenecks": [self._bottleneck_view(connection, row, now) for row in rows],
                "same_origin_groups": self._same_origin(connection, site_id, actor),
            }
            if actor.role in ("admin", "chief"):
                result["critical_path"] = self._critical_path(connection, site_id)
            return result

    def waiting_reasons(self, actor_id: str, bottleneck_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            now = self._now()
            self._sweep(connection, now)
            self._recompute_unfinished(connection, now)
            bottleneck = self._bottleneck(connection, bottleneck_id)
            self._visible(actor, bottleneck)
            return {"bottleneck_id": bottleneck_id, "status": bottleneck["status"],
                    "reasons": self._waiting_reasons(connection, bottleneck, now)}

    def switch_cost(self, actor_id: str, solution_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            now = self._now()
            self._sweep(connection, now)
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._visible(actor, bottleneck)
            cost = self._switch_cost(connection, solution, now)
            return {"solution_id": solution_id,
                    "bottleneck_id": bottleneck["bottleneck_id"], **cost}

    def list_evidence(self, actor_id: str, solution_id: str) -> list[dict[str, Any]]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            now = self._now()
            solution = self._solution(connection, solution_id)
            bottleneck = self._bottleneck(connection, solution["bottleneck_id"])
            self._visible(actor, bottleneck)
            clearance = ROLE_CLEARANCE.get(actor.role, 0)
            items = []
            rows = connection.execute(
                "SELECT * FROM evidence WHERE solution_id=? ORDER BY created_at, evidence_id",
                (solution_id,),
            ).fetchall()
            for row in rows:
                disclosed = SECURITY_LEVELS[row["security_level"]] <= clearance
                items.append({
                    "evidence_id": row["evidence_id"],
                    "kind": row["kind"],
                    "security_level": row["security_level"],
                    "valid_from": row["valid_from"],
                    "valid_until": row["valid_until"],
                    "expired": row["valid_until"] <= now,
                    "disclosed": disclosed,
                    "detail": json.loads(row["detail_json"]) if disclosed else None,
                })
            return items

    def list_leases(self, actor_id: str, window_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            now = self._now()
            self._sweep(connection, now)
            window = self._window(connection, window_id)
            leases = connection.execute(
                "SELECT * FROM leases WHERE window_id=? ORDER BY granted_at, lease_id", (window_id,)
            ).fetchall()
            entries = connection.execute(
                "SELECT * FROM waitlist WHERE window_id=? "
                "ORDER BY COALESCE(frozen_seq, ?), priority DESC, requested_at ASC, entry_id ASC",
                (window_id, UNFROZEN_SEQ),
            ).fetchall()
            positions: dict[str, int] = {}
            position = 0
            for entry in entries:
                if entry["status"] == "waiting":
                    position += 1
                    positions[entry["entry_id"]] = position

            def visible(team_id: str) -> bool:
                return actor.role in ("admin", "chief") or team_id == actor.organization_id

            return {
                "window_id": window_id,
                "window_state": window["state"],
                "ends_at": window["ends_at"],
                "leases": [{"lease_id": row["lease_id"], "solution_id": row["solution_id"],
                            "team_id": row["team_id"], "state": row["state"],
                            "granted_at": row["granted_at"], "expires_at": row["expires_at"],
                            "released_at": row["released_at"]}
                           for row in leases if visible(row["team_id"])],
                "waitlist": [{"entry_id": row["entry_id"], "solution_id": row["solution_id"],
                              "team_id": row["team_id"], "priority": row["priority"],
                              "frozen_seq": row["frozen_seq"], "status": row["status"],
                              "position": positions.get(row["entry_id"])}
                             for row in entries if visible(row["team_id"])],
            }

    def list_adjudications(self, actor_id: str, status: str | None = None) -> list[dict[str, Any]]:
        actor = self._actor(self.database.connection, actor_id)
        self._require(actor, "admin", "chief", "auditor")
        query = "SELECT * FROM adjudications"
        parameters: list[Any] = []
        if status:
            query += " WHERE status=?"
            parameters.append(status)
        query += " ORDER BY created_at, adjudication_id"
        items = []
        for row in self.database.connection.execute(query, parameters):
            items.append({"adjudication_id": row["adjudication_id"], "kind": row["kind"],
                          "subject": json.loads(row["subject_json"]), "status": row["status"],
                          "resolution": json.loads(row["resolution_json"]) if row["resolution_json"] else None,
                          "created_by": row["created_by"], "created_at": row["created_at"],
                          "resolved_by": row["resolved_by"], "resolved_at": row["resolved_at"]})
        return items

    def same_origin_groups(self, actor_id: str, site_id: str) -> list[dict[str, Any]]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "chief", "lead")
            return self._same_origin(connection, site_id, actor)

    # ---------- 内部：同源识别、循环检测、重算、冻结与推进 ----------

    def _recover(self) -> None:
        """服务重启后恢复：推进租约到期与候补，重算未完成路径；未决裁定保持待办。"""

        with self.database.transaction(immediate=True) as connection:
            now = self._now()
            self._sweep(connection, now)
            self._recompute_unfinished(connection, now)

    def _flag_same_origin(self, connection, bottleneck_id: str, normalized_origin: str,
                          now: str) -> None:
        rows = connection.execute(
            "SELECT bottleneck_id FROM bottlenecks WHERE normalized_origin=? AND bottleneck_id<>?",
            (normalized_origin, bottleneck_id),
        ).fetchall()
        if not rows:
            return
        ids = sorted([row["bottleneck_id"] for row in rows] + [bottleneck_id])
        pending = connection.execute(
            "SELECT * FROM adjudications WHERE kind='alias_merge' AND status='pending'"
        ).fetchall()
        for row in pending:
            subject = json.loads(row["subject_json"])
            if subject.get("normalized_origin") == normalized_origin:
                merged = sorted(set(subject["bottleneck_ids"]) | set(ids))
                if merged != subject["bottleneck_ids"]:
                    subject["bottleneck_ids"] = merged
                    connection.execute(
                        "UPDATE adjudications SET subject_json=? WHERE adjudication_id=?",
                        (canonical_json(subject), row["adjudication_id"]),
                    )
                return
        adjudication_id = uuid.uuid4().hex
        subject = {"normalized_origin": normalized_origin, "bottleneck_ids": ids}
        connection.execute(
            "INSERT INTO adjudications(adjudication_id,kind,subject_json,status,resolution_json,"
            "created_by,created_at,resolved_by,resolved_at) VALUES(?,?,?,?,NULL,?,?,NULL,NULL)",
            (adjudication_id, "alias_merge", canonical_json(subject), "pending", "system", now),
        )
        append_event(connection, actor_id="system", action="adjudication.raised",
                     resource_type="adjudication", resource_id=adjudication_id,
                     detail={"kind": "alias_merge", "normalized_origin": normalized_origin,
                             "bottleneck_ids": ids}, occurred_at=now)

    def _would_cycle(self, connection, bottleneck_id: str, depends_on: str) -> bool:
        seen: set[str] = set()
        stack = [depends_on]
        while stack:
            node = stack.pop()
            if node == bottleneck_id:
                return True
            if node in seen:
                continue
            seen.add(node)
            rows = connection.execute(
                "SELECT depends_on FROM bottleneck_dependencies WHERE bottleneck_id=?", (node,)
            ).fetchall()
            stack.extend(row["depends_on"] for row in rows)
        return False

    def _evidence_valid(self, connection, solution_id: str, kind: str, now: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM evidence WHERE solution_id=? AND kind=? AND valid_from<=? AND valid_until>? "
            "LIMIT 1",
            (solution_id, kind, now, now),
        ).fetchone()
        return row is not None

    def _entry_evidence_ok(self, connection, solution_id: str, now: str) -> bool:
        solution = self._solution(connection, solution_id)
        required = json.loads(solution["required_evidence_json"])
        return all(self._evidence_valid(connection, solution_id, kind, now) for kind in required)

    def _derive_status(self, connection, bottleneck, now: str) -> str:
        solution = connection.execute(
            "SELECT * FROM solutions WHERE bottleneck_id=? AND status='active'",
            (bottleneck["bottleneck_id"],),
        ).fetchone()
        if solution is None:
            return "pending"
        unverified = connection.execute(
            "SELECT 1 FROM bottleneck_dependencies d JOIN bottlenecks p ON p.bottleneck_id=d.depends_on "
            "WHERE d.bottleneck_id=? AND p.status<>'verified' LIMIT 1",
            (bottleneck["bottleneck_id"],),
        ).fetchone()
        if unverified is not None:
            return "blocked"
        if not self._entry_evidence_ok(connection, solution["solution_id"], now):
            return "blocked"
        lease = connection.execute(
            "SELECT 1 FROM leases WHERE solution_id=? AND state='active' AND expires_at>? LIMIT 1",
            (solution["solution_id"], now),
        ).fetchone()
        return "in_progress" if lease is not None else "ready"

    def _recompute_unfinished(self, connection, now: str) -> None:
        """只重算尚未完成的堵点；已验证的堵点和既有试验事实保持不变。"""

        rows = connection.execute(
            "SELECT * FROM bottlenecks WHERE status<>'verified' ORDER BY created_at, bottleneck_id"
        ).fetchall()
        for row in rows:
            status = self._derive_status(connection, row, now)
            if status != row["status"]:
                connection.execute("UPDATE bottlenecks SET status=? WHERE bottleneck_id=?",
                                   (status, row["bottleneck_id"]))
                append_event(connection, actor_id="system", action="bottleneck.recomputed",
                             resource_type="bottleneck", resource_id=row["bottleneck_id"],
                             detail={"from": row["status"], "to": status}, occurred_at=now)

    def _sweep(self, connection, now: str) -> None:
        for row in connection.execute(
            "SELECT window_id FROM facility_windows WHERE state='open' AND freeze_at<=?", (now,)
        ).fetchall():
            self._freeze_window(connection, row["window_id"], now)
        connection.execute(
            "UPDATE facility_windows SET state='closed' WHERE state<>'closed' AND ends_at<=?", (now,)
        )
        expired = connection.execute(
            "SELECT * FROM leases WHERE state='active' AND expires_at<=?", (now,)
        ).fetchall()
        for lease in expired:
            connection.execute("UPDATE leases SET state='expired' WHERE lease_id=?",
                               (lease["lease_id"],))
            append_event(connection, actor_id="system", action="lease.expired",
                         resource_type="lease", resource_id=lease["lease_id"],
                         detail={"window_id": lease["window_id"],
                                 "solution_id": lease["solution_id"]}, occurred_at=now)
            self._promote_next(connection, lease["window_id"], now, "system")

    def _freeze_window(self, connection, window_id: str, now: str) -> None:
        window = connection.execute(
            "SELECT * FROM facility_windows WHERE window_id=?", (window_id,)
        ).fetchone()
        if window is None or window["state"] != "open" or window["freeze_at"] > now:
            return
        entries = connection.execute(
            "SELECT entry_id FROM waitlist WHERE window_id=? AND status='waiting' AND frozen_seq IS NULL "
            "ORDER BY priority DESC, requested_at ASC, entry_id ASC", (window_id,)
        ).fetchall()
        row = connection.execute(
            "SELECT COALESCE(MAX(frozen_seq),0) AS seq FROM waitlist WHERE window_id=?", (window_id,)
        ).fetchone()
        seq = row["seq"]
        for entry in entries:
            seq += 1
            connection.execute("UPDATE waitlist SET frozen_seq=? WHERE entry_id=?",
                               (seq, entry["entry_id"]))
        connection.execute("UPDATE facility_windows SET state='frozen' WHERE window_id=?", (window_id,))
        append_event(connection, actor_id="system", action="window.frozen",
                     resource_type="facility_window", resource_id=window_id,
                     detail={"frozen_entries": len(entries)}, occurred_at=now)

    def _join_waitlist(self, connection, actor_id: str, window, solution_id: str, team: str,
                       priority: int, now: str) -> tuple[str, bool]:
        existing = connection.execute(
            "SELECT * FROM waitlist WHERE window_id=? AND solution_id=? AND status='waiting'",
            (window["window_id"], solution_id),
        ).fetchone()
        if existing is not None:
            return existing["entry_id"], False
        frozen_seq = None
        if window["state"] == "frozen":
            row = connection.execute(
                "SELECT COALESCE(MAX(frozen_seq),0) AS seq FROM waitlist WHERE window_id=?",
                (window["window_id"],),
            ).fetchone()
            frozen_seq = row["seq"] + 1
        entry_id = uuid.uuid4().hex
        connection.execute(
            "INSERT INTO waitlist(entry_id,window_id,solution_id,team_id,priority,requested_at,"
            "frozen_seq,status) VALUES(?,?,?,?,?,?,?,'waiting')",
            (entry_id, window["window_id"], solution_id, team, priority, now, frozen_seq),
        )
        append_event(connection, actor_id=actor_id, action="waitlist.joined",
                     resource_type="waitlist", resource_id=entry_id,
                     detail={"window_id": window["window_id"], "solution_id": solution_id,
                             "priority": priority, "frozen_seq": frozen_seq}, occurred_at=now)
        return entry_id, True

    def _waitlist_position(self, connection, entry_id: str) -> int | None:
        entry = connection.execute(
            "SELECT * FROM waitlist WHERE entry_id=?", (entry_id,)
        ).fetchone()
        if entry is None or entry["status"] != "waiting":
            return None
        rows = connection.execute(
            "SELECT entry_id FROM waitlist WHERE window_id=? AND status='waiting' "
            "ORDER BY COALESCE(frozen_seq, ?), priority DESC, requested_at ASC, entry_id ASC",
            (entry["window_id"], UNFROZEN_SEQ),
        ).fetchall()
        for index, row in enumerate(rows):
            if row["entry_id"] == entry_id:
                return index + 1
        return None

    def _promote_next(self, connection, window_id: str, now: str, actor_id: str) -> str | None:
        window = self._window(connection, window_id)
        if window["ends_at"] <= now:
            connection.execute(
                "UPDATE waitlist SET status='expired' WHERE window_id=? AND status='waiting'",
                (window_id,),
            )
            return None
        while True:
            entry = connection.execute(
                "SELECT * FROM waitlist WHERE window_id=? AND status='waiting' "
                "ORDER BY COALESCE(frozen_seq, ?), priority DESC, requested_at ASC, entry_id ASC "
                "LIMIT 1",
                (window_id, UNFROZEN_SEQ),
            ).fetchone()
            if entry is None:
                return None
            if not self._entry_evidence_ok(connection, entry["solution_id"], now):
                connection.execute("UPDATE waitlist SET status='expired' WHERE entry_id=?",
                                   (entry["entry_id"],))
                append_event(connection, actor_id="system", action="waitlist.expired",
                             resource_type="waitlist", resource_id=entry["entry_id"],
                             detail={"reason": "入口证据失效"}, occurred_at=now)
                continue
            lease_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO leases(lease_id,window_id,solution_id,team_id,state,granted_at,"
                "expires_at,released_at) VALUES(?,?,?,?,'active',?,?,NULL)",
                (lease_id, window_id, entry["solution_id"], entry["team_id"], now, window["ends_at"]),
            )
            connection.execute("UPDATE waitlist SET status='promoted' WHERE entry_id=?",
                               (entry["entry_id"],))
            append_event(connection, actor_id=actor_id, action="waitlist.promoted",
                         resource_type="waitlist", resource_id=entry["entry_id"],
                         detail={"lease_id": lease_id, "solution_id": entry["solution_id"]},
                         occurred_at=now)
            append_event(connection, actor_id=actor_id, action="lease.granted",
                         resource_type="lease", resource_id=lease_id,
                         detail={"window_id": window_id, "solution_id": entry["solution_id"],
                                 "team_id": entry["team_id"], "expires_at": window["ends_at"],
                                 "promoted": True}, occurred_at=now)
            return lease_id

    def _switch_cost(self, connection, solution, now: str) -> dict[str, Any]:
        siblings = connection.execute(
            "SELECT solution_id FROM solutions WHERE bottleneck_id=? AND solution_id<>?",
            (solution["bottleneck_id"], solution["solution_id"]),
        ).fetchall()
        sunk = 0
        for sibling in siblings:
            sunk += connection.execute(
                "SELECT COUNT(*) AS count FROM test_batches WHERE solution_id=?",
                (sibling["solution_id"],),
            ).fetchone()["count"]
        required = json.loads(solution["required_evidence_json"])
        gap = [kind for kind in required
               if not self._evidence_valid(connection, solution["solution_id"], kind, now)]
        base = float(solution["switch_cost"])
        return {"base_cost": base, "sunk_batches": sunk, "evidence_gap": gap,
                "total_cost": base + float(sunk) + float(len(gap))}

    def _waiting_reasons(self, connection, bottleneck, now: str) -> list[dict[str, Any]]:
        if bottleneck["status"] == "verified":
            return []
        reasons: list[dict[str, Any]] = []
        dependencies = connection.execute(
            "SELECT b.bottleneck_id, b.name, b.status FROM bottleneck_dependencies d "
            "JOIN bottlenecks b ON b.bottleneck_id=d.depends_on "
            "WHERE d.bottleneck_id=? ORDER BY b.bottleneck_id",
            (bottleneck["bottleneck_id"],),
        ).fetchall()
        for dependency in dependencies:
            if dependency["status"] != "verified":
                reasons.append({"type": "dependency_unverified",
                                "depends_on": dependency["bottleneck_id"],
                                "name": dependency["name"]})
        solution = connection.execute(
            "SELECT * FROM solutions WHERE bottleneck_id=? AND status='active'",
            (bottleneck["bottleneck_id"],),
        ).fetchone()
        if solution is None:
            reasons.append({"type": "no_active_solution"})
            return reasons
        for kind in json.loads(solution["required_evidence_json"]):
            if self._evidence_valid(connection, solution["solution_id"], kind, now):
                continue
            any_row = connection.execute(
                "SELECT 1 FROM evidence WHERE solution_id=? AND kind=? LIMIT 1",
                (solution["solution_id"], kind),
            ).fetchone()
            reasons.append({"type": "evidence_expired" if any_row else "evidence_missing",
                            "kind": kind, "solution_id": solution["solution_id"]})
        lease = connection.execute(
            "SELECT lease_id FROM leases WHERE solution_id=? AND state='active' AND expires_at>? LIMIT 1",
            (solution["solution_id"], now),
        ).fetchone()
        if lease is None:
            entry = connection.execute(
                "SELECT entry_id, window_id FROM waitlist WHERE solution_id=? AND status='waiting' "
                "ORDER BY requested_at LIMIT 1",
                (solution["solution_id"],),
            ).fetchone()
            if entry is not None:
                reasons.append({"type": "waitlisted", "window_id": entry["window_id"],
                                "position": self._waitlist_position(connection, entry["entry_id"])})
            else:
                reasons.append({"type": "resource_unavailable",
                                "solution_id": solution["solution_id"]})
        return reasons

    def _critical_path(self, connection, site_id: str) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT * FROM bottlenecks WHERE site_id=? AND status<>'verified' ORDER BY bottleneck_id",
            (site_id,),
        ).fetchall()
        if not rows:
            return {"site_id": site_id, "total_days": 0, "path": []}
        ids = [row["bottleneck_id"] for row in rows]
        id_set = set(ids)
        estimates = {row["bottleneck_id"]: row["estimate_days"] for row in rows}
        placeholders = ",".join(["?"] * len(ids))
        dependencies = connection.execute(
            f"SELECT bottleneck_id, depends_on FROM bottleneck_dependencies "
            f"WHERE bottleneck_id IN ({placeholders})", ids,
        ).fetchall()
        adjacency: dict[str, list[str]] = {node: [] for node in ids}
        indegree: dict[str, int] = {node: 0 for node in ids}
        for dependency in dependencies:
            if dependency["depends_on"] in id_set:
                adjacency[dependency["depends_on"]].append(dependency["bottleneck_id"])
                indegree[dependency["bottleneck_id"]] += 1
        queue = sorted(node for node in ids if indegree[node] == 0)
        topo: list[str] = []
        while queue:
            node = queue.pop(0)
            topo.append(node)
            for follower in sorted(adjacency[node]):
                indegree[follower] -= 1
                if indegree[follower] == 0:
                    queue.append(follower)
                    queue.sort()
        if len(topo) != len(ids):
            raise ConflictError("依赖图中存在循环")
        longest = {node: estimates[node] for node in ids}
        parent: dict[str, str] = {}
        for node in topo:
            for follower in adjacency[node]:
                candidate = longest[node] + estimates[follower]
                if candidate > longest[follower]:
                    longest[follower] = candidate
                    parent[follower] = node
        best = sorted(ids, key=lambda node: (-longest[node], node))[0]
        chain = []
        node: str | None = best
        while node is not None:
            chain.append(node)
            node = parent.get(node)
        chain.reverse()
        by_id = {row["bottleneck_id"]: row for row in rows}
        return {"site_id": site_id, "total_days": longest[best],
                "path": [{"bottleneck_id": node, "name": by_id[node]["name"],
                          "estimate_days": estimates[node], "status": by_id[node]["status"]}
                         for node in chain]}

    def _bottleneck_view(self, connection, row, now: str) -> dict[str, Any]:
        dependencies = connection.execute(
            "SELECT depends_on FROM bottleneck_dependencies WHERE bottleneck_id=? ORDER BY depends_on",
            (row["bottleneck_id"],),
        ).fetchall()
        active = connection.execute(
            "SELECT solution_id FROM solutions WHERE bottleneck_id=? AND status='active'",
            (row["bottleneck_id"],),
        ).fetchone()
        commitments = connection.execute(
            "SELECT team_id, milestone, promised_date FROM commitments WHERE bottleneck_id=? "
            "ORDER BY created_at",
            (row["bottleneck_id"],),
        ).fetchall()
        return {
            "bottleneck_id": row["bottleneck_id"],
            "name": row["name"],
            "status": row["status"],
            "owner_team": row["owner_team"],
            "security_level": row["security_level"],
            "origin_key": row["origin_key"],
            "canonical_id": row["canonical_id"],
            "metric": {"name": row["metric_name"], "unit": row["metric_unit"],
                       "direction": row["metric_direction"], "baseline": row["baseline_value"],
                       "target": row["target_value"], "revision": row["metric_revision"]},
            "estimate_days": row["estimate_days"],
            "dependencies": [dependency["depends_on"] for dependency in dependencies],
            "active_solution_id": active["solution_id"] if active else None,
            "commitments": [{"team_id": item["team_id"], "milestone": item["milestone"],
                             "promised_date": item["promised_date"]} for item in commitments],
            "waiting_reasons": self._waiting_reasons(connection, row, now),
        }

    def _same_origin(self, connection, site_id: str, actor) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT bottleneck_id, name, owner_team, normalized_origin, canonical_id "
            "FROM bottlenecks WHERE site_id=? ORDER BY created_at, bottleneck_id",
            (site_id,),
        ).fetchall()
        groups: dict[str, list[Any]] = {}
        for row in rows:
            groups.setdefault(row["normalized_origin"], []).append(row)
        status_by_origin: dict[str, str] = {}
        adjudications = connection.execute(
            "SELECT subject_json, status FROM adjudications WHERE kind='alias_merge' "
            "ORDER BY created_at, adjudication_id"
        ).fetchall()
        for adjudication in adjudications:
            subject = json.loads(adjudication["subject_json"])
            status_by_origin[subject.get("normalized_origin")] = adjudication["status"]
        result = []
        for origin, members in groups.items():
            if len(members) < 2:
                continue
            if actor.role == "lead" and not any(
                member["owner_team"] == actor.organization_id for member in members
            ):
                continue
            canonical = next((member["canonical_id"] for member in members
                              if member["canonical_id"]), None)
            result.append({
                "normalized_origin": origin,
                "bottleneck_ids": [member["bottleneck_id"] for member in members],
                "names": [member["name"] for member in members],
                "canonical_id": canonical,
                "adjudication_status": status_by_origin.get(origin, "none"),
            })
        return result
