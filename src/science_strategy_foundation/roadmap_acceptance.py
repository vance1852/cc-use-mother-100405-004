"""关键技术堵点与攻关路线服务的离线端到端验收。

在临时 SQLite 数据库中走一遍完整流程：同源堵点归并、循环依赖识别、
入口证据门控、限时租约、候补冻结推进、试验事实不可改写、只重算
未完成路径、证据过期触发重算、服务重启后租约与未决裁定恢复。
成功时输出一行 status 为 ok 的 JSON 并以退出码 0 结束。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .errors import ConflictError
from .roadmap import RoadmapService
from .service import DomainService
from .storage import Database


class StepClock:
    """离线验收使用的可推进时钟。"""

    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        return self._value

    def advance(self, **kwargs) -> None:
        self._value += timedelta(**kwargs)


def run() -> dict[str, object]:
    """执行一条完整攻关链并返回各检查点结果。"""

    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "roadmap.sqlite3"
        database = Database(path)
        clock = StepClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
        foundation = DomainService(database, clock)
        roadmap = RoadmapService(database, clock, confirm_ttl_seconds=600)

        foundation.register_organization(request_id="org-chief", actor_id="bootstrap",
                                         organization_id="org-chief", name="总师办")
        foundation.register_actor(request_id="actor-admin", actor_id="bootstrap", new_actor_id="admin",
                                  display_name="系统管理员", role="admin", organization_id="org-chief")
        foundation.register_actor(request_id="actor-chief", actor_id="admin", new_actor_id="chief",
                                  display_name="总师", role="chief_engineer", organization_id="org-chief")
        foundation.register_organization(request_id="org-sensor", actor_id="admin",
                                         organization_id="org-sensor", name="传感器团队")
        foundation.register_organization(request_id="org-control", actor_id="admin",
                                         organization_id="org-control", name="控制器团队")
        foundation.register_actor(request_id="actor-sensor", actor_id="admin", new_actor_id="lead-sensor",
                                  display_name="传感器负责人", role="project_lead", organization_id="org-sensor")
        foundation.register_actor(request_id="actor-control", actor_id="admin", new_actor_id="lead-control",
                                  display_name="控制器负责人", role="project_lead", organization_id="org-control")
        foundation.register_site(request_id="site-1", actor_id="admin", site_id="s1",
                                 organization_id="org-chief", name="联合攻关试验场", timezone_name="Asia/Shanghai")

        # 三个团队把同一项进口部件替代登记成不同名称，系统归并到同一根堵点
        root = roadmap.register_bottleneck(request_id="b-root", actor_id="chief", site_id="s1",
                                           name="控制器采样芯片替代", source_name="进口ADC部件替代",
                                           owner_team_id="org-control", estimate_days=10)
        alias = roadmap.register_bottleneck(request_id="b-alias", actor_id="lead-sensor", site_id="s1",
                                            name="传感器前端放大器替代", source_name="进口 ADC 部件替代",
                                            owner_team_id="org-sensor", estimate_days=8)
        checks["same_source_merged"] = bool(alias["merged"]) and alias["root_bottleneck_id"] == root["bottleneck_id"]

        downstream = roadmap.register_bottleneck(request_id="b-down", actor_id="chief", site_id="s1",
                                                 name="整机校准装置联调", source_name="整机校准联调",
                                                 owner_team_id="org-control", estimate_days=5)
        roadmap.add_dependency(request_id="dep-1", actor_id="chief",
                               upstream_id=root["bottleneck_id"], downstream_id=downstream["bottleneck_id"])
        try:
            roadmap.add_dependency(request_id="dep-cycle", actor_id="chief",
                                   upstream_id=downstream["bottleneck_id"], downstream_id=root["bottleneck_id"])
            checks["cycle_rejected"] = False
        except ConflictError:
            checks["cycle_rejected"] = True

        roadmap.register_metric(request_id="m-root", actor_id="chief", bottleneck_id=root["bottleneck_id"],
                                name="采样精度", unit="bit", target_value=24, direction="at_least")
        solution = roadmap.register_solution(request_id="sol-1", actor_id="lead-control",
                                             bottleneck_id=root["bottleneck_id"], name="国产ADC直替",
                                             required_evidence=["仿真报告"], switch_cost=1.0)
        roadmap.register_solution(request_id="sol-2", actor_id="chief",
                                  bottleneck_id=root["bottleneck_id"], name="分立元件重构",
                                  required_evidence=[], switch_cost=4.0)
        window = roadmap.register_window(request_id="w-1", actor_id="chief", facility_id="bench-1",
                                         site_id="s1", starts_at="2026-10-06T09:00:00Z",
                                         ends_at="2026-10-06T17:00:00Z")

        # 入口证据未满足时不能获得限时资源
        try:
            roadmap.acquire_lease(request_id="lease-blocked", actor_id="lead-control",
                                  window_id=window["window_id"], solution_id=solution["solution_id"],
                                  team_id="org-control", ttl_seconds=3600)
            checks["evidence_gated"] = False
        except ConflictError:
            checks["evidence_gated"] = True
        roadmap.register_evidence(request_id="ev-1", actor_id="lead-control",
                                  bottleneck_id=root["bottleneck_id"], evidence_type="仿真报告",
                                  confidentiality="internal", expires_at="2026-10-07T08:00:00Z",
                                  payload={"report": "sim-2026-101"})
        lease = roadmap.acquire_lease(request_id="lease-1", actor_id="lead-control",
                                      window_id=window["window_id"], solution_id=solution["solution_id"],
                                      team_id="org-control", ttl_seconds=3600)
        checks["lease_acquired"] = lease["status"] == "active"

        # 候补在释放瞬间冻结，按冻结顺序推进；并发确认只有一个成功
        roadmap.join_waitlist(request_id="wait-1", actor_id="lead-sensor", window_id=window["window_id"],
                              solution_id=solution["solution_id"], team_id="org-sensor")
        released = roadmap.release_lease(request_id="release-1", actor_id="lead-control",
                                         lease_id=lease["lease_id"])
        adjudication = released.get("adjudication", {})
        checks["waitlist_promoted"] = adjudication.get("team_id") == "org-sensor"
        confirmed = roadmap.confirm_adjudication(request_id="confirm-1", actor_id="lead-sensor",
                                                 adjudication_id=adjudication["adjudication_id"],
                                                 team_id="org-sensor")
        try:
            roadmap.confirm_adjudication(request_id="confirm-2", actor_id="lead-sensor",
                                         adjudication_id=adjudication["adjudication_id"],
                                         team_id="org-sensor")
            checks["single_confirm"] = False
        except ConflictError:
            checks["single_confirm"] = True
        checks["confirm_lease"] = confirmed["status"] == "confirmed"

        # 试验通过形成不可改写的事实，堵点完成
        batch = roadmap.register_test_batch(request_id="batch-1", actor_id="lead-sensor",
                                            solution_id=solution["solution_id"],
                                            lease_id=confirmed["lease_id"])
        passed = roadmap.record_test_result(request_id="result-1", actor_id="lead-sensor",
                                            batch_id=batch["batch_id"], result="passed",
                                            measured={"precision_bit": 24})
        checks["resolved"] = bool(passed.get("resolved"))
        try:
            roadmap.record_test_result(request_id="result-2", actor_id="lead-sensor",
                                       batch_id=batch["batch_id"], result="failed")
            checks["fact_immutable"] = False
        except ConflictError:
            checks["fact_immutable"] = True
        try:
            roadmap.degrade_metric(request_id="degrade-blocked", actor_id="chief",
                                   metric_id=roadmap.bottleneck_detail("chief", root["bottleneck_id"])["metrics"][0]["metric_id"],
                                   new_target_value=16)
            checks["resolved_frozen"] = False
        except ConflictError:
            checks["resolved_frozen"] = True

        # 下游堵点：指标降级与证据过期只重算未完成路径
        metric_down = roadmap.register_metric(request_id="m-down", actor_id="chief",
                                              bottleneck_id=downstream["bottleneck_id"],
                                              name="校准误差", unit="um", target_value=5, direction="at_most")
        solution_down = roadmap.register_solution(request_id="sol-down", actor_id="lead-control",
                                                  bottleneck_id=downstream["bottleneck_id"],
                                                  name="激光干涉校准", required_evidence=["环境报告"])
        degraded = roadmap.degrade_metric(request_id="degrade-1", actor_id="chief",
                                          metric_id=metric_down["metric_id"], new_target_value=8)
        checks["degrade_recomputed"] = degraded["recomputed"] == [downstream["bottleneck_id"]]
        roadmap.register_evidence(request_id="ev-2", actor_id="lead-control",
                                  bottleneck_id=downstream["bottleneck_id"], evidence_type="环境报告",
                                  confidentiality="open", expires_at="2026-10-06T10:00:00Z")
        clock.advance(hours=3)
        swept = roadmap.expire_evidence_sweep(request_id="sweep-evidence", actor_id="chief")
        checks["expiry_recomputed"] = swept["recomputed"] == [downstream["bottleneck_id"]]
        window2 = roadmap.register_window(request_id="w-2", actor_id="chief", facility_id="bench-2",
                                          site_id="s1", starts_at="2026-10-06T12:00:00Z",
                                          ends_at="2026-10-06T20:00:00Z")
        try:
            roadmap.acquire_lease(request_id="lease-expired", actor_id="lead-control",
                                  window_id=window2["window_id"], solution_id=solution_down["solution_id"],
                                  team_id="org-control", ttl_seconds=600)
            checks["expired_evidence_blocked"] = False
        except ConflictError:
            checks["expired_evidence_blocked"] = True

        # 制造一个未决裁定，验证服务重启后租约与裁定仍可恢复
        aux = roadmap.register_bottleneck(request_id="b-aux", actor_id="chief", site_id="s1",
                                          name="辅助电源国产化", source_name="辅助电源",
                                          owner_team_id="org-control", estimate_days=3)
        solution_aux = roadmap.register_solution(request_id="sol-aux", actor_id="chief",
                                                 bottleneck_id=aux["bottleneck_id"], name="国产电源模块")
        window3 = roadmap.register_window(request_id="w-3", actor_id="chief", facility_id="bench-3",
                                          site_id="s1", starts_at="2026-10-06T12:00:00Z",
                                          ends_at="2026-10-06T18:00:00Z")
        lease_aux = roadmap.acquire_lease(request_id="lease-aux", actor_id="chief",
                                          window_id=window3["window_id"],
                                          solution_id=solution_aux["solution_id"],
                                          team_id="org-control", ttl_seconds=1800)
        roadmap.join_waitlist(request_id="wait-aux", actor_id="lead-sensor",
                              window_id=window3["window_id"],
                              solution_id=solution_aux["solution_id"], team_id="org-sensor")
        released_aux = roadmap.release_lease(request_id="release-aux", actor_id="chief",
                                             lease_id=lease_aux["lease_id"])
        pending_id = released_aux["adjudication"]["adjudication_id"]
        database.close()

        reopened = Database(path)
        roadmap2 = RoadmapService(reopened, clock, confirm_ttl_seconds=600)
        foundation2 = DomainService(reopened, clock)
        snapshot = roadmap2.recovery_snapshot("chief")
        recovered_lease_ids = {item["lease_id"] for item in snapshot["leases"]}
        recovered_pending = {item["adjudication_id"] for item in snapshot["adjudications"]}
        checks["restart_recovered"] = confirmed["lease_id"] in recovered_lease_ids and pending_id in recovered_pending
        after_restart = roadmap2.confirm_adjudication(request_id="confirm-aux", actor_id="lead-sensor",
                                                      adjudication_id=pending_id, team_id="org-sensor")
        checks["restart_confirm"] = after_restart["status"] == "confirmed"
        valid, _ = foundation2.verify_audit()
        checks["audit_valid"] = valid

        # 权限化视图：总师看全局关键路径，课题负责人看本团队范围与可披露证据
        roadmap2.register_evidence(request_id="ev-3", actor_id="chief",
                                   bottleneck_id=downstream["bottleneck_id"], evidence_type="复测数据",
                                   confidentiality="confidential", expires_at="2026-10-08T08:00:00Z")
        path = roadmap2.critical_path("chief")
        checks["critical_path"] = path["total_days"] == 5 and [n["bottleneck_id"] for n in path["path"]] == [downstream["bottleneck_id"]]
        lead_evidence = roadmap2.disclosable_evidence("lead-control", downstream["bottleneck_id"])
        chief_evidence = roadmap2.disclosable_evidence("chief", downstream["bottleneck_id"])
        checks["evidence_disclosure"] = (
            all(item["confidentiality"] != "confidential" for item in lead_evidence["items"])
            and any(item["confidentiality"] == "confidential" for item in chief_evidence["items"])
        )
        reasons = roadmap2.wait_reasons("chief")
        down_reasons = next((item for item in reasons["items"]
                             if item["bottleneck_id"] == downstream["bottleneck_id"]), None)
        checks["wait_reasons"] = down_reasons is not None and any(
            reason["type"] == "missing_evidence" for reason in down_reasons["reasons"])
        reopened.close()

    checks["status"] = all(checks.values())
    return {"status": "ok" if checks["status"] else "failed", "checks": checks}


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
