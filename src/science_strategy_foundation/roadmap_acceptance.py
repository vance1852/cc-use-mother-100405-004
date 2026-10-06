"""运行关键技术堵点与攻关路线服务的离线端到端验收。

场景：传感器、控制器、校准装置三个团队把同一项进口部件替代登记成不同名称的堵点，
服务识别同源与循环依赖，按入口证据发放公共试验台的限时租约，试验失败启用替代路线，
指标降级与证据过期只重算未完成路径，最后重启服务恢复租约与未决裁定。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import MutableClock
from .errors import ConflictError, PermissionDenied, ValidationError
from .roadmap import RoadmapService
from .storage import Database

T0 = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)


def _at(moment: datetime) -> str:
    return moment.isoformat()


def run() -> dict[str, object]:
    """执行完整攻关路线场景并返回各项检查结果。"""

    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "roadmap.sqlite3"
        clock = MutableClock(T0)
        database = Database(path)
        service = RoadmapService(database, clock)

        # 建档：总师办与三个课题团队
        service.register_organization(request_id="org-hq", actor_id="bootstrap",
                                      organization_id="org-hq", name="总师办")
        service.register_actor(request_id="actor-admin", actor_id="bootstrap", new_actor_id="admin-1",
                               display_name="系统管理员", role="admin", organization_id="org-hq")
        for org_id, name in (("org-sensor", "传感器团队"), ("org-control", "控制器团队"),
                             ("org-calib", "校准装置团队")):
            service.register_organization(request_id=f"org-{org_id}", actor_id="admin-1",
                                          organization_id=org_id, name=name)
        service.register_actor(request_id="actor-chief", actor_id="admin-1", new_actor_id="chief-1",
                               display_name="总师", role="chief", organization_id="org-hq")
        service.register_actor(request_id="actor-sensor", actor_id="admin-1", new_actor_id="lead-sensor",
                               display_name="传感器负责人", role="lead", organization_id="org-sensor")
        service.register_actor(request_id="actor-control", actor_id="admin-1", new_actor_id="lead-control",
                               display_name="控制器负责人", role="lead", organization_id="org-control")
        service.register_actor(request_id="actor-calib", actor_id="admin-1", new_actor_id="lead-calib",
                               display_name="校准负责人", role="lead", organization_id="org-calib")
        service.register_site(request_id="site-1", actor_id="admin-1", site_id="site-1",
                              organization_id="org-hq", name="联合攻关节点", timezone_name="Asia/Shanghai")

        # 三个团队用不同名称登记同一项进口部件替代
        bn_sensor = service.register_bottleneck(
            request_id="bn-sensor", actor_id="lead-sensor", site_id="site-1",
            name="传感器前端ADC替代", origin_key="ADC-X100 进口部件", security_level="internal",
            metric={"name": "采样精度", "unit": "bit", "direction": "gte", "baseline": 14, "target": 18},
            estimate_days=30).resource_id
        bn_control = service.register_bottleneck(
            request_id="bn-control", actor_id="lead-control", site_id="site-1",
            name="控制器模数转换国产化", origin_key="adc-x100进口部件", security_level="internal",
            metric={"name": "转换位数", "unit": "bit", "direction": "gte", "baseline": 12, "target": 16},
            estimate_days=20).resource_id
        bn_calib = service.register_bottleneck(
            request_id="bn-calib", actor_id="lead-calib", site_id="site-1",
            name="校准装置ADC芯片进口替代", origin_key="ADC-X100进口部件", security_level="internal",
            metric={"name": "校准不确定度", "unit": "ppm", "direction": "gte", "baseline": 12, "target": 16},
            estimate_days=25).resource_id

        groups = service.same_origin_groups("chief-1", "site-1")
        checks["same_origin_detected"] = any(
            set(group["bottleneck_ids"]) == {bn_sensor, bn_control, bn_calib} for group in groups)
        pending = service.list_adjudications("chief-1", status="pending")
        checks["adjudication_auto_raised"] = len(pending) == 1 and pending[0]["kind"] == "alias_merge"

        # 依赖：传感器等校准、校准等控制器；反向写入必须被循环检测拒绝
        service.add_dependency(request_id="dep-1", actor_id="lead-sensor",
                               bottleneck_id=bn_sensor, depends_on=bn_calib)
        service.add_dependency(request_id="dep-2", actor_id="lead-calib",
                               bottleneck_id=bn_calib, depends_on=bn_control)
        try:
            service.add_dependency(request_id="dep-3", actor_id="lead-control",
                                   bottleneck_id=bn_control, depends_on=bn_sensor)
            checks["cycle_rejected"] = False
        except ConflictError:
            checks["cycle_rejected"] = True

        # 候选方案与入口证据
        sol_sensor_a = service.register_solution(
            request_id="sol-sensor-a", actor_id="lead-sensor", bottleneck_id=bn_sensor,
            name="进口芯片原位替换", required_evidence=["bench_report"], switch_cost=2).resource_id
        service.activate_solution(request_id="act-sensor-a", actor_id="lead-sensor", solution_id=sol_sensor_a)
        sol_sensor_b = service.register_solution(
            request_id="sol-sensor-b", actor_id="lead-sensor", bottleneck_id=bn_sensor,
            name="国产ADC重设计", required_evidence=["bench_report"], switch_cost=5).resource_id
        sol_control = service.register_solution(
            request_id="sol-control", actor_id="lead-control", bottleneck_id=bn_control,
            name="国产转换器验证", required_evidence=["bench_report"], switch_cost=3).resource_id
        service.activate_solution(request_id="act-control", actor_id="lead-control", solution_id=sol_control)
        sol_calib = service.register_solution(
            request_id="sol-calib", actor_id="lead-calib", bottleneck_id=bn_calib,
            name="校准链路重构", required_evidence=["calibration_certificate"], switch_cost=4).resource_id
        service.activate_solution(request_id="act-calib", actor_id="lead-calib", solution_id=sol_calib)

        service.register_evidence(request_id="ev-sensor", actor_id="lead-sensor", solution_id=sol_sensor_a,
                                  kind="bench_report", security_level="internal",
                                  detail={"report": "台架试验报告"},
                                  valid_from=_at(T0 - timedelta(days=1)),
                                  valid_until=_at(T0 + timedelta(days=10)))
        service.register_evidence(request_id="ev-control", actor_id="chief-1", solution_id=sol_control,
                                  kind="bench_report", security_level="secret",
                                  detail={"report": "涉密台架数据"},
                                  valid_from=_at(T0 - timedelta(days=1)),
                                  valid_until=_at(T0 + timedelta(days=10)))
        service.register_evidence(request_id="ev-calib-stale", actor_id="lead-calib", solution_id=sol_calib,
                                  kind="calibration_certificate", security_level="internal",
                                  detail={"certificate": "过期证书"},
                                  valid_from=_at(T0 - timedelta(days=3)),
                                  valid_until=_at(T0 - timedelta(days=1)))

        # 公共试验台窗口
        facility = service.register_facility(request_id="fac-1", actor_id="admin-1",
                                             site_id="site-1", name="公共试验台").resource_id
        window = service.register_window(request_id="win-1", actor_id="admin-1", facility_id=facility,
                                         starts_at=_at(T0), ends_at=_at(T0 + timedelta(days=7)),
                                         freeze_at=_at(T0 + timedelta(days=2))).resource_id

        # 入口证据未满足（证书已过期）的方案拿不到限时资源
        try:
            service.confirm_resource(request_id="cf-calib-early", actor_id="lead-calib",
                                     window_id=window, solution_id=sol_calib)
            checks["lease_blocked_without_evidence"] = False
        except PermissionDenied:
            checks["lease_blocked_without_evidence"] = True

        # 并发确认同一窗口：只有一个获得租约，其余进入候补
        granted = service.confirm_resource(request_id="cf-sensor", actor_id="lead-sensor",
                                           window_id=window, solution_id=sol_sensor_a, priority=5)
        queued_control = service.confirm_resource(request_id="cf-control", actor_id="lead-control",
                                                  window_id=window, solution_id=sol_control, priority=9)
        checks["single_winner"] = (granted.resource_type == "lease"
                                   and queued_control.resource_type == "waitlist")
        lease_sensor = granted.resource_id

        # 冻结时点之后加入的候补，即使优先级更高也只能追加到队尾
        clock.advance(days=3)
        service.register_evidence(request_id="ev-calib-fresh", actor_id="lead-calib", solution_id=sol_calib,
                                  kind="calibration_certificate", security_level="internal",
                                  detail={"certificate": "新证书"},
                                  valid_from=_at(T0 + timedelta(days=3)),
                                  valid_until=_at(T0 + timedelta(days=10)))
        queued_calib = service.confirm_resource(request_id="cf-calib", actor_id="lead-calib",
                                                window_id=window, solution_id=sol_calib, priority=99)
        checks["freeze_appends_latecomer"] = (queued_calib.resource_type == "waitlist"
                                              and queued_calib.response.get("position") == 2)

        # 释放后候补按冻结顺序推进
        released = service.release_lease(request_id="rel-sensor", actor_id="chief-1", lease_id=lease_sensor)
        promoted_lease = released.response.get("promoted_lease_id")
        leases_now = service.list_leases("chief-1", window)
        promoted = [item for item in leases_now["leases"] if item["lease_id"] == promoted_lease]
        checks["release_promotes_head"] = bool(promoted) and promoted[0]["solution_id"] == sol_control

        # 试验批次：传感器失败（启用替代路线），控制器通过（堵点验证）
        service.record_test_batch(request_id="tb-sensor", actor_id="lead-sensor",
                                  solution_id=sol_sensor_a, lease_id=lease_sensor,
                                  result="failed", metrics={"precision_bit": 15.2})
        service.record_test_batch(request_id="tb-control", actor_id="lead-control",
                                  solution_id=sol_control, lease_id=promoted_lease,
                                  result="passed", metrics={"bits": 16.4})
        try:
            database.connection.execute("DELETE FROM test_batches")
            checks["facts_immutable"] = False
        except sqlite3.IntegrityError:
            checks["facts_immutable"] = True

        # 替代路线的切换代价 = 基础代价 + 已沉没试验批次 + 证据缺口
        cost = service.switch_cost("chief-1", sol_sensor_b)
        checks["switch_cost_computed"] = (cost["base_cost"] == 5.0 and cost["sunk_batches"] == 1
                                          and cost["evidence_gap"] == ["bench_report"]
                                          and cost["total_cost"] == 7.0)
        service.activate_solution(request_id="act-sensor-b", actor_id="lead-sensor", solution_id=sol_sensor_b)
        service.register_evidence(request_id="ev-sensor-b", actor_id="lead-sensor", solution_id=sol_sensor_b,
                                  kind="bench_report", security_level="internal",
                                  detail={"report": "重设计台架报告"},
                                  valid_from=_at(T0 + timedelta(days=3)),
                                  valid_until=_at(T0 + timedelta(days=10)))

        # 指标降级留下修订记录，只接受真正的降级方向
        downgraded = service.downgrade_metric(request_id="dg-calib", actor_id="chief-1",
                                              bottleneck_id=bn_calib, new_target=15,
                                              reason="样机实测达不到原指标")
        checks["downgrade_recorded"] = downgraded.response.get("metric_revision") == 2
        try:
            service.downgrade_metric(request_id="dg-calib-up", actor_id="chief-1",
                                     bottleneck_id=bn_calib, new_target=17, reason="反向调整")
            checks["downgrade_direction_checked"] = False
        except ValidationError:
            checks["downgrade_direction_checked"] = True

        # 总师看关键路径，课题负责人无权查看
        critical = service.critical_path("chief-1", "site-1")
        checks["critical_path_computed"] = (
            critical["total_days"] == 55
            and [node["bottleneck_id"] for node in critical["path"]] == [bn_calib, bn_sensor])
        try:
            service.critical_path("lead-sensor", "site-1")
            checks["lead_denied_critical_path"] = False
        except PermissionDenied:
            checks["lead_denied_critical_path"] = True

        waiting = service.waiting_reasons("chief-1", bn_calib)
        checks["waiting_reason_waitlisted"] = any(
            reason["type"] == "waitlisted" and reason["position"] == 1
            for reason in waiting["reasons"])

        # 可披露证据：总师可见涉密细节，本团队负责人按密级打码，外团队直接拒绝
        checks["chief_sees_secret"] = service.list_evidence("chief-1", sol_control)[0]["disclosed"]
        checks["lead_redacted"] = not service.list_evidence("lead-control", sol_control)[0]["disclosed"]
        try:
            service.list_evidence("lead-sensor", sol_control)
            checks["cross_team_denied"] = False
        except PermissionDenied:
            checks["cross_team_denied"] = True

        # 服务重启：租约按到期时间推进，未决裁定仍可恢复
        database.close()
        clock.advance(days=10)
        database2 = Database(path)
        service2 = RoadmapService(database2, clock)
        recovered = service2.list_leases("chief-1", window)
        states = {item["lease_id"]: item["state"] for item in recovered["leases"]}
        checks["restart_lease_expired"] = states.get(promoted_lease) == "expired"
        checks["restart_no_active_lease"] = not any(
            item["state"] == "active" for item in recovered["leases"])
        still_pending = service2.list_adjudications("chief-1", status="pending")
        checks["restart_adjudication_pending"] = len(still_pending) == 1

        # 已验证堵点不受证据过期影响，试验事实保持
        verified = service2.waiting_reasons("chief-1", bn_control)
        checks["verified_survives_expiry"] = verified["status"] == "verified" and not verified["reasons"]

        # 裁定结案：确认同源并指定基准堵点
        resolved = service2.resolve_adjudication(request_id="res-alias", actor_id="chief-1",
                                                 adjudication_id=still_pending[0]["adjudication_id"],
                                                 decision="approved", rationale="确认为同源堵点")
        groups_after = service2.same_origin_groups("chief-1", "site-1")
        canonical = next((group["canonical_id"] for group in groups_after
                          if set(group["bottleneck_ids"]) == {bn_sensor, bn_control, bn_calib}), None)
        checks["adjudication_sets_canonical"] = (resolved.response.get("canonical_id") == canonical
                                                 and canonical is not None)

        valid, event_count = service2.verify_audit()
        checks["audit_valid"] = valid
        result: dict[str, object] = {"status": "ok" if all(checks.values()) else "failed",
                                     "checks": checks, "audit_events": event_count}
        database2.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
