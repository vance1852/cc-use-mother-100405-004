import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from science_strategy_foundation.errors import ConflictError, PermissionDenied, ValidationError
from science_strategy_foundation.roadmap import RoadmapService, normalize_source_key
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database


class MutableClock:
    def __init__(self, value):
        self._value = value

    def now(self):
        return self._value

    def advance(self, **kwargs):
        self._value += timedelta(**kwargs)


def build_environment(database, clock):
    foundation = DomainService(database, clock)
    foundation.register_organization(request_id="org-chief", actor_id="bootstrap",
                                     organization_id="org-chief", name="总师办")
    foundation.register_actor(request_id="actor-admin", actor_id="bootstrap", new_actor_id="admin",
                              display_name="管理员", role="admin", organization_id="org-chief")
    foundation.register_actor(request_id="actor-chief", actor_id="admin", new_actor_id="chief",
                              display_name="总师", role="chief_engineer", organization_id="org-chief")
    for org_id, name in (("org-sensor", "传感器团队"), ("org-control", "控制器团队")):
        foundation.register_organization(request_id=f"org-{org_id}", actor_id="admin",
                                         organization_id=org_id, name=name)
    foundation.register_actor(request_id="actor-sensor", actor_id="admin", new_actor_id="lead-sensor",
                              display_name="传感器负责人", role="project_lead", organization_id="org-sensor")
    foundation.register_actor(request_id="actor-control", actor_id="admin", new_actor_id="lead-control",
                              display_name="控制器负责人", role="project_lead", organization_id="org-control")
    foundation.register_actor(request_id="actor-auditor", actor_id="admin", new_actor_id="auditor",
                              display_name="审计员", role="auditor", organization_id="org-chief")
    foundation.register_site(request_id="site-1", actor_id="admin", site_id="s1",
                             organization_id="org-chief", name="联合攻关试验场",
                             timezone_name="Asia/Shanghai")
    return foundation


class RoadmapTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = MutableClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
        self.foundation = build_environment(self.database, self.clock)
        self.roadmap = RoadmapService(self.database, self.clock, confirm_ttl_seconds=600)

    def tearDown(self):
        self.database.close()

    # ---------- 准备工具 ----------

    def make_bottleneck(self, request_id="b-1", name="进口部件替代", source="进口ADC部件替代",
                        owner="org-control", estimate=10, actor="chief"):
        return self.roadmap.register_bottleneck(
            request_id=request_id, actor_id=actor, site_id="s1", name=name,
            source_name=source, owner_team_id=owner, estimate_days=estimate)

    def make_solution(self, bottleneck_id, request_id="sol-1", name="国产直替",
                      required=(), switch_cost=1.0, actor="chief"):
        return self.roadmap.register_solution(
            request_id=request_id, actor_id=actor, bottleneck_id=bottleneck_id,
            name=name, required_evidence=list(required), switch_cost=switch_cost)

    def make_window(self, request_id="w-1", facility="bench-1",
                    starts="2026-10-06T09:00:00Z", ends="2026-10-06T17:00:00Z"):
        return self.roadmap.register_window(request_id=request_id, actor_id="chief",
                                            facility_id=facility, site_id="s1",
                                            starts_at=starts, ends_at=ends)

    def test_source_key_normalization(self):
        self.assertEqual(normalize_source_key("进口 ADC 部件-替代"), normalize_source_key("进口adc部件替代"))

    def test_same_source_bottlenecks_are_merged(self):
        root = self.make_bottleneck()
        alias = self.roadmap.register_bottleneck(
            request_id="b-2", actor_id="lead-sensor", site_id="s1", name="传感器前端放大器替代",
            source_name="进口 ADC 部件替代", owner_team_id="org-sensor", estimate_days=8)
        self.assertFalse(root["merged"])
        self.assertTrue(alias["merged"])
        self.assertEqual(root["bottleneck_id"], alias["root_bottleneck_id"])
        detail = self.roadmap.bottleneck_detail("chief", root["bottleneck_id"])
        self.assertEqual([alias["bottleneck_id"]], [a["bottleneck_id"] for a in detail["aliases"]])

    def test_lead_cannot_register_for_other_team(self):
        with self.assertRaises(PermissionDenied):
            self.make_bottleneck(actor="lead-sensor", owner="org-control")

    def test_cycle_dependency_is_rejected(self):
        first = self.make_bottleneck(request_id="b-a", source="堵点甲")
        second = self.make_bottleneck(request_id="b-b", source="堵点乙")
        third = self.make_bottleneck(request_id="b-c", source="堵点丙")
        self.roadmap.add_dependency(request_id="d-1", actor_id="chief",
                                    upstream_id=first["bottleneck_id"], downstream_id=second["bottleneck_id"])
        self.roadmap.add_dependency(request_id="d-2", actor_id="chief",
                                    upstream_id=second["bottleneck_id"], downstream_id=third["bottleneck_id"])
        with self.assertRaises(ConflictError) as ctx:
            self.roadmap.add_dependency(request_id="d-3", actor_id="chief",
                                        upstream_id=third["bottleneck_id"], downstream_id=first["bottleneck_id"])
        self.assertIn("循环", str(ctx.exception))
        with self.assertRaises(ValidationError):
            self.roadmap.add_dependency(request_id="d-4", actor_id="chief",
                                        upstream_id=first["bottleneck_id"],
                                        downstream_id=first["bottleneck_id"])

    def test_entry_evidence_gates_lease(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"], required=["仿真报告"])
        window = self.make_window()
        with self.assertRaises(ConflictError) as ctx:
            self.roadmap.acquire_lease(request_id="l-1", actor_id="lead-control",
                                       window_id=window["window_id"],
                                       solution_id=solution["solution_id"], team_id="org-control")
        self.assertIn("入口证据", str(ctx.exception))
        self.roadmap.register_evidence(request_id="e-1", actor_id="lead-control",
                                       bottleneck_id=root["bottleneck_id"], evidence_type="仿真报告",
                                       confidentiality="internal", expires_at="2026-10-07T08:00:00Z")
        lease = self.roadmap.acquire_lease(request_id="l-2", actor_id="lead-control",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control",
                                           ttl_seconds=3600)
        self.assertEqual("active", lease["status"])
        self.assertEqual("2026-10-06T09:00:00Z", lease["expires_at"])

    def test_expired_evidence_blocks_lease_and_recomputes(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"], required=["环境报告"])
        self.roadmap.register_evidence(request_id="e-1", actor_id="chief",
                                       bottleneck_id=root["bottleneck_id"], evidence_type="环境报告",
                                       confidentiality="open", expires_at="2026-10-06T10:00:00Z")
        self.clock.advance(hours=3)
        swept = self.roadmap.expire_evidence_sweep(request_id="sweep-1", actor_id="chief")
        self.assertEqual([root["bottleneck_id"]], swept["recomputed"])
        window = self.make_window(starts="2026-10-06T12:00:00Z", ends="2026-10-06T18:00:00Z")
        with self.assertRaises(ConflictError):
            self.roadmap.acquire_lease(request_id="l-1", actor_id="lead-control",
                                       window_id=window["window_id"],
                                       solution_id=solution["solution_id"], team_id="org-control")

    def test_concurrent_lease_has_single_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "race.sqlite3")
            setup_db = Database(path)
            clock = MutableClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
            build_environment(setup_db, clock)
            roadmap = RoadmapService(setup_db, clock)
            root = roadmap.register_bottleneck(request_id="b-1", actor_id="chief", site_id="s1",
                                               name="堵点", source_name="堵点", owner_team_id="org-control",
                                               estimate_days=1)
            solution = roadmap.register_solution(request_id="s-1", actor_id="chief",
                                                 bottleneck_id=root["bottleneck_id"], name="方案")
            window = roadmap.register_window(request_id="w-1", actor_id="chief", facility_id="bench-1",
                                             site_id="s1", starts_at="2026-10-06T09:00:00Z",
                                             ends_at="2026-10-06T17:00:00Z")
            other_db = Database(path)
            other = RoadmapService(other_db, clock)
            barrier = threading.Barrier(2)
            outcomes = []

            def acquire(service, tag):
                barrier.wait()
                try:
                    service.acquire_lease(request_id=f"lease-{tag}", actor_id="chief",
                                          window_id=window["window_id"],
                                          solution_id=solution["solution_id"],
                                          team_id="org-control", ttl_seconds=600)
                    outcomes.append("ok")
                except ConflictError:
                    outcomes.append("conflict")

            threads = [threading.Thread(target=acquire, args=(roadmap, "a")),
                       threading.Thread(target=acquire, args=(other, "b"))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["conflict", "ok"])
            other_db.close()
            setup_db.close()

    def test_waitlist_freeze_order_and_single_confirm(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"])
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control")
        self.roadmap.join_waitlist(request_id="q-1", actor_id="lead-sensor",
                                   window_id=window["window_id"],
                                   solution_id=solution["solution_id"], team_id="org-sensor")
        self.roadmap.join_waitlist(request_id="q-2", actor_id="lead-control",
                                   window_id=window["window_id"],
                                   solution_id=solution["solution_id"], team_id="org-control")
        released = self.roadmap.release_lease(request_id="r-1", actor_id="chief",
                                              lease_id=lease["lease_id"])
        adjudication = released["adjudication"]
        self.assertEqual("org-sensor", adjudication["team_id"])
        with self.assertRaises(PermissionDenied):
            self.roadmap.confirm_adjudication(request_id="c-0", actor_id="lead-control",
                                              adjudication_id=adjudication["adjudication_id"],
                                              team_id="org-control")
        confirmed = self.roadmap.confirm_adjudication(request_id="c-1", actor_id="lead-sensor",
                                                      adjudication_id=adjudication["adjudication_id"],
                                                      team_id="org-sensor")
        self.assertEqual("confirmed", confirmed["status"])
        with self.assertRaises(ConflictError):
            self.roadmap.confirm_adjudication(request_id="c-2", actor_id="lead-sensor",
                                              adjudication_id=adjudication["adjudication_id"],
                                              team_id="org-sensor")

    def test_lapsed_adjudication_advances_frozen_queue(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"])
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control")
        self.roadmap.join_waitlist(request_id="q-1", actor_id="lead-sensor",
                                   window_id=window["window_id"],
                                   solution_id=solution["solution_id"], team_id="org-sensor")
        self.roadmap.join_waitlist(request_id="q-2", actor_id="lead-control",
                                   window_id=window["window_id"],
                                   solution_id=solution["solution_id"], team_id="org-control")
        released = self.roadmap.release_lease(request_id="r-1", actor_id="chief",
                                              lease_id=lease["lease_id"])
        first = released["adjudication"]
        self.assertEqual("org-sensor", first["team_id"])
        self.clock.advance(seconds=601)
        with self.assertRaises(ConflictError):
            self.roadmap.confirm_adjudication(request_id="c-1", actor_id="lead-sensor",
                                              adjudication_id=first["adjudication_id"],
                                              team_id="org-sensor")
        snapshot = self.roadmap.recovery_snapshot("chief")
        pending = [a for a in snapshot["adjudications"] if a["status"] == "pending"]
        self.assertEqual(1, len(pending))
        self.assertEqual("org-control", pending[0]["team_id"])
        self.assertEqual(first["freeze_seq"], pending[0]["freeze_seq"])

    def test_test_fact_is_immutable_and_resolves_bottleneck(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"])
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control")
        batch = self.roadmap.register_test_batch(request_id="t-1", actor_id="chief",
                                                 solution_id=solution["solution_id"],
                                                 lease_id=lease["lease_id"])
        passed = self.roadmap.record_test_result(request_id="t-1r", actor_id="chief",
                                                 batch_id=batch["batch_id"], result="passed")
        self.assertTrue(passed["resolved"])
        with self.assertRaises(ConflictError):
            self.roadmap.record_test_result(request_id="t-2r", actor_id="chief",
                                            batch_id=batch["batch_id"], result="failed")
        detail = self.roadmap.bottleneck_detail("chief", root["bottleneck_id"])
        self.assertTrue(detail["resolved"])

    def test_failed_test_recomputes_only_incomplete_paths(self):
        up = self.make_bottleneck(request_id="b-up", source="上游堵点", estimate=4)
        mid = self.make_bottleneck(request_id="b-mid", source="中游堵点", estimate=3)
        down = self.make_bottleneck(request_id="b-down", source="下游堵点", estimate=2)
        self.roadmap.add_dependency(request_id="d-1", actor_id="chief",
                                    upstream_id=up["bottleneck_id"], downstream_id=mid["bottleneck_id"])
        self.roadmap.add_dependency(request_id="d-2", actor_id="chief",
                                    upstream_id=mid["bottleneck_id"], downstream_id=down["bottleneck_id"])
        solution_up = self.make_solution(up["bottleneck_id"], request_id="s-up")
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-up", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution_up["solution_id"], team_id="org-control")
        batch = self.roadmap.register_test_batch(request_id="t-up", actor_id="chief",
                                                 solution_id=solution_up["solution_id"],
                                                 lease_id=lease["lease_id"])
        self.roadmap.record_test_result(request_id="t-up-r", actor_id="chief",
                                        batch_id=batch["batch_id"], result="passed")
        solution_mid = self.make_solution(mid["bottleneck_id"], request_id="s-mid")
        window2 = self.make_window(request_id="w-2", facility="bench-2")
        lease2 = self.roadmap.acquire_lease(request_id="l-mid", actor_id="chief",
                                            window_id=window2["window_id"],
                                            solution_id=solution_mid["solution_id"], team_id="org-control")
        batch2 = self.roadmap.register_test_batch(request_id="t-mid", actor_id="chief",
                                                  solution_id=solution_mid["solution_id"],
                                                  lease_id=lease2["lease_id"])
        failed = self.roadmap.record_test_result(request_id="t-mid-r", actor_id="chief",
                                                 batch_id=batch2["batch_id"], result="failed")
        self.assertEqual(sorted([mid["bottleneck_id"], down["bottleneck_id"]]), failed["recomputed"])
        self.assertNotIn(up["bottleneck_id"], failed["recomputed"])

    def test_resolved_bottleneck_blocks_recompute_propagation(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"])
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control")
        batch = self.roadmap.register_test_batch(request_id="t-1", actor_id="chief",
                                                 solution_id=solution["solution_id"],
                                                 lease_id=lease["lease_id"])
        self.roadmap.record_test_result(request_id="t-1r", actor_id="chief",
                                        batch_id=batch["batch_id"], result="passed")
        self.roadmap.register_evidence(request_id="e-1", actor_id="chief",
                                       bottleneck_id=root["bottleneck_id"], evidence_type="仿真报告",
                                       confidentiality="open", expires_at="2026-10-06T09:00:00Z")
        self.clock.advance(hours=2)
        swept = self.roadmap.expire_evidence_sweep(request_id="sweep-1", actor_id="chief")
        self.assertEqual([], swept["recomputed"])

    def test_metric_degrade_rules(self):
        root = self.make_bottleneck()
        metric = self.roadmap.register_metric(request_id="m-1", actor_id="chief",
                                              bottleneck_id=root["bottleneck_id"], name="精度",
                                              unit="bit", target_value=24, direction="at_least")
        with self.assertRaises(ValidationError):
            self.roadmap.degrade_metric(request_id="m-1x", actor_id="chief",
                                        metric_id=metric["metric_id"], new_target_value=28)
        degraded = self.roadmap.degrade_metric(request_id="m-1d", actor_id="chief",
                                               metric_id=metric["metric_id"], new_target_value=16)
        self.assertEqual(2, degraded["version"])
        self.assertEqual([root["bottleneck_id"]], degraded["recomputed"])

    def test_alternative_route_activation(self):
        root = self.make_bottleneck()
        first = self.make_solution(root["bottleneck_id"], request_id="s-1")
        second = self.make_solution(root["bottleneck_id"], request_id="s-2", name="替代路线")
        self.assertEqual("active", first["status"])
        self.assertEqual("standby", second["status"])
        activated = self.roadmap.activate_solution(request_id="act-1", actor_id="chief",
                                                   solution_id=second["solution_id"])
        self.assertEqual("active", activated["status"])
        self.assertEqual([root["bottleneck_id"]], activated["recomputed"])
        detail = self.roadmap.bottleneck_detail("chief", root["bottleneck_id"])
        statuses = {s["solution_id"]: s["status"] for s in detail["solutions"]}
        self.assertEqual("replaced", statuses[first["solution_id"]])
        self.assertEqual("active", statuses[second["solution_id"]])

    def test_critical_path_and_team_scope(self):
        first = self.make_bottleneck(request_id="b-1", source="堵点一", estimate=5)
        second = self.make_bottleneck(request_id="b-2", source="堵点二", estimate=3)
        third = self.make_bottleneck(request_id="b-3", source="堵点三", estimate=4)
        other = self.make_bottleneck(request_id="b-4", source="独立堵点", owner="org-sensor", estimate=2)
        self.roadmap.add_dependency(request_id="d-1", actor_id="chief",
                                    upstream_id=first["bottleneck_id"], downstream_id=second["bottleneck_id"])
        self.roadmap.add_dependency(request_id="d-2", actor_id="chief",
                                    upstream_id=second["bottleneck_id"], downstream_id=third["bottleneck_id"])
        chief_view = self.roadmap.critical_path("chief")
        self.assertEqual("global", chief_view["scope"])
        self.assertEqual(12, chief_view["total_days"])
        self.assertEqual([first["bottleneck_id"], second["bottleneck_id"], third["bottleneck_id"]],
                         [node["bottleneck_id"] for node in chief_view["path"]])
        lead_view = self.roadmap.critical_path("lead-sensor")
        self.assertEqual("team", lead_view["scope"])
        self.assertEqual([other["bottleneck_id"]],
                         [node["bottleneck_id"] for node in lead_view["path"]])
        with self.assertRaises(PermissionDenied):
            self.roadmap.critical_path("auditor")

    def test_wait_reasons_cover_evidence_dependency_and_commitment(self):
        up = self.make_bottleneck(request_id="b-1", source="上游")
        down = self.make_bottleneck(request_id="b-2", source="下游")
        self.roadmap.add_dependency(request_id="d-1", actor_id="chief",
                                    upstream_id=up["bottleneck_id"], downstream_id=down["bottleneck_id"])
        self.make_solution(up["bottleneck_id"], request_id="s-1", required=["仿真报告"])
        self.make_solution(down["bottleneck_id"], request_id="s-2")
        self.roadmap.register_commitment(request_id="cm-1", actor_id="lead-control",
                                         bottleneck_id=down["bottleneck_id"], team_id="org-control",
                                         promise_date="2026-10-09T08:00:00Z", note="完成联调")
        reasons = {item["bottleneck_id"]: item["reasons"] for item in self.roadmap.wait_reasons("chief")["items"]}
        up_types = {reason["type"] for reason in reasons[up["bottleneck_id"]]}
        down_types = {reason["type"] for reason in reasons[down["bottleneck_id"]]}
        self.assertIn("missing_evidence", up_types)
        self.assertIn("dependency_open", down_types)
        self.assertIn("commitment_pending", down_types)

    def test_switch_cost_formula(self):
        root = self.make_bottleneck()
        current = self.make_solution(root["bottleneck_id"], request_id="s-1", switch_cost=1.0)
        self.make_solution(root["bottleneck_id"], request_id="s-2", name="备选", switch_cost=2.0)
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=current["solution_id"], team_id="org-control")
        self.roadmap.register_test_batch(request_id="t-1", actor_id="chief",
                                         solution_id=current["solution_id"], lease_id=lease["lease_id"])
        costs = self.roadmap.switch_costs("chief")
        item = next(i for i in costs["items"] if i["bottleneck_id"] == root["bottleneck_id"])
        alternative = item["alternatives"][0]
        self.assertEqual(2.0, alternative["base_cost"])
        self.assertEqual(1, alternative["active_leases"])
        self.assertEqual(1, alternative["pending_batches"])
        self.assertAlmostEqual(3.5, alternative["switch_cost"])

    def test_evidence_disclosure_by_role(self):
        root = self.make_bottleneck()
        for index, level in enumerate(("open", "internal", "confidential")):
            self.roadmap.register_evidence(request_id=f"e-{index}", actor_id="chief",
                                           bottleneck_id=root["bottleneck_id"], evidence_type=f"报告{index}",
                                           confidentiality=level, expires_at="2026-10-08T08:00:00Z")
        chief_items = self.roadmap.disclosable_evidence("chief", root["bottleneck_id"])["items"]
        lead_items = self.roadmap.disclosable_evidence("lead-control", root["bottleneck_id"])["items"]
        self.assertEqual(3, len(chief_items))
        self.assertEqual({"open", "internal"}, {item["confidentiality"] for item in lead_items})
        with self.assertRaises(PermissionDenied):
            self.roadmap.disclosable_evidence("lead-sensor", root["bottleneck_id"])

    def test_restart_recovers_leases_and_pending_adjudications(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "restart.sqlite3")
            database = Database(path)
            clock = MutableClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
            build_environment(database, clock)
            roadmap = RoadmapService(database, clock, confirm_ttl_seconds=600)
            root = roadmap.register_bottleneck(request_id="b-1", actor_id="chief", site_id="s1",
                                               name="堵点", source_name="堵点", owner_team_id="org-control",
                                               estimate_days=1)
            solution = roadmap.register_solution(request_id="s-1", actor_id="chief",
                                                 bottleneck_id=root["bottleneck_id"], name="方案")
            window = roadmap.register_window(request_id="w-1", actor_id="chief", facility_id="bench-1",
                                             site_id="s1", starts_at="2026-10-06T09:00:00Z",
                                             ends_at="2026-10-06T17:00:00Z")
            lease = roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                          window_id=window["window_id"],
                                          solution_id=solution["solution_id"], team_id="org-control")
            roadmap.join_waitlist(request_id="q-1", actor_id="lead-sensor",
                                  window_id=window["window_id"],
                                  solution_id=solution["solution_id"], team_id="org-sensor")
            released = roadmap.release_lease(request_id="r-1", actor_id="chief",
                                             lease_id=lease["lease_id"])
            adjudication_id = released["adjudication"]["adjudication_id"]
            database.close()

            reopened = Database(path)
            roadmap2 = RoadmapService(reopened, clock, confirm_ttl_seconds=600)
            snapshot = roadmap2.recovery_snapshot("chief")
            self.assertEqual([adjudication_id],
                             [a["adjudication_id"] for a in snapshot["adjudications"]])
            confirmed = roadmap2.confirm_adjudication(request_id="c-1", actor_id="lead-sensor",
                                                      adjudication_id=adjudication_id, team_id="org-sensor")
            self.assertEqual("confirmed", confirmed["status"])
            snapshot2 = roadmap2.recovery_snapshot("chief")
            self.assertIn(confirmed["lease_id"], [l["lease_id"] for l in snapshot2["leases"]])
            foundation2 = DomainService(reopened, clock)
            valid, _ = foundation2.verify_audit()
            self.assertTrue(valid)
            reopened.close()

    def test_idempotent_replay_returns_same_response(self):
        first = self.make_bottleneck(request_id="b-1")
        replay = self.make_bottleneck(request_id="b-1")
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["bottleneck_id"], replay["bottleneck_id"])
        with self.assertRaises(ConflictError):
            self.make_bottleneck(request_id="b-1", name="不同内容")

    def test_sweep_expires_lease_and_promotes_waitlist(self):
        root = self.make_bottleneck()
        solution = self.make_solution(root["bottleneck_id"])
        window = self.make_window()
        lease = self.roadmap.acquire_lease(request_id="l-1", actor_id="chief",
                                           window_id=window["window_id"],
                                           solution_id=solution["solution_id"], team_id="org-control",
                                           ttl_seconds=600)
        self.roadmap.join_waitlist(request_id="q-1", actor_id="lead-sensor",
                                   window_id=window["window_id"],
                                   solution_id=solution["solution_id"], team_id="org-sensor")
        self.clock.advance(seconds=601)
        swept = self.roadmap.sweep_expired(request_id="sw-1", actor_id="chief")
        self.assertEqual([lease["lease_id"]], swept["expired_leases"])
        self.assertEqual("org-sensor", swept["promotions"][0]["team_id"])


class RoadmapApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = MutableClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
        self.foundation = build_environment(self.database, self.clock)

    def tearDown(self):
        self.database.close()

    def route(self, method, path, body=None, actor="chief"):
        from science_strategy_foundation.api import route
        return route(self.foundation, method, path, body, {"X-Actor-Id": actor})

    def test_roadmap_routes_end_to_end(self):
        status, payload = self.route("POST", "/roadmap/bottlenecks", {
            "request_id": "b-1", "site_id": "s1", "name": "进口部件替代",
            "source_name": "进口ADC部件替代", "owner_team_id": "org-control", "estimate_days": 10})
        self.assertEqual(201, status)
        self.assertFalse(payload["merged"])
        status, payload = self.route("POST", "/roadmap/bottlenecks", {
            "request_id": "b-2", "site_id": "s1", "name": "传感器前端替代",
            "source_name": "进口 ADC 部件替代", "owner_team_id": "org-sensor", "estimate_days": 8})
        self.assertEqual(201, status)
        self.assertTrue(payload["merged"])
        status, payload = self.route("GET", "/roadmap/bottlenecks")
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))
        self.assertEqual(1, len(payload["items"][0]["aliases"]))
        status, payload = self.route("GET", "/roadmap/critical-path", actor="lead-sensor")
        self.assertEqual(200, status)
        self.assertEqual("team", payload["scope"])
        status, payload = self.route("GET", "/roadmap/recovery")
        self.assertEqual(200, status)
        self.assertIn("leases", payload)
        status, payload = self.route("GET", "/roadmap/wait-reasons")
        self.assertEqual(200, status)
        status, payload = self.route("GET", "/roadmap/switch-costs")
        self.assertEqual(200, status)

    def test_roadmap_route_requires_known_actor(self):
        status, payload = self.route("POST", "/roadmap/bottlenecks", {
            "request_id": "b-1", "site_id": "s1", "name": "堵点",
            "source_name": "堵点", "owner_team_id": "org-control"}, actor="missing")
        self.assertEqual(404, status)

    def test_roadmap_unknown_route_returns_404(self):
        status, payload = self.route("GET", "/roadmap/unknown")
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])

    def test_auditor_cannot_use_roadmap_views(self):
        status, payload = self.route("GET", "/roadmap/critical-path", actor="auditor")
        self.assertEqual(403, status)


class RoadmapAcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        from science_strategy_foundation.roadmap_acceptance import run
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()
