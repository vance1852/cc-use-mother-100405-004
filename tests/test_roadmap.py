import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from science_strategy_foundation.clock import MutableClock
from science_strategy_foundation.errors import ConflictError, PermissionDenied, ValidationError
from science_strategy_foundation.roadmap import RoadmapService, normalize_key
from science_strategy_foundation.storage import Database

T0 = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)


def at(moment):
    return moment.isoformat()


class RoadmapTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = MutableClock(T0)
        self.service = RoadmapService(self.database, self.clock)
        self.service.register_organization(request_id="o1", actor_id="bootstrap",
                                           organization_id="org-1", name="总师办")
        self.service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="admin1",
                                    display_name="管理员", role="admin", organization_id="org-1")
        self.service.register_organization(request_id="o2", actor_id="admin1",
                                           organization_id="org-2", name="传感器团队")
        self.service.register_actor(request_id="c1", actor_id="admin1", new_actor_id="chief1",
                                    display_name="总师", role="chief", organization_id="org-1")
        self.service.register_actor(request_id="l1", actor_id="admin1", new_actor_id="lead1",
                                    display_name="负责人一", role="lead", organization_id="org-1")
        self.service.register_actor(request_id="l2", actor_id="admin1", new_actor_id="lead2",
                                    display_name="负责人二", role="lead", organization_id="org-2")
        self.service.register_site(request_id="s1", actor_id="admin1", site_id="site1",
                                   organization_id="org-1", name="联合攻关节点",
                                   timezone_name="Asia/Shanghai")

    def tearDown(self):
        self.database.close()

    def bottleneck(self, request_id, actor="lead1", name="堵点", origin="ADC-X100",
                   target=10.0, days=5, direction="gte"):
        receipt = self.service.register_bottleneck(
            request_id=request_id, actor_id=actor, site_id="site1", name=name,
            origin_key=origin, security_level="internal",
            metric={"name": "精度", "unit": "bit", "direction": direction,
                    "baseline": 1.0, "target": target},
            estimate_days=days)
        return receipt.resource_id

    def solution(self, request_id, bottleneck_id, actor="lead1", required=("bench_report",),
                 switch_cost=1.0, activate=True):
        receipt = self.service.register_solution(
            request_id=request_id + "-s", actor_id=actor, bottleneck_id=bottleneck_id,
            name="方案" + request_id, required_evidence=list(required), switch_cost=switch_cost)
        solution_id = receipt.resource_id
        if activate:
            self.service.activate_solution(request_id=request_id + "-a", actor_id=actor,
                                           solution_id=solution_id)
        return solution_id

    def evidence(self, request_id, solution_id, actor="lead1", kind="bench_report",
                 level="internal", start=None, end=None):
        start = start or at(T0 - timedelta(days=1))
        end = end or at(T0 + timedelta(days=10))
        return self.service.register_evidence(
            request_id=request_id, actor_id=actor, solution_id=solution_id, kind=kind,
            security_level=level, detail={"ref": request_id},
            valid_from=start, valid_until=end).resource_id

    def window(self, request_id="win", days=7, freeze_days=2):
        facility = self.service.register_facility(
            request_id=request_id + "-f", actor_id="admin1", site_id="site1",
            name="公共试验台").resource_id
        return self.service.register_window(
            request_id=request_id + "-w", actor_id="admin1", facility_id=facility,
            starts_at=at(T0), ends_at=at(T0 + timedelta(days=days)),
            freeze_at=at(T0 + timedelta(days=freeze_days))).resource_id

    def ready_solution(self, request_id, actor="lead1", origin=None, switch_cost=1.0):
        bottleneck_id = self.bottleneck(request_id + "-b", actor=actor,
                                        origin=origin or ("SRC-" + request_id))
        solution_id = self.solution(request_id, bottleneck_id, actor=actor,
                                    switch_cost=switch_cost)
        self.evidence(request_id + "-e", solution_id, actor=actor)
        return bottleneck_id, solution_id

    def test_normalize_key_hides_disguise(self):
        self.assertEqual(normalize_key("ADC-X100 进口部件"), normalize_key("adc-x100进口部件"))
        self.assertEqual(normalize_key("ＡＢＣ－１"), normalize_key("abc-1"))

    def test_cycle_dependency_rejected(self):
        first = self.bottleneck("bn-a", name="甲")
        second = self.bottleneck("bn-b", name="乙")
        third = self.bottleneck("bn-c", name="丙")
        self.service.add_dependency(request_id="d1", actor_id="lead1",
                                    bottleneck_id=first, depends_on=second)
        self.service.add_dependency(request_id="d2", actor_id="lead1",
                                    bottleneck_id=second, depends_on=third)
        with self.assertRaises(ConflictError):
            self.service.add_dependency(request_id="d3", actor_id="lead1",
                                        bottleneck_id=third, depends_on=first)
        with self.assertRaises(ValidationError):
            self.service.add_dependency(request_id="d4", actor_id="lead1",
                                        bottleneck_id=first, depends_on=first)

    def test_same_origin_detected_and_resolved(self):
        first = self.bottleneck("bn-x", name="进口ADC替代", origin="ADC-X100 进口部件")
        self.clock.advance(seconds=1)
        second = self.bottleneck("bn-y", actor="lead2", name="adc芯片国产化",
                                 origin="adc-x100进口部件")
        groups = self.service.same_origin_groups("chief1", "site1")
        match = [group for group in groups
                 if set(group["bottleneck_ids"]) == {first, second}]
        self.assertEqual(1, len(match))
        self.assertEqual("pending", match[0]["adjudication_status"])
        pending = self.service.list_adjudications("chief1", status="pending")
        self.assertEqual(1, len(pending))
        receipt = self.service.resolve_adjudication(
            request_id="res-1", actor_id="chief1",
            adjudication_id=pending[0]["adjudication_id"],
            decision="approved", rationale="确认为同源堵点")
        self.assertEqual(first, receipt.response["canonical_id"])
        with self.assertRaises(ConflictError):
            self.service.resolve_adjudication(
                request_id="res-2", actor_id="chief1",
                adjudication_id=pending[0]["adjudication_id"], decision="rejected")
        with self.assertRaises(PermissionDenied):
            self.service.resolve_adjudication(
                request_id="res-3", actor_id="lead1",
                adjudication_id=pending[0]["adjudication_id"], decision="approved")

    def test_entry_evidence_gates_lease(self):
        bottleneck_id = self.bottleneck("bn-g")
        solution_id = self.solution("sg", bottleneck_id)
        window_id = self.window()
        with self.assertRaises(PermissionDenied):
            self.service.confirm_resource(request_id="cf-1", actor_id="lead1",
                                          window_id=window_id, solution_id=solution_id)
        self.evidence("e-expired", solution_id,
                      start=at(T0 - timedelta(days=3)), end=at(T0 - timedelta(days=1)))
        with self.assertRaises(PermissionDenied):
            self.service.confirm_resource(request_id="cf-2", actor_id="lead1",
                                          window_id=window_id, solution_id=solution_id)
        self.evidence("e-valid", solution_id)
        receipt = self.service.confirm_resource(request_id="cf-3", actor_id="lead1",
                                                window_id=window_id, solution_id=solution_id)
        self.assertEqual("lease", receipt.resource_type)

    def test_concurrent_confirm_single_winner(self):
        _, solution_one = self.ready_solution("one", actor="lead1")
        _, solution_two = self.ready_solution("two", actor="lead2")
        window_id = self.window()
        first = self.service.confirm_resource(request_id="cf-a", actor_id="lead1",
                                              window_id=window_id, solution_id=solution_one)
        second = self.service.confirm_resource(request_id="cf-b", actor_id="lead2",
                                               window_id=window_id, solution_id=solution_two)
        self.assertEqual("lease", first.resource_type)
        self.assertEqual("waitlist", second.resource_type)
        active = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM leases WHERE state='active'").fetchone()["count"]
        self.assertEqual(1, active)
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "INSERT INTO leases(lease_id,window_id,solution_id,team_id,state,granted_at,"
                "expires_at) VALUES(?,?,?,?,'active',?,?)",
                (uuid.uuid4().hex, window_id, solution_two, "org-2", at(T0),
                 at(T0 + timedelta(days=7))))

    def test_waitlist_freeze_rules(self):
        _, holder = self.ready_solution("holder", actor="lead1")
        _, early_high = self.ready_solution("early-high", actor="lead2")
        _, early_low = self.ready_solution("early-low", actor="lead1")
        _, late_high = self.ready_solution("late-high", actor="lead2")
        window_id = self.window()
        lease = self.service.confirm_resource(request_id="cf-h", actor_id="lead1",
                                              window_id=window_id, solution_id=holder)
        self.service.confirm_resource(request_id="cf-eh", actor_id="lead2", priority=9,
                                      window_id=window_id, solution_id=early_high)
        self.service.confirm_resource(request_id="cf-el", actor_id="lead1", priority=1,
                                      window_id=window_id, solution_id=early_low)
        self.clock.advance(days=3)
        late = self.service.confirm_resource(request_id="cf-lh", actor_id="lead2", priority=99,
                                             window_id=window_id, solution_id=late_high)
        self.assertEqual(3, late.response["position"])
        order = []
        current = lease.resource_id
        for index in range(3):
            released = self.service.release_lease(request_id=f"rel-{index}", actor_id="chief1",
                                                  lease_id=current)
            current = released.response["promoted_lease_id"]
            row = self.database.connection.execute(
                "SELECT solution_id FROM leases WHERE lease_id=?", (current,)).fetchone()
            order.append(row["solution_id"])
        self.assertEqual([early_high, early_low, late_high], order)

    def test_release_skips_candidate_with_expired_evidence(self):
        _, holder = self.ready_solution("hd", actor="lead1")
        bn_stale = self.bottleneck("bn-stale", actor="lead2", origin="SRC-stale")
        stale = self.solution("stale", bn_stale, actor="lead2")
        self.evidence("e-stale", stale, actor="lead2", end=at(T0 + timedelta(days=4)))
        _, fresh = self.ready_solution("fresh", actor="lead1")
        window_id = self.window()
        lease = self.service.confirm_resource(request_id="cf-hd", actor_id="lead1",
                                              window_id=window_id, solution_id=holder)
        self.service.confirm_resource(request_id="cf-st", actor_id="lead2", priority=9,
                                      window_id=window_id, solution_id=stale)
        self.service.confirm_resource(request_id="cf-fr", actor_id="lead1", priority=1,
                                      window_id=window_id, solution_id=fresh)
        self.clock.advance(days=5)
        released = self.service.release_lease(request_id="rel-hd", actor_id="chief1",
                                              lease_id=lease.resource_id)
        promoted = released.response["promoted_lease_id"]
        row = self.database.connection.execute(
            "SELECT solution_id FROM leases WHERE lease_id=?", (promoted,)).fetchone()
        self.assertEqual(fresh, row["solution_id"])
        skipped = self.database.connection.execute(
            "SELECT status FROM waitlist WHERE solution_id=?", (stale,)).fetchone()
        self.assertEqual("expired", skipped["status"])

    def test_failure_recomputes_only_unfinished(self):
        bn_done, solution_done = self.ready_solution("done", actor="lead1")
        bn_open = self.bottleneck("bn-open", actor="lead2", origin="SRC-open")
        self.service.add_dependency(request_id="dep-open", actor_id="lead2",
                                    bottleneck_id=bn_open, depends_on=bn_done)
        solution_open = self.solution("open", bn_open, actor="lead2")
        self.evidence("e-open", solution_open, actor="lead2")
        window_id = self.window()
        lease_done = self.service.confirm_resource(request_id="cf-done", actor_id="lead1",
                                                   window_id=window_id, solution_id=solution_done)
        self.service.record_test_batch(request_id="tb-done", actor_id="lead1",
                                       solution_id=solution_done, lease_id=lease_done.resource_id,
                                       result="passed", metrics={"precision": 11.0})
        self.service.release_lease(request_id="rel-done", actor_id="chief1",
                                   lease_id=lease_done.resource_id)
        lease_open = self.service.confirm_resource(request_id="cf-open", actor_id="lead2",
                                                   window_id=window_id, solution_id=solution_open)
        self.service.record_test_batch(request_id="tb-open", actor_id="lead2",
                                       solution_id=solution_open, lease_id=lease_open.resource_id,
                                       result="failed", metrics={"precision": 7.5})
        rows = {row["bottleneck_id"]: row["status"] for row in
                self.database.connection.execute("SELECT bottleneck_id, status FROM bottlenecks")}
        self.assertEqual("verified", rows[bn_done])
        self.assertEqual("pending", rows[bn_open])
        batches = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM test_batches").fetchone()["count"]
        self.assertEqual(2, batches)
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute("DELETE FROM test_batches")
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "UPDATE test_batches SET result='passed' WHERE result='failed'")
        self.clock.advance(days=30)
        waiting = self.service.waiting_reasons("chief1", bn_done)
        self.assertEqual("verified", waiting["status"])
        self.assertEqual([], waiting["reasons"])

    def test_metric_downgrade_records_revision(self):
        bottleneck_id = self.bottleneck("bn-m", target=10.0)
        receipt = self.service.downgrade_metric(request_id="dg-1", actor_id="chief1",
                                                bottleneck_id=bottleneck_id, new_target=8.0,
                                                reason="样机实测不足")
        self.assertEqual(2, receipt.response["metric_revision"])
        view = self.service.roadmap("chief1", "site1")
        metric = view["bottlenecks"][0]["metric"]
        self.assertEqual(8.0, metric["target"])
        self.assertEqual(2, metric["revision"])
        with self.assertRaises(ValidationError):
            self.service.downgrade_metric(request_id="dg-2", actor_id="chief1",
                                          bottleneck_id=bottleneck_id, new_target=9.0,
                                          reason="反向调整")
        with self.assertRaises(PermissionDenied):
            self.service.downgrade_metric(request_id="dg-3", actor_id="lead1",
                                          bottleneck_id=bottleneck_id, new_target=7.0,
                                          reason="越权")

    def test_switch_cost_and_alternative_activation(self):
        bottleneck_id = self.bottleneck("bn-sw")
        first = self.solution("sw-a", bottleneck_id, switch_cost=2.0)
        second = self.solution("sw-b", bottleneck_id, switch_cost=5.0, activate=False)
        self.evidence("e-sw", first)
        window_id = self.window()
        lease = self.service.confirm_resource(request_id="cf-sw", actor_id="lead1",
                                              window_id=window_id, solution_id=first)
        self.service.record_test_batch(request_id="tb-sw", actor_id="lead1",
                                       solution_id=first, lease_id=lease.resource_id,
                                       result="failed", metrics={"precision": 6.0})
        cost = self.service.switch_cost("chief1", second)
        self.assertEqual(5.0, cost["base_cost"])
        self.assertEqual(1, cost["sunk_batches"])
        self.assertEqual(["bench_report"], cost["evidence_gap"])
        self.assertEqual(7.0, cost["total_cost"])
        receipt = self.service.activate_solution(request_id="act-b", actor_id="lead1",
                                                 solution_id=second)
        self.assertEqual(7.0, receipt.response["switch_cost"]["total_cost"])
        statuses = {row["solution_id"]: row["status"] for row in
                    self.database.connection.execute("SELECT solution_id, status FROM solutions")}
        self.assertEqual("suspended", statuses[first])
        self.assertEqual("active", statuses[second])

    def test_restart_recovers_leases_and_adjudications(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite3"
            clock = MutableClock(T0)
            database = Database(path)
            service = RoadmapService(database, clock)
            service.register_organization(request_id="o1", actor_id="bootstrap",
                                          organization_id="org-1", name="总师办")
            service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="admin1",
                                   display_name="管理员", role="admin", organization_id="org-1")
            service.register_actor(request_id="c1", actor_id="admin1", new_actor_id="chief1",
                                   display_name="总师", role="chief", organization_id="org-1")
            service.register_actor(request_id="l1", actor_id="admin1", new_actor_id="lead1",
                                   display_name="负责人", role="lead", organization_id="org-1")
            service.register_site(request_id="s1", actor_id="admin1", site_id="site1",
                                  organization_id="org-1", name="节点", timezone_name="Asia/Shanghai")
            first = service.register_bottleneck(
                request_id="b1", actor_id="lead1", site_id="site1", name="甲", origin_key="SRC-9",
                security_level="internal",
                metric={"name": "精度", "unit": "bit", "direction": "gte",
                        "baseline": 1.0, "target": 5.0}, estimate_days=3).resource_id
            service.register_bottleneck(
                request_id="b2", actor_id="lead1", site_id="site1", name="乙", origin_key="src-9 ",
                security_level="internal",
                metric={"name": "精度", "unit": "bit", "direction": "gte",
                        "baseline": 1.0, "target": 5.0}, estimate_days=3)
            solution = service.register_solution(
                request_id="so1", actor_id="lead1", bottleneck_id=first, name="方案",
                required_evidence=["bench_report"], switch_cost=1).resource_id
            service.activate_solution(request_id="act1", actor_id="lead1", solution_id=solution)
            service.register_evidence(request_id="e1", actor_id="lead1", solution_id=solution,
                                      kind="bench_report", security_level="internal",
                                      detail={"r": 1}, valid_from=at(T0 - timedelta(days=1)),
                                      valid_until=at(T0 + timedelta(days=30)))
            facility = service.register_facility(request_id="f1", actor_id="admin1",
                                                 site_id="site1", name="试验台").resource_id
            window_id = service.register_window(
                request_id="w1", actor_id="admin1", facility_id=facility, starts_at=at(T0),
                ends_at=at(T0 + timedelta(days=7)), freeze_at=at(T0 + timedelta(days=2))).resource_id
            lease = service.confirm_resource(request_id="cf1", actor_id="lead1",
                                             window_id=window_id, solution_id=solution)
            database.close()

            clock.set(T0 + timedelta(days=1))
            reopened = RoadmapService(Database(path), clock)
            leases = reopened.list_leases("chief1", window_id)["leases"]
            self.assertEqual("active", leases[0]["state"])
            self.assertEqual(1, len(reopened.list_adjudications("chief1", status="pending")))
            reopened.database.close()

            clock.set(T0 + timedelta(days=8))
            expired = RoadmapService(Database(path), clock)
            leases = expired.list_leases("chief1", window_id)["leases"]
            self.assertEqual("expired", leases[0]["state"])
            self.assertEqual(1, len(expired.list_adjudications("chief1", status="pending")))
            valid, _ = expired.verify_audit()
            self.assertTrue(valid)
            expired.database.close()
            self.assertEqual(lease.resource_type, "lease")

    def test_role_filtered_views_and_redaction(self):
        bn_one, solution_one = self.ready_solution("v-one", actor="lead1")
        bn_two = self.bottleneck("v-two-b", actor="lead2", origin="SRC-v-two")
        solution_two = self.solution("v-two", bn_two, actor="lead2")
        self.evidence("e-secret", solution_two, actor="chief1", level="secret")
        with self.assertRaises(PermissionDenied):
            self.service.critical_path("lead1", "site1")
        with self.assertRaises(PermissionDenied):
            self.service.waiting_reasons("lead1", bn_two)
        with self.assertRaises(PermissionDenied):
            self.service.list_evidence("lead1", solution_two)
        chief_view = self.service.list_evidence("chief1", solution_two)
        self.assertTrue(chief_view[0]["disclosed"])
        self.assertIsNotNone(chief_view[0]["detail"])
        lead_view = self.service.list_evidence("lead2", solution_two)
        self.assertFalse(lead_view[0]["disclosed"])
        self.assertIsNone(lead_view[0]["detail"])
        roadmap = self.service.roadmap("lead1", "site1")
        self.assertEqual([bn_one], [item["bottleneck_id"] for item in roadmap["bottlenecks"]])
        self.assertNotIn("critical_path", roadmap)
        chief_roadmap = self.service.roadmap("chief1", "site1")
        self.assertIn("critical_path", chief_roadmap)
        self.assertEqual(2, len(chief_roadmap["bottlenecks"]))

    def test_confirm_replay_is_idempotent(self):
        _, solution_id = self.ready_solution("idem", actor="lead1")
        window_id = self.window()
        first = self.service.confirm_resource(request_id="cf-i", actor_id="lead1",
                                              window_id=window_id, solution_id=solution_id)
        replay = self.service.confirm_resource(request_id="cf-i", actor_id="lead1",
                                               window_id=window_id, solution_id=solution_id)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.resource_id, replay.resource_id)
        with self.assertRaises(ConflictError):
            self.service.confirm_resource(request_id="cf-i", actor_id="lead1",
                                          window_id=window_id, solution_id=solution_id,
                                          priority=9)


if __name__ == "__main__":
    unittest.main()
