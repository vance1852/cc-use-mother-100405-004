import unittest
from datetime import datetime, timezone

from science_strategy_foundation.api import route
from science_strategy_foundation.clock import FixedClock
from science_strategy_foundation.roadmap import RoadmapService
from science_strategy_foundation.storage import Database


class RoadmapApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = RoadmapService(
            self.database, FixedClock(datetime(2026, 10, 6, tzinfo=timezone.utc)))
        self.service.register_organization(request_id="o1", actor_id="bootstrap",
                                           organization_id="org-1", name="总师办")
        self.service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="admin1",
                                    display_name="管理员", role="admin", organization_id="org-1")
        self.service.register_actor(request_id="c1", actor_id="admin1", new_actor_id="chief1",
                                    display_name="总师", role="chief", organization_id="org-1")
        self.service.register_actor(request_id="l1", actor_id="admin1", new_actor_id="lead1",
                                    display_name="负责人", role="lead", organization_id="org-1")
        self.service.register_site(request_id="s1", actor_id="admin1", site_id="site1",
                                   organization_id="org-1", name="节点", timezone_name="Asia/Shanghai")

    def tearDown(self):
        self.database.close()

    def test_register_bottleneck_via_route(self):
        body = {"request_id": "rb-1", "site_id": "site1", "name": "进口ADC替代",
                "origin_key": "ADC-X100", "security_level": "internal",
                "metric": {"name": "精度", "unit": "bit", "direction": "gte",
                           "baseline": 1, "target": 5},
                "estimate_days": 10}
        status, payload = route(self.service, "POST", "/roadmap/bottlenecks", body,
                                {"X-Actor-Id": "lead1"})
        self.assertEqual(201, status)
        self.assertEqual("bottleneck", payload["resource_type"])
        replay, _ = route(self.service, "POST", "/roadmap/bottlenecks", body,
                          {"X-Actor-Id": "lead1"})
        self.assertEqual(200, replay)
        status, roadmap = route(self.service, "GET", "/roadmap/roadmap?site_id=site1", None,
                                {"X-Actor-Id": "chief1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(roadmap["bottlenecks"]))
        self.assertIn("critical_path", roadmap)

    def test_critical_path_requires_privileged_role(self):
        status, payload = route(self.service, "GET", "/roadmap/critical-path?site_id=site1",
                                None, {"X-Actor-Id": "lead1"})
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])
        status, _ = route(self.service, "GET", "/roadmap/critical-path?site_id=site1",
                          None, {"X-Actor-Id": "chief1"})
        self.assertEqual(200, status)

    def test_missing_actor_returns_404(self):
        status, payload = route(self.service, "GET", "/roadmap/roadmap?site_id=site1", None)
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"])

    def test_missing_query_param_returns_400(self):
        status, payload = route(self.service, "GET", "/roadmap/waiting-reasons", None,
                                {"X-Actor-Id": "chief1"})
        self.assertEqual(400, status)
        self.assertEqual("validation_error", payload["error"])

    def test_unknown_roadmap_route_returns_404(self):
        status, payload = route(self.service, "GET", "/roadmap/unknown", None,
                                {"X-Actor-Id": "chief1"})
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])


if __name__ == "__main__":
    unittest.main()
