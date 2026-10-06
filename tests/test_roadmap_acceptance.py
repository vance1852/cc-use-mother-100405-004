import unittest

from science_strategy_foundation.roadmap_acceptance import run


class RoadmapAcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["checks"]["audit_valid"])
        self.assertTrue(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()
