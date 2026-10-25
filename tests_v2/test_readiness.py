import unittest
from p0core.model import ContractError
from p0core.readiness import wait, ReadinessError


class Clock:
    def __init__(self):
        self.now = 0
    def time(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class ReadinessTests(unittest.TestCase):
    def test_deadline_bounds_retry_sleep_and_probe(self):
        clock = Clock()
        observations = []
        def check(probe, timeout):
            observations.append(timeout)
            clock.now += timeout
            return False
        with self.assertRaises(ReadinessError):
            wait([{'kind': 'tcp', 'host': '127.0.0.1', 'port': 1234}], budget=2,
                 clock=clock.time, sleep=clock.sleep, check=check)
        self.assertLessEqual(clock.now, 2)
        self.assertTrue(all(0 < duration <= 1 for duration in observations))

    def test_dns_refused_instead_of_unbounded_lookup(self):
        with self.assertRaises(ContractError):
            wait([{'kind': 'tcp', 'host': 'unbounded.example', 'port': 1234}])

    def test_cancel_preserves_service_lifetime(self):
        with self.assertRaises(ReadinessError):
            wait([{'kind': 'tcp', 'host': '127.0.0.1', 'port': 1234}], cancelled=lambda: True,
                 check=lambda *_: self.fail('cancelled observation must not run'))

    def test_late_success_does_not_pass(self):
        clock = Clock()
        def late(*_):
            clock.now = 5
            return True
        with self.assertRaises(ReadinessError):
            wait([{'kind': 'tcp', 'host': '127.0.0.1', 'port': 1234}], budget=1,
                 clock=clock.time, sleep=clock.sleep, check=late)

    def test_multiple_probe_shared_budget(self):
        clock = Clock()
        def check(*_):
            clock.now += 0.3
            return True
        result = wait([{'kind': 'tcp', 'host': '127.0.0.1', 'port': 1234}] * 2,
                      budget=1, clock=clock.time, sleep=clock.sleep, check=check)
        self.assertEqual(result['attempts'], 2)
        self.assertFalse(result['installationCertified'])


if __name__ == '__main__':
    unittest.main()
