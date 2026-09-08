import unittest
from fixtures.value import VALUE


class FixtureTest(unittest.TestCase):
    def test_fixture_value_is_one(self):
        self.assertEqual(VALUE, 1)
