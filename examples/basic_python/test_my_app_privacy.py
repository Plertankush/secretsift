"""Drill SDK example with plain unittest (pytest runs it too).

Run from the repository root:
    PYTHONPATH=src python3 -m unittest discover -s examples/basic_python -v
"""

from __future__ import annotations

import unittest

import my_app

from secretsift import Drill


class SignupPrivacyTest(unittest.TestCase):
    def test_fixed_signup_is_clean(self) -> None:
        with Drill(seed=1) as drill:
            email = drill.secret("user_email", "synthetic_email")
            password = drill.secret("user_password", "synthetic_password")
            my_app.fixed_signup(email, password)
        drill.assert_clean()

    def test_leaky_signup_is_caught(self) -> None:
        with Drill(seed=1) as drill:
            email = drill.secret("user_email", "synthetic_email")
            password = drill.secret("user_password", "synthetic_password")
            my_app.leaky_signup(email, password)
        with self.assertRaises(AssertionError) as caught:
            drill.assert_clean()
        message = str(caught.exception)
        self.assertNotIn(password, message)  # failure text is redacted
        self.assertNotIn(email, message)
        destinations = {f.destination.value for f in drill.findings}
        self.assertEqual(destinations, {"application_logs"})

    def test_allow_rule_turns_a_leak_into_an_accepted_flow(self) -> None:
        with Drill(seed=1) as drill:
            email = drill.secret("user_email", "synthetic_email")
            password = drill.secret("user_password", "synthetic_password")
            drill.allow("user_email", "application_logs")
            drill.warn("user_password", "application_logs")
            my_app.leaky_signup(email, password)
        self.assertEqual([f.action.value for f in drill.findings], ["warn"])
        drill.assert_clean(allow_warn=True)


if __name__ == "__main__":
    unittest.main()
