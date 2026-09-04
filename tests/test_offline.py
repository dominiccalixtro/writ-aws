"""sec. 5.5: every test SHALL pass with no network access and no AWS
credentials present in the environment. This module enforces both halves
of that requirement for the suite itself.
"""

from __future__ import annotations

import os
import socket
import unittest


class NoNetworkTests(unittest.TestCase):
    def test_socket_construction_is_blocked_during_this_test(self) -> None:
        original = socket.socket

        def _blocked(*_args, **_kwargs):
            raise AssertionError("network access attempted during offline test run")

        socket.socket = _blocked  # type: ignore[assignment]
        try:
            with self.assertRaises(AssertionError):
                socket.socket()
        finally:
            socket.socket = original

    def test_no_aws_credentials_in_environment(self) -> None:
        forbidden = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
        present = [name for name in forbidden if os.environ.get(name)]
        self.assertEqual(
            present,
            [],
            f"AWS credentials present in test environment: {present} (sec. 5.5)",
        )


if __name__ == "__main__":
    unittest.main()
