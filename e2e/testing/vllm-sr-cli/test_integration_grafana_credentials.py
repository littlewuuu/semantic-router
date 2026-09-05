#!/usr/bin/env python3
"""
test_integration_grafana_credentials.py - real-daemon Grafana startup coverage.

The unit suite in `src/vllm-sr/tests/test_grafana_credentials.py` mocks the
container runtime, so it can only assert the file mode and the command the CLI
emits. Whether an unprivileged Grafana container can actually read the mounted
``GF_SECURITY_ADMIN_PASSWORD__FILE`` and finish booting is a property of a real
daemon, and that is what this test measures: one container is started exactly
the way ``container_start_grafana`` starts it, and the test requires it to
become ready and to accept the generated password over the API.

Signed-off-by: vLLM-SR Team
"""

import base64
import os
import stat
import time
import unittest
from urllib import error as urllib_error
from urllib import request as urllib_request

from cli import grafana_credentials as gc
from cli_test_base import (
    HTTP_STATUS_OK,
    CLITestBase,
    stack_scoped_test_container_name,
)

# Keep in sync with `container_start_grafana` in
# src/vllm-sr/cli/container_support_services.py.
GRAFANA_IMAGE = "docker.io/grafana/grafana:11.5.1"

GRAFANA_CONTAINER_SUFFIX = "vllm-sr-cli-test-grafana"
GRAFANA_READY_TIMEOUT = 180
GRAFANA_START_COMMAND_TIMEOUT = 600

integration_only = unittest.skipUnless(
    os.environ.get("RUN_INTEGRATION_TESTS", "").lower() == "true",
    "Integration tests disabled. Set RUN_INTEGRATION_TESTS=true to enable.",
)


class TestGrafanaPasswordFileContainer(CLITestBase):
    """A real Grafana container must boot with the CLI's mounted password file."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.GRAFANA_CONTAINER_NAME = stack_scoped_test_container_name(
            cls.runtime_stack.stack_name, GRAFANA_CONTAINER_SUFFIX
        )

    def tearDown(self):
        self._run_subprocess(
            [self.container_runtime, "rm", "-f", self.GRAFANA_CONTAINER_NAME],
            timeout=30,
        )
        super().tearDown()

    @integration_only
    def test_grafana_boots_ready_with_the_mounted_password_file(self):
        """Start one real Grafana container against the CLI's secret file.

        Grafana drops to an unprivileged uid before reading
        ``GF_SECURITY_ADMIN_PASSWORD__FILE``, so a bind-mounted owner-only file
        makes the container exit instead of becoming ready. The file the CLI
        materializes must therefore carry the container-readable mode while its
        enclosing directory stays owner-only, and this test proves a container
        started exactly like ``container_start_grafana`` boots, passes its
        readiness check, and accepts the generated password.
        """
        self.print_test_header(
            "grafana password file container startup",
            "a real Grafana container becomes ready from the mounted secret file",
        )

        saved_override = os.environ.pop(gc.GRAFANA_ADMIN_PASSWORD_ENV, None)
        try:
            password_file = gc.ensure_grafana_admin_password_file(self.test_dir)
            password = gc.resolve_grafana_admin_password(self.test_dir)
        finally:
            if saved_override is not None:
                os.environ[gc.GRAFANA_ADMIN_PASSWORD_ENV] = saved_override

        self.assertEqual(
            stat.S_IMODE(password_file.stat().st_mode),
            0o644,
            "the mounted secret must be readable by the unprivileged Grafana uid",
        )
        self.assertEqual(
            stat.S_IMODE(password_file.parent.stat().st_mode),
            0o700,
            "the state directory holding the secret must stay owner-only",
        )

        result = self._run_subprocess(
            [
                self.container_runtime,
                "run",
                "-d",
                "--name",
                self.GRAFANA_CONTAINER_NAME,
                "-e",
                f"{gc.GRAFANA_ADMIN_PASSWORD_FILE_ENV}="
                f"{gc.CONTAINER_GRAFANA_PASSWORD_PATH}",
                "-v",
                (f"{password_file}:{gc.CONTAINER_GRAFANA_PASSWORD_PATH}:ro,z"),
                "-p",
                "3000",
                GRAFANA_IMAGE,
            ],
            timeout=GRAFANA_START_COMMAND_TIMEOUT,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"the Grafana container failed to start: {result.stderr}",
        )
        try:
            self.assertTrue(
                self.wait_for_container_running(
                    timeout=120,
                    container_name=self.GRAFANA_CONTAINER_NAME,
                ),
                "the Grafana container exited instead of becoming ready; the "
                "bind-mounted password file may be unreadable by the "
                "unprivileged Grafana uid",
            )
            host_port = self._published_host_port()
            self.assertTrue(
                self._wait_until_grafana_ready(host_port),
                "the Grafana container never became ready; inspect the "
                "container logs for a password-file read failure",
            )

            # The generated value from the mounted file must be the active
            # admin credential: a wrong password is rejected, the file value
            # is not. The readiness wait above would already catch a container
            # that cannot read the file at all; this catches one that boots
            # with a credential other than the value the CLI generated.
            self.assertEqual(
                self._grafana_api_status(
                    "/api/org", host_port, "definitely-not-the-password"
                ),
                401,
                "an unknown admin password was not rejected",
            )
            self.assertEqual(
                self._grafana_api_status("/api/org", host_port, password),
                200,
                "the generated admin password from the mounted file was "
                "rejected by a ready Grafana",
            )
        finally:
            self._run_subprocess(
                [self.container_runtime, "rm", "-f", self.GRAFANA_CONTAINER_NAME],
                timeout=30,
            )
        self.print_test_result(
            True,
            "a real Grafana container read the mounted secret and became ready",
        )

    def _published_host_port(self) -> str:
        """Resolve the host port Docker assigned to the container's 3000."""
        result = self._run_subprocess(
            [
                self.container_runtime,
                "port",
                self.GRAFANA_CONTAINER_NAME,
                "3000",
            ],
            timeout=10,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"could not resolve the published Grafana port: {result.stderr}",
        )
        first_binding = result.stdout.strip().splitlines()[0]
        return first_binding.rsplit(":", 1)[-1]

    def _wait_until_grafana_ready(self, host_port: str) -> bool:
        """Poll the unauthenticated health endpoint until Grafana answers."""
        deadline = time.time() + GRAFANA_READY_TIMEOUT
        while time.time() < deadline:
            if (
                self._grafana_api_status("/api/health", host_port, password=None)
                == HTTP_STATUS_OK
            ):
                return True
            time.sleep(2)
        return False

    def _grafana_api_status(
        self, api_path: str, host_port: str, password: str | None
    ) -> int | None:
        """Return the HTTP status of *api_path*, or ``None`` on no response.

        ``/api/health`` is anonymous and gates the readiness wait; ``/api/org``
        requires authentication and gates the credential check. Both calls
        share one request path so a read of the wrong endpoint cannot be
        mistaken for a read of the right one.
        """
        url = f"http://127.0.0.1:{host_port}{api_path}"
        headers = {}
        if password is not None:
            credentials = base64.b64encode(
                f"{gc.grafana_admin_username()}:{password}".encode()
            ).decode("ascii")
            headers["Authorization"] = f"Basic {credentials}"
        request = urllib_request.Request(url, headers=headers)
        try:
            with urllib_request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib_error.HTTPError as error:
            return error.code
        except Exception:
            return None
