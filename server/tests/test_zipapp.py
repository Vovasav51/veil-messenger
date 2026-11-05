"""Build and run the packaged zipapp artifact against a real socket."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests.support as support  # noqa: F401  (sets sys.path for the server dir)
import build_zipapp
from tests.support import free_port, make_bundle, new_uuid, wait_for_health


class ZipappTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="veil-zipapp-test-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)

    def test_default_output_is_the_repo_root_dist(self) -> None:
        self.assertEqual(
            Path(build_zipapp.DEFAULT_OUTPUT),
            Path(build_zipapp.SERVER_DIR).parent / "dist" / "veil-relay.pyz",
        )
        self.assertEqual(Path(build_zipapp.DEFAULT_OUTPUT).parent.name, "dist")

    def test_built_zipapp_runs_and_serves_the_api(self) -> None:
        target = Path(self.tmpdir) / "veil-relay.pyz"
        built = build_zipapp.build(target)
        self.assertTrue(built.exists())
        self.assertTrue(os.access(built, os.X_OK))
        self.assertGreater(built.stat().st_size, 10_000)

        port = free_port()
        db_path = Path(self.tmpdir) / "private" / "relay.sqlite3"
        process = subprocess.Popen(
            [
                sys.executable,
                str(built),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--db",
                str(db_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def stop() -> None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()
                    process.wait(timeout=5)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

        self.addCleanup(stop)

        health = wait_for_health(port)
        self.assertEqual(health, {"status": "ok", "version": "0.1.0"})

        # Full registration + message round-trip through the packaged artifact.
        bundle = make_bundle(label="zip")
        body = json.dumps(
            {
                "uid": new_uuid(),
                "handle": "zip_user",
                "device_id": 1,
                "bundle": bundle,
            }
        ).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request(
                "POST",
                "/v1/register",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 201, payload)
            token = payload["token"]
        finally:
            connection.close()

        self.assertTrue(os.path.exists(db_path))
        self.assertEqual(os.stat(db_path).st_mode & 0o777, 0o600)

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request(
                "GET", "/v1/messages", headers={"Authorization": "Bearer " + token}
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"messages": []})
        finally:
            connection.close()

    def test_zipapp_check_mode(self) -> None:
        target = Path(self.tmpdir) / "veil-relay.pyz"
        build_zipapp.build(target)
        db_path = Path(self.tmpdir) / "check" / "relay.sqlite3"
        result = subprocess.run(
            [sys.executable, str(target), "--db", str(db_path), "--check"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("configuration ok", result.stdout)
        self.assertTrue(db_path.exists())


if __name__ == "__main__":
    unittest.main()
