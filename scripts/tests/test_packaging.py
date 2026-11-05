import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("package_source", Path(__file__).resolve().parents[1] / "package-source.py")
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class PackagingTests(unittest.TestCase):
    def test_excludes_secrets_binaries_caches_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [
                "README.md", "android/app/src/main/java/dev/veil/Main.java",
                ".env", ".env.production", "ios/local.properties", "signing.jks",
                "private.pem", "private.key", "credentials.json", "secrets.json",
                "relay.sqlite3", "relay.sqlite3-wal", "relay.db-shm",
                "android/.gradle/cached.dat", "android/app/build/debug/app.apk",
                "dist/Veil.apk", "ios/Pods/downloaded.swift",
                "ios/Veil.xcodeproj/project.pbxproj", "code/__pycache__/module.pyc",
            ]
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            (root / "external.txt").symlink_to(root / ".env")
            previous = packager.ROOT
            try:
                packager.ROOT = root
                actual = {p.relative_to(root).as_posix() for p in packager.source_files()}
            finally:
                packager.ROOT = previous
            self.assertEqual(actual, {"README.md", "android/app/src/main/java/dev/veil/Main.java"})


if __name__ == "__main__":
    unittest.main()
