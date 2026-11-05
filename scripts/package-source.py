#!/usr/bin/env python3
"""Package source only; never include databases, caches or signing keys."""
from pathlib import Path
import hashlib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIRS = {".git", ".gradle", ".venv", "__pycache__", "build", "dist", "Pods", "DerivedData", "xcuserdata", "data"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db", ".jks", ".keystore", ".p12", ".p8", ".pfx", ".pem", ".key", ".mobileprovision", ".ipa", ".apk"}


def source_files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS or part.endswith((".xcodeproj", ".xcworkspace", ".xcarchive")) for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix in EXCLUDED_SUFFIXES or path.name in {".env", "local.properties", ".DS_Store", "secrets.json", "credentials.json"}:
            continue
        if path.name.startswith(".env."):
            continue
        if any(marker in path.name for marker in (".sqlite3-", ".sqlite-", ".db-")):
            continue
        yield path


def main():
    destination = ROOT / "dist/Veil-0.1.0-source.zip"
    destination.parent.mkdir(exist_ok=True)
    count = 0
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source_files():
            archive.write(path, "Veil/" + path.relative_to(ROOT).as_posix())
            count += 1
    with destination.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    print(f"Packaged {count} source files: {destination}")
    print(f"SHA-256 {digest}")


if __name__ == "__main__":
    main()
