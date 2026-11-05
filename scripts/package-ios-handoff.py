#!/usr/bin/env python3
"""Create a small source-only Mac handoff, preserving the XcodeGen folder layout."""
from pathlib import Path
import hashlib
import importlib.util
import re
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("veil_source_packager", ROOT / "scripts/package-source.py")
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)

EXTRA = {
    "LICENSE", "THIRD_PARTY_NOTICES.md", "SPEC.md",
    "scripts/ios-build.sh", "scripts/ios-ci-sign.sh",
    "docs/IOS_BUILD.md", "docs/BUILD_STATUS.md",
    "docs/MAC_FRIEND_QUICKSTART_UA.md",
}
SECRET = re.compile(rb"(?:github_pat_[A-Za-z0-9_]{25,}|ghp_[A-Za-z0-9]{25,}|-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)")


def main():
    destination = ROOT / "dist/Veil-iPhone-for-Mac.zip"
    destination.parent.mkdir(exist_ok=True)
    instruction = ROOT / "docs/MAC_FRIEND_QUICKSTART_UA.md"
    selected = []
    for path in packager.source_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(("ios/", "licenses/")) or relative in EXTRA:
            content = path.read_bytes()
            if SECRET.search(content):
                raise RuntimeError(f"Refusing credential-like data in {relative}")
            selected.append((path, relative))
    required = {"ios/project.yml", "ios/Podfile", "ios/Veil/VeilApp.swift", "licenses/AGPL-3.0.txt", "scripts/ios-build.sh"}
    if not required.issubset({name for _, name in selected}):
        raise RuntimeError("Incomplete Mac handoff")
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Veil-iPhone/START_HERE.txt", instruction.read_text())
        for path, relative in selected:
            archive.write(path, "Veil-iPhone/" + relative)
    instructions_out = destination.parent / "Veil-iPhone-instructions.txt"
    shutil.copyfile(instruction, instructions_out)
    with destination.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    (destination.parent / "Veil-iPhone-for-Mac.sha256").write_text(digest + "  " + destination.name + "\n")
    print(f"Created {destination} ({destination.stat().st_size} bytes; {len(selected) + 1} entries)")
    print(f"Instructions: {instructions_out}")
    print(f"SHA-256: {digest}")
    print("Source only: no compiled IPA, signing credentials or relay secrets.")


if __name__ == "__main__":
    main()
