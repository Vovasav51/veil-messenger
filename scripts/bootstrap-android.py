#!/usr/bin/env python3
"""Download verified Android build tools to a user-owned cache (no root).

SDK licenses are NOT auto-accepted. Run sdkmanager --licenses yourself after
reading them; this helper only downloads the tools and installs JDK/Gradle.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

CACHE = Path(os.environ.get("VEIL_BUILD_CACHE", Path.home() / ".cache/veil-build"))
SDK = CACHE / "android-sdk"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "VeilBuild/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def download(url, path, expected, algorithm="sha256"):
    if path.exists() and hashlib.file_digest(path.open("rb"), algorithm).hexdigest() == expected:
        return path
    partial = path.with_suffix(path.suffix + ".part")
    print(f"Downloading {path.name}", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "VeilBuild/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
        shutil.copyfileobj(response, output, 1024 * 1024)
    with partial.open("rb") as source:
        actual = hashlib.file_digest(source, algorithm).hexdigest()
    if actual != expected:
        raise RuntimeError(f"Checksum mismatch for {path.name}")
    partial.replace(path)
    return path


def unzip(path, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            target = (destination / entry.filename).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise RuntimeError("Unsafe ZIP entry")
            archive.extract(entry, destination)
            mode = entry.external_attr >> 16
            if mode and not entry.is_dir():
                target.chmod(mode & 0o777)


def jdk():
    home = CACHE / "jdk-21"
    if (home / "bin/javac").exists():
        return str(home)
    info = json.loads(fetch("https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux"))
    package = info[0]["binary"]["package"]
    path = download(package["link"], CACHE / "jdk-21.tar.gz", package["checksum"])
    unpack = CACHE / "jdk-unpack"
    unpack.mkdir(exist_ok=True)
    with tarfile.open(path) as archive:
        archive.extractall(unpack, filter="data")
    candidates = [p for p in unpack.iterdir() if (p / "bin/javac").exists()]
    if len(candidates) != 1:
        raise RuntimeError("JDK root not found")
    candidates[0].rename(home)
    return str(home)


def gradle():
    home = CACHE / "gradle-8.9"
    if (home / "bin/gradle").exists():
        return str(home)
    url = "https://services.gradle.org/distributions/gradle-8.9-bin.zip"
    checksum = fetch(url + ".sha256").decode().strip().split()[0]
    path = download(url, CACHE / "gradle-8.9-bin.zip", checksum)
    unzip(path, CACHE)
    return str(home)


def sdktools():
    executable = SDK / "cmdline-tools/latest/bin/sdkmanager"
    if executable.exists():
        return str(SDK)
    root = ET.fromstring(fetch("https://dl.google.com/android/repository/repository2-1.xml"))
    choices = []
    for package in root.findall("remotePackage"):
        if not package.attrib.get("path", "").startswith("cmdline-tools;"):
            continue
        channel = package.find("channelRef")
        if channel is not None and channel.get("ref") != "channel-0":
            continue
        major = int(package.findtext("revision/major", "0"))
        for archive in package.findall("archives/archive"):
            if archive.findtext("host-os") == "linux":
                complete = archive.find("complete")
                choices.append((major, complete.findtext("url"), complete.findtext("checksum")))
    _, name, checksum = max(choices)
    path = download("https://dl.google.com/android/repository/" + name, CACHE / name, checksum, "sha1")
    temporary = CACHE / "sdk-tools-unpack"
    unzip(path, temporary)
    executable.parent.parent.parent.mkdir(parents=True, exist_ok=True)
    (temporary / "cmdline-tools").rename(SDK / "cmdline-tools/latest")
    return str(SDK)


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(function) for function in (jdk, gradle, sdktools)]
        java, gradle_home, sdk = [future.result() for future in futures]
    env_file = CACHE / "env.sh"
    env_file.write_text(
        f'export JAVA_HOME="{java}"\nexport ANDROID_HOME="{sdk}"\n'
        f'export ANDROID_SDK_ROOT="{sdk}"\nexport GRADLE_USER_HOME="{CACHE}/gradle-cache"\n'
        f'export PATH="{java}/bin:{gradle_home}/bin:{sdk}/cmdline-tools/latest/bin:$PATH"\n'
    )
    print(f"Tools ready. source {env_file}")
    print('Read/accept SDK license: sdkmanager --licenses')
    print('Then install: sdkmanager "platforms;android-35" "build-tools;35.0.0" "platform-tools"')


if __name__ == "__main__":
    main()
