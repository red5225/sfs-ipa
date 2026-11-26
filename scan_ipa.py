#!/usr/bin/env python3
"""Non-destructive inventory of an iOS IPA for developer debugging."""
import argparse
import hashlib
import plistlib
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

KNOWN = {
    "igamegod.framework": "iGameGod framework",
    "cydiasubstrate.framework": "CydiaSubstrate hooking framework",
    "spaceflightsimulator.dylib": "Additional bundled dynamic library",
}
TOKENS = (b"iosgods.com", b"iosgods", b"igamegod", b"cydiasubstrate",
          b"substrateinjection", b"spaceflightsimulator.dylib")
MAX_BYTES = 1_500_000_000


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def download(url, dest):
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS URLs are accepted")
    req = urllib.request.Request(url, headers={"User-Agent": "SFS-IPA-Audit/1.0"})
    size = 0
    with urllib.request.urlopen(req, timeout=60) as response, dest.open("wb") as out:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_BYTES:
                raise ValueError("IPA exceeds the 1.5 GB download limit")
            out.write(block)


def command(args, cwd):
    try:
        p = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=30, check=False)
        return p.stdout.strip() or "(no output)"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "Unavailable: " + str(exc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ipa", type=Path)
    group.add_argument("--url")
    parser.add_argument("--report", type=Path, default=Path("developer-report.md"))
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sfs-audit-") as folder:
        temp = Path(folder)
        ipa = args.ipa.resolve() if args.ipa else temp / "download.ipa"
        if args.url:
            download(args.url, ipa)
        if not ipa.is_file():
            raise FileNotFoundError(ipa)

        with zipfile.ZipFile(ipa) as archive:
            bad = archive.testzip()
            if bad:
                raise ValueError("ZIP CRC error: " + bad)
            names = archive.namelist()
            plist_name = next((n for n in names if n.endswith(".app/Info.plist")), None)
            info = plistlib.loads(archive.read(plist_name)) if plist_name else {}
            app_prefix = plist_name.rsplit("Info.plist", 1)[0] if plist_name else None
            app_dir = temp / "app"
            if app_prefix:
                for name in names:
                    if name.startswith(app_prefix) and not name.endswith("/"):
                        target = app_dir / name[len(app_prefix):]
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.read(name))

            paths = [n for n in names if ".framework/" in n.lower()
                     or n.lower().endswith(".dylib") or ".appex/" in n]
            matches = []
            for key, description in KNOWN.items():
                found = [n for n in names if key in n.lower()]
                matches.extend((key, description, n) for n in found)
            string_hits = set()
            for name in names:
                if name.endswith("/"):
                    continue
                try:
                    item = archive.getinfo(name)
                    if item.file_size > 250 * 1024 * 1024:
                        continue
                    data = archive.read(name).lower()
                except Exception:
                    continue
                for token in TOKENS:
                    if token in data:
                        string_hits.add(token.decode() + " in " + name)

        executable = info.get("CFBundleExecutable")
        binary = app_dir / executable if executable else None
        macho = command(["otool", "-L", str(binary)], temp) if binary and binary.exists() else "Not available"
        signature = command(["codesign", "-dv", "--verbose=4", str(app_dir)], temp) if app_dir.exists() else "Not available"

        lines = [
            "# SFS IPA developer audit", "",
            "> Non-destructive inventory. No binary was modified, removed, re-signed, or repackaged.", "",
            "## Archive",
            "- File: `" + ipa.name + "`",
            "- Size: " + format(ipa.stat().st_size, ",") + " bytes",
            "- SHA-256: `" + digest(ipa) + "`", "",
            "## App metadata",
            "- Bundle ID: `" + str(info.get("CFBundleIdentifier", "Unknown")) + "`",
            "- Version: `" + str(info.get("CFBundleShortVersionString", "Unknown")) + "`",
            "- Build: `" + str(info.get("CFBundleVersion", "Unknown")) + "`",
            "- Executable: `" + str(executable or "Unknown") + "`", "",
            "## Known component matches"
        ]
        lines += ["- **" + key + "** (" + desc + "): `" + path + "`" for key, desc, path in matches] or ["- No known path matches."]
        lines += ["", "## Framework and library paths"]
        lines += ["- `" + p + "`" for p in sorted(set(paths))] or ["- None found."]
        lines += ["", "## Embedded string matches"]
        lines += ["- `" + s + "`" for s in sorted(string_hits)] or ["- No configured strings matched."]
        lines += ["", "## Mach-O linked libraries", "```text", macho, "```",
                  "", "## Code-signature metadata", "```text", signature, "```",
                  "", "## Developer notes",
                  "- A path or string match is an indicator, not proof of runtime behavior.",
                  "- Removing an injected framework alone cannot reconstruct modified Unity/game binaries.",
                  "- Compare against a developer-supplied known-good build with the same version and build number.",
                  "- Restore changed executables/resources from trusted source/build outputs and use the developer's normal signing process.", ""]
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text("\n".join(lines), encoding="utf-8")
        print("Wrote", args.report)
        print("SHA-256:", digest(ipa))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        raise SystemExit(2)
