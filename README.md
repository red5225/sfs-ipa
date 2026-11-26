# SFS IPA Audit

Non-destructive IPA inspection for a developer handoff. This repository does not alter or repackage the game.

## What it checks
- App bundle ID, version, and build from Info.plist
- Bundled frameworks and dynamic libraries
- Known component paths: iGameGod.framework, CydiaSubstrate.framework, SpaceflightSimulator.dylib
- Embedded iOSGods/iGameGod/Substrate strings
- Mach-O linked libraries and code-signature metadata on macOS runners

## Run locally
`python3 scan_ipa.py --ipa /path/to/game.ipa --report developer-report.md`

## Run with GitHub Actions
Open Actions → Audit SFS IPA → Run workflow, then provide a direct HTTPS URL to the IPA release asset. Download the generated `sfs-ipa-developer-report` artifact when the run finishes.

## Why this does not create a “clean” IPA
Deleting injected frameworks does not restore any modified Unity/game executable or resources. A real clean build requires the developers' known-good source/build artifacts or an original unmodified IPA. This workflow deliberately does not erase provenance, patch binaries, remove frameworks, re-sign, or repackage the commercial game.

## Supplied sample observations
The uploaded sample IPA SHA-256 was:
`82394489509101cab18ebede91255a51dbfc24d4c5923a295603e24de6e28296`

The sample contained:
- `Payload/SpaceflightSimulator.app/Frameworks/iGameGod.framework`
- `Payload/SpaceflightSimulator.app/Frameworks/CydiaSubstrate.framework`
- `Payload/SpaceflightSimulator.app/Frameworks/SpaceflightSimulator.dylib`

These are observations about that uploaded sample only, not a claim about other builds. Do not commit IPA files, certificates, provisioning profiles, or private keys to this repository.
