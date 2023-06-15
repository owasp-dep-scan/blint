#!/usr/bin/env bash

# poetry install

poetry run pyinstaller blint/cli.py --noconfirm --log-level=WARN --nowindow --onefile --name blint --collect-all blint --osx-bundle-identifier io.appthreat.blint --target-architecture x86_64 --codesign-identity ${CODESIGN_ID} --osx-entitlements-file .builds/Entitlements.plist
