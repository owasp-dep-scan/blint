#!/usr/bin/env bash

# poetry install
# rustup target add x86_64-unknown-linux-musl
# rustup target add x86_64-pc-windows-msvc
# rustup target add x86_64-apple-darwin
# rustup target add aarch64-apple-darwin
poetry export -f requirements.txt > requirements-dist.txt
pyoxidizer build --release --target-triple x86_64-unknown-linux-gnu
# pyoxidizer build --release --target-triple x86_64-unknown-linux-musl
# pyoxidizer build --release --target-triple x86_64-pc-windows-msvc
# pyoxidizer build --release --target-triple x86_64-apple-darwin
# pyoxidizer build --release --target-triple aarch64-apple-darwin
# pyoxidizer run
rm requirements-dist.txt

# poetry run pyinstaller blint/cli.py --noconfirm --log-level=WARN --nowindow --onefile --name blint --collect-all blint