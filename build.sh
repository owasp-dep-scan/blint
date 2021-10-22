#!/usr/bin/env bash

# poetry install
# rustup target add x86_64-unknown-linux-musl
# rustup target add x86_64-pc-windows-gnu
# rustup target add x86_64-apple-darwin
poetry export -f requirements.txt > requirements-dist.txt
pyoxidizer build --release --target-triple x86_64-unknown-linux-gnu
# pyoxidizer build --release --target-triple x86_64-unknown-linux-musl
# pyoxidizer build --release --target-triple x86_64-pc-windows-gnu
# pyoxidizer build --release --target-triple x86_64-apple-darwin
# pyoxidizer run
rm requirements-dist.txt
