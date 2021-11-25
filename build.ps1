# poetry install
rustup target add x86_64-pc-windows-msvc
poetry export -f requirements.txt > requirements-dist.txt
set RUSTFLAGS=-C target-feature=+crt-static
pyoxidizer build --release --target-triple i686-pc-windows-msvc
pyoxidizer build --release --target-triple x86_64-pc-windows-msvc
pyoxidizer build --release --target-triple x86_64-pc-windows-msvc exe_installer
rm requirements-dist.txt
