# poetry install
rustup target add x86_64-pc-windows-msvc
poetry export -f requirements.txt > requirements-dist.txt
pyoxidizer build --release --target-triple x86_64-pc-windows-msvc
rm requirements-dist.txt
