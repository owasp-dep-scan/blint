#!/usr/bin/env python3
"""Build the tier-0 benign ELF/Mach-O false-positive corpus (~/sandbox/fp-corpus).

This is the F0.1 corpus builder for the ELF/Mach-O false-positive lane. It
assembles a benign (nothing in it is an attack) corpus of Mach-O and ELF
binaries with a ``MANIFEST.json`` in the same entry shape as the PE lane's
``~/sandbox/pe-corpus``: one entry per file with ``path`` (relative to the
corpus root), ``tier``, ``sha256``, ``bytes``, ``source`` (provenance string
naming the distro image + package + version, or the toolchain that built the
file) and ``fetched`` (UTC timestamp).

Why a builder rather than a committed corpus: Apple system binaries and
distro packages cannot be committed. The builder is deterministic for a fixed
machine state (seeded sampling, sorted file lists); package versions are
recorded at build time, so two builds on different days differ in exactly the
versions the manifest names.

Inputs it draws on, all named in the manifest:
- Mach-O (runs on the macOS host):
  * ``/bin``, ``/usr/bin``, ``/usr/lib`` (*.dylib on disk), ``/usr/libexec``
    that exist on disk (sampled with a fixed seed for the large directories);
  * dylibs extracted from the dyld shared caches. The extractor is
    ``ipsw dyld extract --all`` (blacktop/ipsw; version recorded in each
    entry's source) run over the arm64e and x86_64 caches under
    ``/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld``. The Xcode
    16.4 ``dsc_extractor.bundle`` (``dyld_shared_cache_extract_dylibs_progress``)
    was tried first and refuses this macOS 15.8 cache layout ("stat failed for
    dyld shared cache"); that attempt and its failure mode are recorded here
    so the extractor choice is an argument, not an accident.
  * a few notarised third-party applications (``--apps``; notarisation checked
    with ``spctl -a -vv`` and recorded in the source string);
  * Go/Rust fixtures built by the toolchains present on the host, plus the
    wasm-tools 1.247.0 release binaries already on this machine.
- ELF (runs in docker containers, linux/arm64):
  * Debian stable, Ubuntu 24.04 and Alpine packages, with package name and
    version recorded per file (``dpkg -L``/``apk info -L`` for the file list,
    ``dpkg-query``/``apk info -v`` for versions). Packages not in the base
    image are installed inside the ephemeral container and recorded as such.
  * static Go binaries built in the golang container (CGO_ENABLED=0);
  * static/dynamic Rust ELF from the wasm-tools 1.247.0 release (musl static
    and glibc dynamic builds);
  * kernel modules: the Alpine ``linux-lts`` package is *downloaded and
    unpacked* (``apk fetch`` + tar), never installed, and a deterministic
    sample of its ``.ko`` files is gunzipped into the corpus.

No network fetch is needed beyond docker image pulls, the Alpine package
download, and the distro package installs inside the ephemeral containers.

Usage:
    python tests/scripts/build_fp_corpus.py --corpus ~/sandbox/fp-corpus \
        [--seed 20260923] [--skip-macho] [--skip-elf] [--apps Transmission.app,...]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SEED = 20260923
DEFAULT_CORPUS = Path.home() / "sandbox" / "fp-corpus"
WASM_TOOLS_DIR = Path.home() / "sandbox" / "rust-binaries" / "wasm-tools-1.247.0"
DYLD_CACHE_ROOT = Path(
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"
)
DYLD_EXTRACT_SCRATCH = Path.home() / "sandbox" / "fp-corpus-work"

# ipsw release used for dyld shared cache extraction (see module docstring).
IPSW_VERSION = "3.1.723"
IPSW_COMMIT = "ee9db4bc6feeeb45d9625687a66aa3ebbb4dd526"
IPSW_BIN = DYLD_EXTRACT_SCRATCH / "tools" / "ipsw"

# Sampling caps per Mach-O source directory (deterministic under --seed).
MACHO_SAMPLES = {
    "usr-bin": 100,
    "usr-lib": 120,
    "usr-libexec": 60,
    "dyld-arm64e": 150,
    "dyld-x86_64": 80,
}

# Distro package lists. Packages not present in the base image are installed
# inside the ephemeral container (recorded per file in the manifest source).
# File names differ between releases (libssl3 vs libssl3t64, libpng16-16 vs
# libpng16-16t64); the install step tries the plain name first and the t64
# alias second, and the recorded version always comes from dpkg-query/apk
# after the install, never from the request.
DISTRO_PACKAGES = {
    "debian": [
        "bash", "coreutils", "grep", "sed", "tar", "findutils", "gzip",
        "dpkg", "apt", "binutils", "libc6", "libgcc-s1", "libstdc++6",
        "zlib1g", "libssl3", "libpng16-16", "libbz2-1.0",
    ],
    "ubuntu": [
        "bash", "coreutils", "grep", "sed", "tar", "findutils", "gzip",
        "dpkg", "apt", "binutils", "libc6", "libgcc-s1", "libstdc++6",
        "zlib1g", "libssl3", "libpng16-16", "libbz2-1.0",
    ],
    "alpine": [
        "busybox", "musl", "coreutils", "binutils", "apk-tools",
        "zlib", "libssl3", "libpng", "bash", "grep",
    ],
}
DISTRO_IMAGES = {
    "debian": "debian:stable",
    "ubuntu": "ubuntu:24.04",
    "alpine": "alpine:latest",
}
# Max files copied per package (sorted inside the container, then truncated).
FILES_PER_PACKAGE = 6
# Max kernel modules sampled from the downloaded Alpine linux-lts package.
KERNEL_MODULE_SAMPLE = 12

THIRD_PARTY_APPS_DEFAULT = [
    "/Applications/Transmission.app",
    "/Applications/Tailscale.app",
    "/Applications/OrbStack.app",
    "/Applications/Claude.app",
]
APP_BINARIES_PER_APP = 6


def is_macho_file(path: Path) -> bool:
    """Mach-O magic check (64/32-bit and fat/universal), so directory
    samples contain binaries and not the shell/Perl scripts that live
    beside them in /usr/bin."""
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic in (
        b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64 little-endian
        b"\xce\xfa\xed\xfe",  # MH_MAGIC little-endian
        b"\xca\xfe\xba\xbe",  # FAT magic
        b"\xbe\xba\xfe\xca",
    )


def sh(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusBuilder:
    def __init__(self, corpus_root: Path, seed: int):
        self.root = corpus_root
        self.seed = seed
        self.entries: list[dict] = []
        self.notes: list[str] = []
        self.now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.macOS_version = sh(["sw_vers", "-productVersion"]).stdout.strip() or "macOS"
        self.macOS_build = sh(["sw_vers", "-buildVersion"]).stdout.strip()

    def add_file(self, src: Path, rel_dir: str, source: str, dest_name: str | None = None) -> None:
        """Copy src into <root>/<rel_dir>/ (basename, or dest_name when given)."""
        if not src.is_file() or src.is_symlink():
            return
        dest_dir = self.root / rel_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / (dest_name or src.name)
        if not dest.exists():
            # copyfile, not copy2: macOS system files carry restricted flags
            # (SF_RESTRICTED and friends) that chflags cannot re-apply, and the
            # corpus needs the bytes, not the flags.
            shutil.copyfile(src, dest)
        self.entries.append(
            {
                "path": str(dest.relative_to(self.root)),
                "tier": "tier0",
                "sha256": file_sha256(dest),
                "bytes": dest.stat().st_size,
                "source": source,
                "fetched": self.now,
            }
        )

    def sample_files(self, files: list[Path], cap: int) -> list[Path]:
        if len(files) <= cap:
            return sorted(files)
        rng = random.Random(self.seed)
        return sorted(rng.sample(files, cap))

    # --- Mach-O ------------------------------------------------------------

    def build_macho(self, apps: list[str], dyld_extract_dir: Path | None) -> None:
        print("[macho] on-disk Apple system files")
        base_src = f"macOS {self.macOS_version} ({self.macOS_build}) on-disk {{where}}"
        for name in sorted(
            p
            for p in Path("/bin").iterdir()
            if p.is_file() and not p.is_symlink() and is_macho_file(p)
        ):
            self.add_file(name, "macho/apple-bin", base_src.format(where="/bin"))
        usr_bin = sorted(
            p
            for p in Path("/usr/bin").iterdir()
            if p.is_file() and not p.is_symlink() and is_macho_file(p)
        )
        for name in self.sample_files(usr_bin, MACHO_SAMPLES["usr-bin"]):
            self.add_file(name, "macho/apple-usr-bin", base_src.format(where="/usr/bin"))
        usr_lib = sorted(
            p
            for p in Path("/usr/lib").iterdir()
            if p.is_file() and not p.is_symlink() and p.suffix == ".dylib" and is_macho_file(p)
        )
        for name in self.sample_files(usr_lib, MACHO_SAMPLES["usr-lib"]):
            self.add_file(name, "macho/apple-usr-lib", base_src.format(where="/usr/lib"))
        usr_libexec = sorted(
            p
            for p in Path("/usr/libexec").iterdir()
            if p.is_file() and not p.is_symlink() and is_macho_file(p)
        )
        for name in self.sample_files(usr_libexec, MACHO_SAMPLES["usr-libexec"]):
            self.add_file(
                name, "macho/apple-usr-libexec", base_src.format(where="/usr/libexec")
            )

        if dyld_extract_dir is not None:
            self.build_dyld(dyld_extract_dir)

        print("[macho] third-party notarised apps")
        for app in apps:
            self.add_app(Path(app))

        print("[macho] Go/Rust fixtures")
        self.add_golang_macho()
        self.add_rust_macho()

    def build_dyld(self, extract_root: Path) -> None:
        """Sample the ipsw-extracted dyld cache dylibs (already on disk)."""
        ipsw_src = (
            f"dyld shared cache {{arch}} extracted with ipsw {IPSW_VERSION} "
            f"(commit {IPSW_COMMIT[:12]}) `dyld extract --all`"
        )
        for arch, sub, cap in (
            ("arm64e", "dyld-extract-arm64e", MACHO_SAMPLES["dyld-arm64e"]),
            ("x86_64", "dyld-extract-x86_64", MACHO_SAMPLES["dyld-x86_64"]),
        ):
            src_dir = extract_root / sub
            if not src_dir.is_dir():
                self.notes.append(f"dyld extract dir missing for {arch}: {src_dir}")
                continue
            dylibs = sorted(src_dir.rglob("*.dylib"))
            for path in self.sample_files(dylibs, cap):
                rel = str(path.relative_to(src_dir))
                rel_dir = os.path.dirname(str(Path("macho/dyld-" + arch) / Path(rel).name))
                self.add_file(
                    path,
                    rel_dir,
                    ipsw_src.format(arch=arch) + f"; install path {rel}",
                )

    def add_app(self, app: Path) -> None:
        if not app.is_dir():
            self.notes.append(f"app not found: {app}")
            return
        spctl = sh(["spctl", "-a", "-vv", str(app)])
        verdict = " ".join(spctl.stdout.split()) or spctl.stderr.strip()
        binaries: list[Path] = []
        for pattern in (
            "Contents/MacOS/*",
            "Contents/Frameworks/**/*.dylib",
            "Contents/Helpers/*/Contents/MacOS/*",
            "Contents/Frameworks/*/Versions/*/Helpers/*/Contents/MacOS/*",
        ):
            binaries.extend(p for p in app.glob(pattern) if p.is_file() and not p.is_symlink())
        if not binaries:
            self.notes.append(f"no binaries found in {app}")
            return
        source = f"{app.name} ({verdict})"
        for path in self.sample_files(binaries, APP_BINARIES_PER_APP):
            self.add_file(path, f"macho/apps/{app.name}", source)

    def add_golang_macho(self) -> None:
        result = sh(["go", "version"])
        version = result.stdout.strip() or "go (unknown version)"
        for name, code in (
            ("go-hello-darwin", 'package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n'),
            (
                "go-net-darwin",
                'package main\nimport ("net/http"; "os")\n'
                'func main(){http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){w.WriteHeader(200)});'
                'http.ListenAndServe("127.0.0.1:0", nil); os.Exit(0)}\n',
            ),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                (tmp_path / "main.go").write_text(code)
                out = tmp_path / name
                build = sh(
                    ["go", "build", "-tags", "netgo", "-ldflags", "-s -w", "-o", str(out), "main.go"],
                    cwd=tmp,
                    env={**os.environ, "CGO_ENABLED": "0"},
                )
                if build.returncode != 0:
                    self.notes.append(f"go build failed for {name}: {build.stderr[:200]}")
                    continue
                self.add_file(out, "macho/toolchain", f"built by {version}, CGO_ENABLED=0")

    def add_rust_macho(self) -> None:
        result = sh(["rustc", "--version"])
        version = result.stdout.strip() or "rustc (unknown version)"
        code = "fn main() { println!(\"hi\"); }\n"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "main.rs").write_text(code)
            out = tmp_path / "rust-hello-darwin"
            build = sh(["rustc", "-O", "-o", str(out), str(tmp_path / "main.rs")])
            if build.returncode != 0:
                self.notes.append(f"rustc build failed: {build.stderr[:200]}")
            else:
                self.add_file(out, "macho/toolchain", f"built by {version}")
        for arch in ("aarch64-macos", "x86_64-macos"):
            path = WASM_TOOLS_DIR / f"wasm-tools-1.247.0-{arch}" / "wasm-tools"
            self.add_file(
                path,
                "macho/toolchain",
                f"wasm-tools 1.247.0 official release ({arch}), rust-built",
                dest_name=f"wasm-tools-{arch}",
            )

    # --- ELF ---------------------------------------------------------------

    def build_elf(self) -> None:
        for distro in ("debian", "ubuntu", "alpine"):
            print(f"[elf] {distro} container extraction")
            self.build_distro(distro)
        print("[elf] static Go (golang container)")
        self.add_golang_elf()
        print("[elf] Rust fixtures")
        for arch in ("aarch64-musl", "x86_64-musl", "aarch64-linux", "x86_64-linux"):
            path = WASM_TOOLS_DIR / f"wasm-tools-1.247.0-{arch}" / "wasm-tools"
            kind = "static musl" if arch.endswith("-musl") else "dynamic glibc"
            self.add_file(
                path,
                "elf/rust-toolchain",
                f"wasm-tools 1.247.0 official release ({arch}), rust-built, {kind}",
                dest_name=f"wasm-tools-{arch}",
            )
        print("[elf] kernel modules (Alpine linux-lts, downloaded not installed)")
        self.add_kernel_modules()

    def _docker(
        self, args: list[str], workdir: Path | None = None
    ) -> subprocess.CompletedProcess:
        return sh(["docker", "run", "--rm", "--platform", "linux/arm64", *args])

    def _distro_install_script(self, distro: str) -> str:
        packages = DISTRO_PACKAGES[distro]
        if distro == "alpine":
            return "apk update >/dev/null 2>&1 || true\napk add --no-cache " + " ".join(packages) + " >/dev/null 2>&1 || true\n"
        # apt installs per package so a renamed package cannot silently take
        # the whole install down with it: trixie/noble renamed several runtime
        # libraries to their time64 variants (libssl3 -> libssl3t64,
        # libpng16-16 -> libpng16-16t64, libbz2-1.0 -> libbz2-1.0t64), and a
        # single apt-get invocation with one unknown name installs nothing.
        lines = [
            "export DEBIAN_FRONTEND=noninteractive\n",
            "apt-get update >/dev/null 2>&1 || true\n",
            "rm -f /tmp/missing\n",
        ]
        for pkg in packages:
            lines.append(
                f"apt-get install -y --no-install-recommends {pkg} >/dev/null 2>&1 || "
                f"apt-get install -y --no-install-recommends {pkg}t64 >/dev/null 2>&1 || "
                f"echo {pkg} >> /tmp/missing\n"
            )
        return "".join(lines)

    def build_distro(self, distro: str) -> None:
        image = DISTRO_IMAGES[distro]
        # One container does install + selection + provenance + tar: a fresh
        # container of the same image would not carry the installed packages,
        # so the files must leave in the same run that installed them.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            if distro == "alpine":
                list_files = self._alpine_list_script()
            else:
                list_files = self._dpkg_list_script()
            inner = (
                self._distro_install_script(distro)
                + list_files
                + "cd /\n"
                "tar cf /host/files.tar --files-from=/tmp/selection\n"
                "cp /tmp/selection /host/selection\n"
                "cp /tmp/provenance /host/provenance\n"
                "[ -f /tmp/missing ] && cp /tmp/missing /host/missing || true\n"
            )
            result = self._docker(["-v", f"{tmp_path}:/host", image, "sh", "-c", inner])
            if result.returncode != 0 or not (tmp_path / "files.tar").exists():
                self.notes.append(f"{distro} extraction failed: {result.stderr[-300:]}")
                return
            if (tmp_path / "missing").exists():
                missing = (tmp_path / "missing").read_text().split()
                if missing:
                    self.notes.append(f"{distro}: packages not installable: {missing}")
            selection = [
                line
                for line in (tmp_path / "selection").read_text().splitlines()
                if line.strip()
            ]
            provenance = {}
            for line in (tmp_path / "provenance").read_text().splitlines():
                if line.count("|") == 2:
                    file_path, pkg, version = line.split("|")
                    provenance[file_path] = (pkg, version)
            if not selection:
                self.notes.append(f"{distro}: empty selection")
                return
            image_version = self._distro_version(distro)
            with tempfile.TemporaryDirectory() as unpack:
                with tarfile.open(tmp_path / "files.tar") as tar:
                    tar.extractall(unpack, filter="data")
                for file_path in selection:
                    src = Path(unpack) / file_path.lstrip("/")
                    if not src.is_file():
                        continue
                    pkg, version = provenance.get(file_path, ("unknown", "unknown"))
                    self.add_file(
                        src,
                        f"elf/{distro}",
                        f"{image} ({image_version}) linux/arm64, package {pkg} {version}",
                    )

    def _distro_version(self, distro: str) -> str:
        result = self._docker(
            [DISTRO_IMAGES[distro], "sh", "-c", "cat /etc/os-release | head -2"]
        )
        return " ".join(result.stdout.split())[:80]

    def _dpkg_list_script(self) -> str:
        packages = " ".join(DISTRO_PACKAGES["debian"])
        # Two preference passes per package: executables under */bin first,
        # then versioned .so libraries under */lib — so a large package like
        # libc6 contributes ld-linux/libc instead of six alphabetically-first
        # gconv modules (though those are ELF too and the second pass still
        # reaches them when a package has no binaries).
        return f"""
rm -f /tmp/selection /tmp/provenance /tmp/pkgsel
for pkg in {packages}; do
  dpkg -L "$pkg" 2>/dev/null | grep -E '^/(usr/)?s?bin/' | sort | while read -r f; do
      [ -f "$f" ] && [ ! -L "$f" ] && [ "$(dd if="$f" bs=1 skip=1 count=3 2>/dev/null)" = "ELF" ] && echo "$f"
  done | head -{FILES_PER_PACKAGE} > /tmp/pkgsel
  dpkg -L "$pkg" 2>/dev/null | grep -E '^/(usr/)?lib/.*\\.so' | sort | while read -r f; do
      [ -f "$f" ] && [ ! -L "$f" ] && [ "$(dd if="$f" bs=1 skip=1 count=3 2>/dev/null)" = "ELF" ] && echo "$f"
  done | head -4 >> /tmp/pkgsel
  while read -r f; do
    echo "$f" >> /tmp/selection
    echo "$f|$pkg|$(dpkg-query -W -f='${{Version}}' "$pkg" 2>/dev/null)" >> /tmp/provenance
  done < /tmp/pkgsel
done
touch /tmp/selection /tmp/provenance
"""

    def _alpine_list_script(self) -> str:
        packages = " ".join(DISTRO_PACKAGES["alpine"])
        # apk info -L lists paths WITHOUT the leading slash (bin/busybox), so
        # the patterns accept both and the loop re-roots relative names; apk
        # info -v <pkg> prints a description, so versions come from
        # `apk list --installed` whose first token is pkg-version.
        return f"""
rm -f /tmp/selection /tmp/provenance /tmp/pkgsel
for pkg in {packages}; do
  apk info -L "$pkg" 2>/dev/null | grep -E '^/?(usr/)?s?bin/' | sort | while read -r f; do
      [ -f "/$f" ] && [ ! -L "/$f" ] && [ "$(dd if="/$f" bs=1 skip=1 count=3 2>/dev/null)" = "ELF" ] && echo "/$f"
  done | head -{FILES_PER_PACKAGE} > /tmp/pkgsel
  apk info -L "$pkg" 2>/dev/null | grep -E '^/?(usr/)?lib/.*\\.so' | sort | while read -r f; do
      [ -f "/$f" ] && [ ! -L "/$f" ] && [ "$(dd if="/$f" bs=1 skip=1 count=3 2>/dev/null)" = "ELF" ] && echo "/$f"
  done | head -4 >> /tmp/pkgsel
  while read -r f; do
    echo "$f" >> /tmp/selection
    ver=$(apk list --installed "$pkg" 2>/dev/null | head -1 | cut -d' ' -f1)
    echo "$f|$pkg|$ver" >> /tmp/provenance
  done < /tmp/pkgsel
done
touch /tmp/selection /tmp/provenance
"""

    def add_golang_elf(self) -> None:
        code_hello = 'package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n'
        code_net = (
            'package main\nimport ("net/http"; "os")\n'
            'func main(){http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){w.WriteHeader(200)});'
            'http.ListenAndServe("127.0.0.1:0", nil); os.Exit(0)}\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "hello.go").write_text(code_hello)
            (tmp_path / "net.go").write_text(code_net)
            for name, src in (("go-hello-static", "hello.go"), ("go-net-static", "net.go")):
                result = self._docker(
                    [
                        "-v",
                        f"{tmp_path}:/src",
                        "golang:1.26",
                        "sh",
                        "-c",
                        f"cd /src && CGO_ENABLED=0 go build -tags netgo -ldflags '-s -w' "
                        f"-o /src/{name} {src} && go version > /src/go-version.txt",
                    ]
                )
                if result.returncode != 0 or not (tmp_path / name).exists():
                    self.notes.append(
                        f"static go build failed for {name}: {result.stderr[-300:]}"
                    )
                    continue
                go_version = (tmp_path / "go-version.txt").read_text().strip()
                self.add_file(
                    tmp_path / name,
                    "elf/golang-static",
                    f"built by {go_version} in golang:1.26 container, "
                    "CGO_ENABLED=0 linux/arm64",
                )

    def add_kernel_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            result = self._docker(
                [
                    "-v",
                    f"{tmp_path}:/host",
                    "alpine:latest",
                    "sh",
                    "-c",
                    "apk update >/dev/null 2>&1; cd /host && apk fetch linux-lts >/dev/null 2>&1 && "
                    "tar xzf linux-lts-*.apk && find lib/modules -name '*.ko*' | sort "
                    "| head -40 > selection.txt && cat /etc/os-release | head -2 >> selection.txt",
                ]
            )
            if result.returncode != 0 or not (tmp_path / "selection.txt").exists():
                self.notes.append(
                    f"kernel module download failed: rc={result.returncode} "
                    f"{result.stderr[-300:]}"
                )
                return
            lines = (tmp_path / "selection.txt").read_text().splitlines()
            os_release = " ".join(lines[-2:])
            modules = sorted(line for line in lines[:-2] if line.strip())
            chosen = self.sample_files(modules, KERNEL_MODULE_SAMPLE)
            alpine_ver = self._distro_version("alpine")
            search = sh(
                [
                    "docker",
                    "run",
                    "--rm",
                    "alpine:latest",
                    "sh",
                    "-c",
                    "apk update >/dev/null 2>&1; apk search -x linux-lts -v 2>/dev/null | head -1",
                ]
            )
            first_line = search.stdout.splitlines()[0].strip() if search.stdout.strip() else ""
            pkg_version = first_line.removeprefix("linux-lts-") or "unknown"
            for rel in chosen:
                src = tmp_path / rel
                if not src.is_file():
                    continue
                if src.suffix == ".gz":
                    out = src.with_suffix("")
                    with gzip.open(src, "rb") as gz, open(out, "wb") as raw:
                        shutil.copyfileobj(gz, raw)
                    src = out
                self.add_file(
                    src,
                    "elf/kernel-modules",
                    f"Alpine linux-lts {pkg_version} kernel modules ({alpine_ver}), "
                    "downloaded and unpacked, never installed",
                )

    # --- manifest ----------------------------------------------------------

    def write_manifest(self) -> None:
        entries = sorted(self.entries, key=lambda entry: entry["path"])
        seen: set[str] = set()
        deduped = []
        for entry in entries:
            if entry["path"] in seen:
                continue
            seen.add(entry["path"])
            deduped.append(entry)
        manifest = self.root / "MANIFEST.json"
        manifest.write_text(json.dumps(deduped, indent=1) + "\n", encoding="utf-8")
        notes_file = self.root / "BUILD-NOTES.json"
        notes_file.write_text(
            json.dumps(
                {
                    "built": self.now,
                    "seed": self.seed,
                    "notes": self.notes,
                    "counts": {
                        "entries": len(deduped),
                        "macho": sum(
                            1 for e in deduped if e["path"].startswith("macho/")
                        ),
                        "elf": sum(1 for e in deduped if e["path"].startswith("elf/")),
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"[manifest] {len(deduped)} entries -> {manifest}")
        for note in self.notes:
            print(f"[note] {note}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--apps",
        default=",".join(THIRD_PARTY_APPS_DEFAULT),
        help="Comma-separated third-party .app paths to sample",
    )
    parser.add_argument("--dyld-extract", default=str(DYLD_EXTRACT_SCRATCH))
    parser.add_argument("--skip-macho", action="store_true")
    parser.add_argument("--skip-elf", action="store_true")
    args = parser.parse_args()

    corpus_root = Path(args.corpus).expanduser()
    corpus_root.mkdir(parents=True, exist_ok=True)
    builder = CorpusBuilder(corpus_root, args.seed)
    if not args.skip_macho:
        builder.build_macho(
            [a for a in args.apps.split(",") if a], Path(args.dyld_extract).expanduser()
        )
    if not args.skip_elf:
        builder.build_elf()
    builder.write_manifest()
    return 0


if __name__ == "__main__":
    sys.exit(main())
