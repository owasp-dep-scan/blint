#!/usr/bin/env python3
# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Build the static-linkage measurement corpus (P4.3 gate 5).

Compiles real C projects as static archives, ingests them into a blint-db
database at member granularity (requires a blint-db checkout carrying the
similarity-hash columns, Binaries.archive_name, and archive-member ingestion),
links stripped query binaries against a known subset of the archives, and
captures per-member linker ground truth with ld's ``-why_load``.

The corpus deliberately includes one archive that is NOT ingested into the
database (miniz 2.1.0, a zlib-shaped library): the query binaries linked
against it are the false-positive probe for member-level attribution.

Outputs, under --output-dir (default .tmp-static-linkage/):

    src/<project>/          downloaded and built project sources
    apps/app-*              linked query binaries (stripped)
    apps/gt-app-*.txt       per-app ground truth: members the linker loaded
    reports/*.json          blint metadata exports for every app
    blintdb-v4.db           the member-level database

Usage (from the blint repo root, blint-db sibling expected at ../blint-db):

    python tests/scripts/build_static_linkage_corpus.py

Network access, clang (LLVM), make, ar, and unzip are required. nyxstone
disassembly needs LLVM 18 on PATH with NYXSTONE_LLVM_PREFIX set.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

LLVM_PREFIX = os.environ.get("BLINT_STATIC_LINKAGE_LLVM", "/opt/homebrew/opt/llvm@18")
CLANG = str(Path(LLVM_PREFIX) / "bin" / "clang")
STRIP = str(Path(LLVM_PREFIX) / "bin" / "llvm-strip")

PROJECTS = (
    # (name, purl, url, build kind)
    ("zlib", "pkg:generic/zlib@1.3.1", "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz", "zlib"),
    ("lua", "pkg:generic/lua@5.4.6", "https://www.lua.org/ftp/lua-5.4.6.tar.gz", "lua"),
    ("sqlite3", "pkg:generic/sqlite@3.46.0", "https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip", "sqlite"),
    ("cjson", "pkg:generic/cjson@1.7.18", None, "cjson"),
    # miniz is built but intentionally NOT ingested: it must stay absent from
    # the database so queries linked against it probe false attribution.
    ("miniz", None, "https://github.com/richgel999/miniz/archive/refs/tags/2.1.0.tar.gz", "miniz"),
)

ARCH = ("-arch", "arm64") if sys.platform == "darwin" else ()


def run(command, **kwargs):
    result = subprocess.run(command, check=False, **kwargs)
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {command}")


def download(url: str, dest: Path) -> None:
    if dest.exists():
        return
    run(["curl", "-sL", "--max-time", "120", "-o", str(dest), url])


def build_project(kind: str, src_dir: Path, out: Path) -> None:
    env = dict(os.environ, CC=CLANG)
    if kind == "zlib":
        run(
            ["./configure", "--static", *(["-archs", "arm64"] if ARCH else [])],
            cwd=src_dir,
            env=env,
            stdout=subprocess.DEVNULL,
        )
        run(["make", "libz.a"], cwd=src_dir, env=env, stdout=subprocess.DEVNULL)
        shutil.copy(src_dir / "libz.a", out)
    elif kind == "lua":
        run(["make", "-s", "macosx", "MYCFLAGS=-O2", "-j4"], cwd=src_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copy(src_dir / "src" / "liblua.a", out)
    elif kind == "sqlite":
        run([CLANG, *ARCH, "-O2", "-DSQLITE_ENABLE_FTS4", "-DSQLITE_ENABLE_RTREE", "-c", "sqlite-amalgamation-3460000/sqlite3.c", "-o", "sqlite3.o"], cwd=src_dir, env=env)
        run(["ar", "cru", str(out), "sqlite3.o"], cwd=src_dir)
    elif kind == "cjson":
        run([CLANG, *ARCH, "-O2", "-I.", "-c", "cJSON.c", "-o", "cJSON.o"], cwd=src_dir, env=env)
        run(["ar", "cru", str(out), "cJSON.o"], cwd=src_dir)
    elif kind == "miniz":
        run([CLANG, *ARCH, "-O2", "-I.", "-c", "miniz.c", "-o", "miniz.o"], cwd=src_dir, env=env)
        run([CLANG, *ARCH, "-O2", "-I.", "-c", "miniz_tdef.c", "-o", "miniz_tdef.o"], cwd=src_dir, env=env)
        run([CLANG, *ARCH, "-O2", "-I.", "-c", "miniz_tinfl.c", "-o", "miniz_tinfl.o"], cwd=src_dir, env=env)
        run(["ar", "cru", str(out), "miniz.o", "miniz_tdef.o", "miniz_tinfl.o"], cwd=src_dir)


APP_SOURCES = {
    "app-zlib-lua": ("main1.c", "zlib lua"),
    "app-cjson-sqlite": ("main2.c", "cjson sqlite3"),
    "app-miniz": ("main3.c", "miniz"),
    "app-zlib-miniz": ("main4.c", "zlib miniz"),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(REPO_ROOT / ".tmp-static-linkage"))
    parser.add_argument(
        "--blint-db-root",
        default=str(REPO_ROOT.parent / "blint-db"),
        help="blint-db checkout with archive-member ingestion (feat/p4.3-member-level).",
    )
    args = parser.parse_args()
    out_dir = Path(args.output_dir).resolve()
    src_dir = out_dir / "src"
    apps_dir = out_dir / "apps"
    reports_dir = out_dir / "reports"
    for directory in (src_dir, apps_dir, reports_dir):
        directory.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, args.blint_db_root)

    archives = {}
    for name, _purl, url, kind in PROJECTS:
        project_dir = src_dir / name
        project_dir.mkdir(exist_ok=True)
        archive = project_dir / f"lib{name}.a"
        if not archive.exists():
            if kind == "cjson":
                for fname in ("cJSON.c", "cJSON.h"):
                    download(f"https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/{fname}", project_dir / fname)
                build_project(kind, project_dir, archive)
            elif kind == "miniz":
                tarball = project_dir / "miniz-2.1.0.tar.gz"
                download(url, tarball)
                with tarfile.open(tarball) as handle:
                    handle.extractall(project_dir)
                build_project(kind, project_dir / "miniz-2.1.0", archive)
            elif kind == "sqlite":
                import zipfile

                zipball = project_dir / "sqlite-amalgamation-3460000.zip"
                download(url, zipball)
                with zipfile.ZipFile(zipball) as handle:
                    handle.extractall(project_dir)
                build_project(kind, project_dir, archive)
            else:
                tarball = project_dir / url.rsplit("/", 1)[-1]
                download(url, tarball)
                with tarfile.open(tarball) as handle:
                    handle.extractall(project_dir)
                build_project(kind, next(project_dir.glob(f"{name}-*")), archive)
        archives[name] = archive

    write_app_sources(apps_dir)
    ground_truth = {}
    for app, (source, libs) in APP_SOURCES.items():
        lib_paths = [archives[name] for name in libs.split()]
        include_args = [f"-I{archives[name].parent}" for name in libs.split()]
        include_args += [
            f"-I{src_dir / 'zlib' / next(d.name for d in src_dir.glob('zlib-*') if d.is_dir())}",
            f"-I{src_dir / 'lua' / next(d.name for d in src_dir.glob('lua-*') if d.is_dir()) / 'src'}",
            f"-I{src_dir / 'miniz' / 'miniz-2.1.0'}",
        ]
        binary = apps_dir / app
        why_load = apps_dir / f"gt-{app}.txt"
        result = subprocess.run(
            [CLANG, *ARCH, "-O2", *include_args, str(apps_dir / source), *[str(p) for p in lib_paths], "-Wl,-why_load", "-o", str(binary)],
            cwd=apps_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise SystemExit(f"link failed for {app}: {result.stderr[:2000]}")
        loaded = [
            line
            for line in result.stderr.splitlines()
            if "caused load of" in line
        ]
        why_load.write_text("\n".join(loaded))
        ground_truth[app] = sorted({part.split("(")[-1].rstrip(")") for line in loaded for part in [line] if "(" in line})
        run([STRIP, str(binary)])

    db_file = out_dir / "blintdb-v4.db"
    if db_file.exists():
        db_file.unlink()
    os.environ["BLINT_DB_FILE"] = str(db_file)
    from blint_db.ingest import ingest_archive_members, ingest_binary_file

    for name, purl, _url, _kind in PROJECTS:
        if purl is None:
            continue
        ingest_binary_file(
            str(archives[name]), db_file=str(db_file), project_name=name, project_purl=purl, disassemble=True
        )
        members = ingest_archive_members(
            str(archives[name]), db_file=str(db_file), project_name=name, project_purl=purl, disassemble=True
        )
        print(f"ingested {name}: {len(members)} members")

    for app in APP_SOURCES:
        export_metadata(str(apps_dir / app), str(reports_dir / f"{app}-metadata.json"))
    print(f"corpus ready under {out_dir}")


def export_metadata(binary_path: str, dest: str) -> None:
    import orjson

    from blint.lib.binary import parse
    from blint.lib.utils import json_serializer

    metadata = parse(binary_path, disassemble=True)
    Path(dest).write_bytes(orjson.dumps(metadata, default=json_serializer))


def write_app_sources(apps_dir: Path) -> None:
    (apps_dir / "main1.c").write_text(
        """#include <string.h>
#include <stdio.h>
#include "zlib.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
int main(int argc, char** argv) {
    unsigned char in[256], out[512]; uLongf outlen = 512;
    for (int i = 0; i < 256; i++) in[i] = (unsigned char)(i * 7);
    int rc = compress2(out, &outlen, in, 256, Z_BEST_SPEED);
    unsigned char back[256]; uLongf backlen = 256;
    uncompress(back, &backlen, out, outlen);
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    if (luaL_dostring(L, "print('hello from lua')") != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        printf("lua error: %s\\n", err ? err : "?");
    }
    lua_getglobal(L, "tostring");
    lua_pushnumber(L, 3.14);
    lua_call(L, 1, 1);
    const char* s = lua_tostring(L, -1);
    printf("zlib rc=%d back=%d lua=%s len=%zu\\n", rc, (int)back[0], s ? s : "?", strlen(s ? s : ""));
    lua_close(L);
    return (argc > 42) ? (int)out[0] : 0;
}
"""
    )
    (apps_dir / "main2.c").write_text(
        """#include <stdio.h>
#include <string.h>
#include "sqlite3.h"
#include "cJSON.h"
int main(int argc, char** argv) {
    sqlite3* db = NULL;
    sqlite3_open(":memory:", &db);
    char* err = NULL;
    sqlite3_exec(db, "CREATE TABLE t(a,b); INSERT INTO t VALUES(1,2);", NULL, NULL, &err);
    cJSON* obj = cJSON_Parse("{\\"name\\":\\"blint\\",\\"n\\":42}");
    const cJSON* name = cJSON_GetObjectItemCaseSensitive(obj, "name");
    printf("db ver=%s name=%s err=%s\\n", sqlite3_libversion(), cJSON_GetStringValue(name), err ? err : "none");
    cJSON_Delete(obj);
    sqlite3_close(db);
    return (argc > 42) ? (int)strlen(err ? err : "") : 0;
}
"""
    )
    (apps_dir / "main3.c").write_text(
        """#include <stdio.h>
#include <string.h>
#include "miniz.h"
int main(int argc, char** argv) {
    unsigned char in[256], out[512]; mz_ulong outlen = 512;
    for (int i = 0; i < 256; i++) in[i] = (unsigned char)(i * 7);
    int rc = mz_compress2(out, &outlen, in, 256, 1);
    mz_ulong crc = mz_crc32(0, in, 256);
    unsigned char back[256]; mz_ulong backlen = 256;
    mz_uncompress(back, &backlen, out, outlen);
    printf("miniz rc=%d crc=%lu back=%d\\n", rc, (unsigned long)crc, (int)back[0]);
    return (argc > 42) ? (int)out[0] : 0;
}
"""
    )
    (apps_dir / "main4.c").write_text(
        """#include <stdio.h>
#include <string.h>
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "miniz.h"
#include "zlib.h"
int main(int argc, char** argv) {
    unsigned char in[256], zout[512], mout[512]; uLongf zlen = 512; mz_ulong mlen = 512;
    for (int i = 0; i < 256; i++) in[i] = (unsigned char)(i * 7);
    int rc1 = compress2(zout, &zlen, in, 256, Z_BEST_SPEED);
    int rc2 = mz_compress2(mout, &mlen, in, 256, 1);
    mz_ulong crc = mz_crc32(0, in, 256);
    uLong ad = adler32(0, in, 256);
    printf("zlib rc=%d miniz rc=%d crc=%lu adler=%lu\\n", rc1, rc2, (unsigned long)crc, (unsigned long)ad);
    return (argc > 42) ? (int)zout[0] : 0;
}
"""
    )


if __name__ == "__main__":
    main()
