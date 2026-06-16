# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import os
from pathlib import Path

import apsw

from blint.config import BLINTDB_LOC, MIN_MATCH_SCORE, SYMBOLS_LOOKUP_BATCH_LEN
from blint.logger import LOG

DB_SCHEMA_FAMILY = "blint-db"
DB_SCHEMA_VERSION = 2
DB_QUERY_LIMIT = 50
DB_EVIDENCE_LIMIT = 25
SYMBOL_ONLY_MATCH_THRESHOLD = max(3, MIN_MATCH_SCORE // 2)
MIN_FUNCTION_INSTRUCTION_COUNT_FOR_HASH_LOOKUP = 4
# Minimum distinct canonical functions a source graph must share with the binary
# before a callgraph-only match (no symbol or hash corroboration) is surfaced.
CALLGRAPH_ONLY_MATCH_THRESHOLD = 8
# Score contribution per shared canonical function, capped so a very large
# overlap corroborates strongly without completely overwhelming other evidence.
CALLGRAPH_MATCH_WEIGHT = 0.5
CALLGRAPH_MATCH_SCORE_CAP = 60.0
SYMBOL_SOURCES = (
    "functions",
    "ctor_functions",
    "dtor_functions",
    "exception_functions",
    "unwind_functions",
    "exports",
    "imports",
    "symtab_symbols",
    "dynamic_symbols",
    "exceptions",
)


def _resolve_db_file(db_file: str | None = None) -> str | None:
    database_file = db_file or BLINTDB_LOC
    if database_file and os.path.exists(database_file):
        return database_file
    if database_file and os.path.basename(database_file) == "blint.db":
        candidate = os.path.join(os.path.dirname(database_file), "blint-v2.db")
        if os.path.exists(candidate):
            return candidate
    return database_file


def get(db_file: str | None = None, read_only: bool = True) -> apsw.Connection | None:
    """Open a direct connection to the local blintdb SQLite database."""
    database_file = _resolve_db_file(db_file)
    if not database_file or not os.path.exists(database_file):
        return None
    flags = apsw.SQLITE_OPEN_NOFOLLOW
    flags |= apsw.SQLITE_OPEN_READONLY if read_only else apsw.SQLITE_OPEN_READWRITE
    connection = apsw.Connection(os.path.abspath(database_file), flags=flags)
    _apply_runtime_pragmas(connection, read_only=read_only)
    return connection


def _apply_runtime_pragmas(connection: apsw.Connection, *, read_only: bool = True) -> None:
    pragmas = [
        "PRAGMA foreign_keys = ON",
        "PRAGMA temp_store = MEMORY",
        "PRAGMA cache_size = -65536",
        "PRAGMA mmap_size = 268435456",
        "PRAGMA automatic_index = ON",
        "PRAGMA busy_timeout = 5000",
    ]
    if read_only:
        pragmas.insert(1, "PRAGMA query_only = 1")
    for pragma in pragmas:
        try:
            connection.execute(pragma)
        except apsw.Error:
            LOG.debug("Unable to apply SQLite runtime pragma: %s", pragma)


def _clean_nonempty_values(values) -> list[str]:
    if not values:
        return []
    return sorted(
        {str(value).strip() for value in values if value is not None and str(value).strip()}
    )


def _batched(values: list[str], batch_size: int = SYMBOLS_LOOKUP_BATCH_LEN):
    for idx in range(0, len(values), batch_size):
        yield values[idx : idx + batch_size]


def _decode_hex_csv(value: str | None) -> set[str]:
    if not value:
        return set()
    decoded = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            decoded.add(bytes.fromhex(item).decode("utf-8", "ignore"))
        except ValueError:
            LOG.debug("Unable to decode hex-encoded SQLite aggregate value")
    return decoded


def _normalize_binary_name(value: str | None) -> str:
    if not value:
        return ""
    name = Path(str(value)).name.lower()
    for suffix in (".dylib", ".dll", ".so", ".a", ".lib", ".exe"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name.startswith("lib"):
        name = name[3:]
    name = name.split(".")[0]
    return "".join(ch for ch in name if ch.isalnum())


def _decode_csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item and item.strip()}


def get_schema_meta(db_file: str | None = None) -> dict[str, str]:
    connection = get(db_file)
    if not connection:
        return {}
    try:
        rows = connection.execute("SELECT key, value FROM SchemaMeta").fetchall()
        return {str(row[0]): str(row[1]) for row in rows}
    except apsw.Error:
        return {}
    finally:
        connection.close()


def is_supported_blintdb(db_file: str | None = None) -> bool:
    meta = get_schema_meta(db_file)
    if not meta:
        return False
    return (
        meta.get("schema_family") == DB_SCHEMA_FAMILY
        and int(meta.get("schema_version", "0")) == DB_SCHEMA_VERSION
    )


def build_symbol_source_map(metadata: dict | None) -> dict[str, list[str]]:
    """Extract source-aware symbol buckets matching the blintdb v2 schema."""
    if not metadata:
        return {}
    source_map = {}
    for source in SYMBOL_SOURCES:
        entries = metadata.get(source) or []
        names = []
        for entry in entries:
            if isinstance(entry, dict):
                name = entry.get("name")
            else:
                name = entry
            if name:
                names.append(name)
        cleaned_names = _clean_nonempty_values(names)
        if cleaned_names:
            source_map[source] = cleaned_names
    return source_map


def build_function_hash_index(metadata: dict | None) -> dict[str, list[str]]:
    """Extract disassembly hashes from parsed binary metadata."""
    if not metadata:
        return {}
    disassembled_functions = metadata.get("disassembled_functions") or {}
    if not isinstance(disassembled_functions, dict):
        return {}
    instruction_hashes = []
    assembly_hashes = []
    for function_data in disassembled_functions.values():
        if not isinstance(function_data, dict):
            continue
        instruction_count = function_data.get("instruction_count")
        if (
            instruction_count is not None
            and int(instruction_count) < MIN_FUNCTION_INSTRUCTION_COUNT_FOR_HASH_LOOKUP
        ):
            continue
        if function_data.get("instruction_hash"):
            instruction_hashes.append(function_data["instruction_hash"])
        if function_data.get("assembly_hash"):
            assembly_hashes.append(function_data["assembly_hash"])
    hash_index = {}
    if instruction_hashes:
        hash_index["instruction_hashes"] = _clean_nonempty_values(instruction_hashes)
    if assembly_hashes:
        hash_index["assembly_hashes"] = _clean_nonempty_values(assembly_hashes)
    return hash_index


def build_callgraph_canon_names(metadata: dict | None) -> list[str]:
    """Return the canonical function names of a binary's recovered callgraph.

    The names are produced by the same canonicalization the source corpus uses,
    so they join directly against the stored source callgraph nodes. Returns an
    empty list when the binary has no callgraph (for example when disassembly
    was not performed).
    """
    if not metadata or not metadata.get("callgraph"):
        return []
    # Imported lazily so importing blint.db never pulls in the matcher stack.
    from blint.lib.callgraph.model import load_binary_callgraph

    graph = load_binary_callgraph(metadata)
    names = {node.canon.value for node in graph.nodes.values() if node.canon.value}
    return sorted(names)


def _blintdb_has_callgraph_tables(connection: apsw.Connection) -> bool:
    """Return True when the database carries the callgraph corpus tables.

    Shipped blintdb images may predate the callgraph corpus, so callers must
    degrade gracefully when these tables are absent.
    """
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('SourceGraphs', 'CallGraphNodes')"
        ).fetchall()
    except apsw.Error:
        return False
    return len({row[0] for row in rows}) == 2


def _build_binary_filters(binary_metadata: dict | None) -> tuple[str, list[str]]:
    if not binary_metadata:
        return "", []
    predicates = []
    params: list[str] = []
    if binary_type := binary_metadata.get("binary_type"):
        predicates.append("Binaries.binary_type = ?")
        params.append(str(binary_type))
    if llvm_target_tuple := binary_metadata.get("llvm_target_tuple"):
        predicates.append("COALESCE(Binaries.llvm_target_tuple, Builds.llvm_target_tuple) = ?")
        params.append(str(llvm_target_tuple))
    if not predicates:
        return "", []
    return " AND " + " AND ".join(predicates), params


def _ensure_project_match(project_matches: dict, row) -> dict:
    project_key = row["project_purl"] or f"project:{row['project_id']}"
    return project_matches.setdefault(
        project_key,
        {
            "project_id": row["project_id"],
            "project_name": row["project_name"],
            "project_purl": row["project_purl"],
            "matched_binary_ids": set(),
            "matched_binary_names": set(),
            "matched_symbols": set(),
            "matched_symbol_sources": set(),
            "matched_instruction_hashes": set(),
            "matched_assembly_hashes": set(),
            "matched_callgraph_functions": set(),
            "matched_symbol_rows": 0,
            "matched_function_rows": 0,
        },
    )


def _merge_symbol_rows(project_matches: dict, rows, source: str) -> None:
    for row in rows:
        match = _ensure_project_match(project_matches, row)
        match["matched_binary_ids"].update(_decode_csv_set(row["matched_binary_ids"]))
        match["matched_binary_names"].update(_decode_hex_csv(row.get("matched_binary_names_hex")))
        match["matched_symbols"].update(_decode_hex_csv(row["matched_symbols_hex"]))
        if row["matched_symbol_count"]:
            match["matched_symbol_sources"].add(source)
        match["matched_symbol_rows"] += int(row["matched_row_count"] or 0)


def _merge_hash_rows(project_matches: dict, rows, hash_kind: str) -> None:
    target_key = (
        "matched_instruction_hashes"
        if hash_kind == "instruction_hash"
        else "matched_assembly_hashes"
    )
    for row in rows:
        match = _ensure_project_match(project_matches, row)
        match["matched_binary_ids"].update(_decode_csv_set(row["matched_binary_ids"]))
        match["matched_binary_names"].update(_decode_hex_csv(row.get("matched_binary_names_hex")))
        match[target_key].update(_decode_csv_set(row["matched_hashes"]))
        match["matched_function_rows"] += int(row["matched_row_count"] or 0)


def _merge_callgraph_rows(project_matches: dict, rows) -> None:
    for row in rows:
        match = _ensure_project_match(project_matches, row)
        matched = row.get("matched_callgraph_functions")
        if matched:
            match["matched_callgraph_functions"].update(
                name for name in matched.split(",") if name
            )


def _execute(connection: apsw.Connection, query: str, params: list) -> list[dict]:
    cursor = connection.execute(query, params)
    columns = [description[0] for description in cursor.getdescription()]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _query_project_symbol_matches(
    connection: apsw.Connection,
    symbol_names: list[str],
    *,
    source: str,
    binary_filters: str = "",
    binary_filter_params: list[str] | None = None,
    limit: int = DB_QUERY_LIMIT,
) -> list[dict]:
    if not symbol_names:
        return []
    placeholders = ",".join("?" for _ in symbol_names)
    params = [source, *symbol_names]
    if binary_filter_params:
        params.extend(binary_filter_params)
    params.append(limit)
    query = f"""
        SELECT
            Projects.project_id,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT Symbols.name) AS matched_symbol_count,
            COUNT(*) AS matched_row_count,
            group_concat(DISTINCT Binaries.binary_id) AS matched_binary_ids,
            group_concat(DISTINCT hex(Binaries.name)) AS matched_binary_names_hex,
            group_concat(DISTINCT hex(Symbols.name)) AS matched_symbols_hex
        FROM Symbols
        JOIN Binaries ON Symbols.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Projects.purl IS NOT NULL
            AND Projects.purl != ''
            AND Symbols.source = ?
            AND Symbols.name IN ({placeholders})
            {binary_filters}
        GROUP BY Projects.project_id
        ORDER BY matched_symbol_count DESC, matched_row_count DESC, Projects.project_id ASC
        LIMIT ?
    """
    return _execute(connection, query, params)


def _query_project_hash_matches(
    connection: apsw.Connection,
    hash_values: list[str],
    *,
    hash_column: str,
    binary_filters: str = "",
    binary_filter_params: list[str] | None = None,
    limit: int = DB_QUERY_LIMIT,
) -> list[dict]:
    if not hash_values:
        return []
    placeholders = ",".join("?" for _ in hash_values)
    params = list(hash_values)
    if binary_filter_params:
        params.extend(binary_filter_params)
    params.append(limit)
    query = f"""
        SELECT
            Projects.project_id,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT FunctionFingerprints.function_key) AS matched_function_count,
            COUNT(*) AS matched_row_count,
            group_concat(DISTINCT Binaries.binary_id) AS matched_binary_ids,
            group_concat(DISTINCT hex(Binaries.name)) AS matched_binary_names_hex,
            group_concat(DISTINCT FunctionFingerprints.{hash_column}) AS matched_hashes
        FROM FunctionFingerprints
        JOIN Binaries ON FunctionFingerprints.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Projects.purl IS NOT NULL
            AND Projects.purl != ''
            AND FunctionFingerprints.{hash_column} IN ({placeholders})
            {binary_filters}
        GROUP BY Projects.project_id
        ORDER BY matched_function_count DESC, matched_row_count DESC, Projects.project_id ASC
        LIMIT ?
    """
    return _execute(connection, query, params)


def _query_symbol_batches(
    connection: apsw.Connection,
    project_matches: dict,
    symbol_source_map: dict[str, list[str]],
    *,
    binary_filters: str = "",
    binary_filter_params: list[str] | None = None,
    limit: int = DB_QUERY_LIMIT,
) -> bool:
    found_matches = False
    for source, names in symbol_source_map.items():
        for batch in _batched(_clean_nonempty_values(names)):
            rows = _query_project_symbol_matches(
                connection,
                batch,
                source=source,
                binary_filters=binary_filters,
                binary_filter_params=binary_filter_params,
                limit=limit,
            )
            if rows:
                found_matches = True
                _merge_symbol_rows(project_matches, rows, source)
    return found_matches


def _query_hash_batches(
    connection: apsw.Connection,
    project_matches: dict,
    hash_values: list[str],
    *,
    hash_column: str,
    binary_filters: str = "",
    binary_filter_params: list[str] | None = None,
    limit: int = DB_QUERY_LIMIT,
) -> bool:
    found_matches = False
    for batch in _batched(_clean_nonempty_values(hash_values)):
        rows = _query_project_hash_matches(
            connection,
            batch,
            hash_column=hash_column,
            binary_filters=binary_filters,
            binary_filter_params=binary_filter_params,
            limit=limit,
        )
        if rows:
            found_matches = True
            _merge_hash_rows(project_matches, rows, hash_column)
    return found_matches


def _query_project_callgraph_matches(
    connection: apsw.Connection,
    canon_names: list[str],
    *,
    limit: int = DB_QUERY_LIMIT,
) -> list[dict]:
    if not canon_names:
        return []
    placeholders = ",".join("?" for _ in canon_names)
    params = [*canon_names, limit]
    query = f"""
        SELECT
            SourceGraphs.project_id AS project_id,
            SourceGraphs.name AS project_name,
            SourceGraphs.purl AS project_purl,
            COUNT(DISTINCT CallGraphNodes.canon_name) AS matched_callgraph_count,
            group_concat(DISTINCT CallGraphNodes.canon_name) AS matched_callgraph_functions
        FROM CallGraphNodes
        JOIN SourceGraphs ON SourceGraphs.source_graph_id = CallGraphNodes.owner_id
        WHERE SourceGraphs.purl IS NOT NULL
            AND SourceGraphs.purl != ''
            AND CallGraphNodes.graph_kind = 'source'
            AND CallGraphNodes.canon_name IN ({placeholders})
        GROUP BY SourceGraphs.source_graph_id
        ORDER BY matched_callgraph_count DESC, SourceGraphs.source_graph_id ASC
        LIMIT ?
    """
    return _execute(connection, query, params)


def _query_callgraph_batches(
    connection: apsw.Connection,
    project_matches: dict,
    canon_names: list[str],
    *,
    limit: int = DB_QUERY_LIMIT,
) -> bool:
    found_matches = False
    for batch in _batched(_clean_nonempty_values(canon_names)):
        rows = _query_project_callgraph_matches(connection, batch, limit=limit)
        if rows:
            found_matches = True
            _merge_callgraph_rows(project_matches, rows)
    return found_matches


def _finalize_project_matches(
    project_matches: dict, *, target_binary_names: set[str] | None = None
) -> list[dict]:
    target_binary_names = target_binary_names or set()
    finalized_matches = []
    for match in project_matches.values():
        if not match["project_purl"]:
            continue
        matched_binary_count = len(match["matched_binary_ids"])
        matched_symbol_count = len(match["matched_symbols"])
        matched_binary_name_count = len(match["matched_binary_names"])
        matched_instruction_hash_count = len(match["matched_instruction_hashes"])
        matched_assembly_hash_count = len(match["matched_assembly_hashes"])
        matched_callgraph_count = len(match["matched_callgraph_functions"])
        binary_name_match = bool(
            target_binary_names
            and target_binary_names.intersection(
                {_normalize_binary_name(name) for name in match["matched_binary_names"]}
            )
        )
        score = float(matched_symbol_count)
        score += matched_instruction_hash_count * float(max(MIN_MATCH_SCORE, 12))
        score += matched_assembly_hash_count * float(max(MIN_MATCH_SCORE // 2, 6))
        score += float(min(len(match["matched_symbol_sources"]), 4))
        score += min(matched_callgraph_count * CALLGRAPH_MATCH_WEIGHT, CALLGRAPH_MATCH_SCORE_CAP)
        if binary_name_match:
            score += float(max(MIN_MATCH_SCORE * 3, 18))
        if not (
            matched_instruction_hash_count
            or matched_assembly_hash_count
            or matched_callgraph_count >= CALLGRAPH_ONLY_MATCH_THRESHOLD
            or score >= SYMBOL_ONLY_MATCH_THRESHOLD
        ):
            continue
        finalized_matches.append(
            {
                "project_id": match["project_id"],
                "project_name": match["project_name"],
                "project_purl": match["project_purl"],
                "matched_binary_count": matched_binary_count,
                "matched_binary_name_count": matched_binary_name_count,
                "matched_binary_names": sorted(match["matched_binary_names"])[:DB_EVIDENCE_LIMIT],
                "binary_name_match": binary_name_match,
                "matched_symbol_count": matched_symbol_count,
                "matched_symbol_sources": sorted(match["matched_symbol_sources"]),
                "matched_symbols": sorted(match["matched_symbols"])[:DB_EVIDENCE_LIMIT],
                "matched_instruction_hash_count": matched_instruction_hash_count,
                "matched_instruction_hashes": sorted(match["matched_instruction_hashes"])[
                    :DB_EVIDENCE_LIMIT
                ],
                "matched_assembly_hash_count": matched_assembly_hash_count,
                "matched_assembly_hashes": sorted(match["matched_assembly_hashes"])[
                    :DB_EVIDENCE_LIMIT
                ],
                "matched_callgraph_count": matched_callgraph_count,
                "matched_callgraph_functions": sorted(match["matched_callgraph_functions"])[
                    :DB_EVIDENCE_LIMIT
                ],
                "score": score,
            }
        )
    return sorted(
        finalized_matches,
        key=lambda row: (
            row["score"],
            row["binary_name_match"],
            row["matched_instruction_hash_count"],
            row["matched_assembly_hash_count"],
            row["matched_callgraph_count"],
            row["matched_symbol_count"],
            row["matched_binary_count"],
            row["project_purl"],
        ),
        reverse=True,
    )


def lookup_project_matches(
    symbol_source_map: dict[str, list[str]] | None = None,
    *,
    function_hash_index: dict[str, list[str]] | None = None,
    callgraph_canon_names: list[str] | None = None,
    binary_metadata: dict | None = None,
    db_file: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Lookup candidate project purls in blintdb v2 using symbols, function hashes, and callgraph."""
    database_file = _resolve_db_file(db_file)
    if not database_file or not os.path.exists(database_file):
        return []
    if not is_supported_blintdb(database_file):
        LOG.debug(
            "Skipping blintdb lookup because the local database is not a supported v2 schema"
        )
        return []
    normalized_source_map = {
        source: _clean_nonempty_values(names)
        for source, names in (symbol_source_map or {}).items()
        if _clean_nonempty_values(names)
    }
    normalized_hash_index = {
        key: _clean_nonempty_values(values)
        for key, values in (function_hash_index or {}).items()
        if _clean_nonempty_values(values)
    }
    normalized_canon_names = _clean_nonempty_values(callgraph_canon_names or [])
    if not normalized_source_map and not normalized_hash_index and not normalized_canon_names:
        return []
    binary_filters, binary_filter_params = _build_binary_filters(binary_metadata)
    connection = get(database_file)
    if not connection:
        return []
    try:
        project_matches: dict = {}
        target_binary_name = _normalize_binary_name(
            (binary_metadata or {}).get("name") or (binary_metadata or {}).get("file_path")
        )
        target_binary_names = {target_binary_name} if target_binary_name else set()
        hash_found = False
        if instruction_hashes := normalized_hash_index.get("instruction_hashes"):
            hash_found = _query_hash_batches(
                connection,
                project_matches,
                instruction_hashes,
                hash_column="instruction_hash",
                binary_filters=binary_filters,
                binary_filter_params=binary_filter_params,
            )
            if not hash_found and binary_filters:
                hash_found = _query_hash_batches(
                    connection,
                    project_matches,
                    instruction_hashes,
                    hash_column="instruction_hash",
                )
        if assembly_hashes := normalized_hash_index.get("assembly_hashes"):
            assembly_found = _query_hash_batches(
                connection,
                project_matches,
                assembly_hashes,
                hash_column="assembly_hash",
                binary_filters=binary_filters,
                binary_filter_params=binary_filter_params,
            )
            if not assembly_found and binary_filters:
                assembly_found = _query_hash_batches(
                    connection,
                    project_matches,
                    assembly_hashes,
                    hash_column="assembly_hash",
                )
            hash_found = hash_found or assembly_found
        symbol_found = False
        if normalized_source_map:
            symbol_found = _query_symbol_batches(
                connection,
                project_matches,
                normalized_source_map,
                binary_filters=binary_filters,
                binary_filter_params=binary_filter_params,
            )
            if not symbol_found and binary_filters:
                symbol_found = _query_symbol_batches(
                    connection,
                    project_matches,
                    normalized_source_map,
                )
        callgraph_found = False
        if normalized_canon_names and _blintdb_has_callgraph_tables(connection):
            callgraph_found = _query_callgraph_batches(
                connection,
                project_matches,
                normalized_canon_names,
            )
        matches = _finalize_project_matches(
            project_matches, target_binary_names=target_binary_names
        )
        name_matched_rows = [match for match in matches if match["binary_name_match"]]
        name_matched_purls = {match["project_purl"] for match in name_matched_rows}
        if name_matched_purls:
            strongest_name_match_score = max(match["score"] for match in name_matched_rows)
            strongest_name_match_hashes = max(
                match["matched_instruction_hash_count"] + match["matched_assembly_hash_count"]
                for match in name_matched_rows
            )
            matches = [
                match
                for match in matches
                if match["project_purl"] in name_matched_purls
                or match["matched_callgraph_count"] >= CALLGRAPH_ONLY_MATCH_THRESHOLD
                or (
                    match["matched_instruction_hash_count"] + match["matched_assembly_hash_count"]
                    >= max(8, strongest_name_match_hashes // 4)
                    and match["score"]
                    >= max(SYMBOL_ONLY_MATCH_THRESHOLD, strongest_name_match_score / 4)
                )
            ]
        if hash_found or callgraph_found:
            return matches[:limit]
        return [
            match
            for match in matches
            if match["matched_symbol_count"] >= SYMBOL_ONLY_MATCH_THRESHOLD
        ][:limit]
    finally:
        connection.close()


def detect_binaries_utilized(
    symbols_list=None,
    *,
    symbol_source_map: dict[str, list[str]] | None = None,
    function_hash_index: dict[str, list[str]] | None = None,
    callgraph_canon_names: list[str] | None = None,
    binary_metadata: dict | None = None,
    db_file: str | None = None,
    limit: int = 20,
) -> tuple[set, dict]:
    """Resolve likely component purls using the local blintdb v2 schema."""
    if symbol_source_map is None and symbols_list:
        symbol_names = []
        for symbol in symbols_list:
            if isinstance(symbol, dict):
                if symbol.get("name"):
                    symbol_names.append(symbol["name"])
            elif symbol:
                symbol_names.append(symbol)
        cleaned_names = _clean_nonempty_values(symbol_names)
        if cleaned_names:
            symbol_source_map = {"symtab_symbols": cleaned_names}
    matches = lookup_project_matches(
        symbol_source_map,
        function_hash_index=function_hash_index,
        callgraph_canon_names=callgraph_canon_names,
        binary_metadata=binary_metadata,
        db_file=db_file,
        limit=limit,
    )
    binary_detected = {match["project_purl"] for match in matches if match["project_purl"]}
    binary_evidence = {
        match["project_purl"]: {
            "project_name": match["project_name"],
            "score": match["score"],
            "matched_binary_count": match["matched_binary_count"],
            "matched_binary_name_count": match["matched_binary_name_count"],
            "matched_binary_names": match["matched_binary_names"],
            "binary_name_match": match["binary_name_match"],
            "matched_symbol_count": match["matched_symbol_count"],
            "matched_symbol_sources": match["matched_symbol_sources"],
            "matched_symbols": match["matched_symbols"],
            "matched_instruction_hash_count": match["matched_instruction_hash_count"],
            "matched_instruction_hashes": match["matched_instruction_hashes"],
            "matched_assembly_hash_count": match["matched_assembly_hash_count"],
            "matched_assembly_hashes": match["matched_assembly_hashes"],
            "matched_callgraph_count": match.get("matched_callgraph_count", 0),
            "matched_callgraph_functions": match.get("matched_callgraph_functions", []),
        }
        for match in matches
        if match["project_purl"]
    }
    return binary_detected, binary_evidence
