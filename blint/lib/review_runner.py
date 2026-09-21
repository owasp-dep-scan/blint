import re
from typing import Any

from blint.lib.analysis import (
    EVIDENCE_LIMIT,
    review_binary_dict,
    review_entries_dict,
    review_exe_dict,
    review_functions_dict,
    review_imports_dict,
    review_methods_dict,
    review_rules_cache,
    review_symbols_dict,
)
from blint.lib.binary_reviews import review_binary_metadata
from blint.lib.function_reviews import review_disassembled_functions
from blint.lib.review_utils import (
    build_loader_symbol_review_results,
    build_pii_review_results,
    run_pattern_reviews,
)
from blint.logger import LOG

ReviewResults = dict[str, list[dict[str, str]]]


class ReviewRunner:
    """Class for running reviews."""

    def __init__(self) -> None:
        self.results: ReviewResults = {}
        self.review_methods_list: list[dict[str, Any]] | None = None
        self.review_exe_list: list[dict[str, Any]] | None = None
        self.review_symbols_list: list[dict[str, Any]] | None = None
        self.review_imports_list: list[dict[str, Any]] | None = None
        self.review_entries_list: list[dict[str, Any]] | None = None
        self.review_functions_list: list[dict[str, Any]] | None = None
        self.review_binary_list: list[dict[str, Any]] | None = None

    def run_review(self, metadata: dict[str, Any]) -> ReviewResults:
        """
        Runs a review of the given file and metadata.

        This function performs a review of the file and metadata based on the
        available review methods for the executable type. It collects the
        results from different review methods, including methods for functions,
        symbols, imports, and dynamic entries.

        Returns:
            dict[str, list]: Review results where the keys are the review
            method IDs and the values are lists of matching results.
        """
        if not review_methods_dict:
            LOG.warning("No review methods loaded!")
            return {}
        if not metadata or not (exe_type := metadata.get("exe_type")):
            return {}
        self._gen_review_lists(exe_type, metadata.get("binary_type") or "")
        if (
            self.review_methods_list
            or self.review_exe_list
            or self.review_symbols_list
            or self.review_imports_list
            or self.review_entries_list
            or self.review_functions_list
            or self.review_binary_list
        ):
            return self._review_lists(metadata)
        self.results |= build_loader_symbol_review_results(metadata, EVIDENCE_LIMIT)
        return self.results

    def _review_lists(self, metadata: dict[str, Any]) -> ReviewResults:
        """
        Reviews lists in the metadata and performs specific actions based on the
        review type.

        Args:
            metadata (dict): The metadata to review.

        Returns:
            dict: The results of the review.
        """
        if self.review_methods_list or self.review_exe_list:
            self._methods_or_exe(metadata)
        if self.review_symbols_list or self.review_exe_list:
            self._review_symbols_exe(metadata)
        if self.review_imports_list:
            self._review_imports(metadata)
        if self.review_entries_list:
            self._review_entries(metadata)
        if self.review_functions_list:
            self._review_functions(metadata)
        if self.review_binary_list:
            self._review_binary(metadata)
        self.results |= build_pii_review_results(metadata, EVIDENCE_LIMIT)
        self.results |= build_loader_symbol_review_results(metadata, EVIDENCE_LIMIT)
        return self.results

    def _review_imports(self, metadata: dict[str, Any]) -> None:
        """Reviews imports in the metadata."""
        imports_list = [f.get("name", "") for f in metadata.get("imports", [])]
        # W3.2: a managed assembly's import surface is its metadata — the
        # referenced types and members, the P/Invoke scopes, and the string
        # literals the IL loads. They ride the same pattern-review
        # machinery the native import table feeds.
        imports_list += self._dotnet_import_surface(metadata)
        LOG.debug(f"Reviewing {len(imports_list)} imports")
        self.run_review_methods_symbols(self.review_imports_list, imports_list)

    @staticmethod
    def _dotnet_import_surface(metadata: dict[str, Any]) -> list[str]:
        """Candidate values a managed assembly offers the import reviews.

        Each rendering is the one the managed rules match on: a TypeRef is
        its namespace-qualified name, a MemberRef its ``Type::member``, a
        P/Invoke entry its ``module::entry_point``. Everything is already
        a capped listing (pe_dotnet), so the candidate count is bounded.
        """
        dotnet = metadata.get("dotnet") or {}
        if not dotnet:
            return []
        values: list[str] = []
        for typeref in dotnet.get("typerefs") or []:
            values.append(typeref.get("name", ""))
        for memberref in dotnet.get("memberrefs") or []:
            parent = memberref.get("parent") or ""
            name = memberref.get("name") or ""
            values.append(f"{parent}::{name}" if parent else name)
        for entry in dotnet.get("pinvoke") or []:
            values.append(
                f"{entry.get('module', '')}::{entry.get('entry_point', '')}"
            )
        values.extend(dotnet.get("module_refs") or [])
        for item in metadata.get("strings") or []:
            value = item.get("value", "") if isinstance(item, dict) else str(item)
            values.append(value)
        return [v for v in values if v]

    def _review_entries(self, metadata: dict[str, Any]) -> None:
        """Reviews dynamic entries in the metadata."""
        entries_list = [
            f.get("name", "")
            for f in metadata.get("dynamic_entries", [])
            if f.get("tag") == "NEEDED"
        ]
        LOG.debug(f"Reviewing {len(entries_list)} dynamic entries")
        self.run_review_methods_symbols(self.review_entries_list, entries_list)

    def _review_symbols_exe(self, metadata: dict[str, Any]) -> None:
        """Reviews symbols in the metadata."""
        symbols_list = [f.get("name", "") for f in metadata.get("dynamic_symbols", [])]
        symbols_list += [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        # Objective-C runtime metadata: referenced selectors and external class
        # names are strong capability signals (e.g. CTTelephonyNetworkInfo,
        # AVCaptureSession) that never appear as plain symbols.
        if objc_metadata := metadata.get("objc_metadata"):
            symbols_list += objc_metadata.get("selectors", [])
            symbols_list += objc_metadata.get("external_classes", [])
        LOG.debug(f"Reviewing {len(symbols_list)} symbols")
        if self.review_symbols_list:
            self.run_review_methods_symbols(self.review_symbols_list, symbols_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(self.review_exe_list, symbols_list)

    def _review_functions(self, metadata: dict[str, Any]) -> None:
        """Reviews disassembled functions based on their behavioural metadata."""
        disassembled_functions = metadata.get("disassembled_functions")
        if not disassembled_functions:
            return

        LOG.debug(f"Reviewing {len(disassembled_functions)} disassembled functions")
        results = review_disassembled_functions(
            self.review_functions_list or [],
            disassembled_functions,
            EVIDENCE_LIMIT,
        )
        self.results |= results

    def _review_binary(self, metadata: dict[str, Any]) -> None:
        """Reviews whole-binary characteristics such as driver access control."""
        results = review_binary_metadata(
            self.review_binary_list,
            metadata,
            EVIDENCE_LIMIT,
        )
        self.results |= results

    def _methods_or_exe(self, metadata: dict[str, Any]) -> None:
        """Reviews method-like lists in the metadata."""
        functions_list = [
            re.sub(r"[*&()]", "", f.get("name", "")) for f in metadata.get("functions", [])
        ]
        if metadata.get("magic", "").startswith("PE"):
            functions_list += [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        if not functions_list and metadata.get("symtab_symbols"):
            functions_list = [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        informative_values = []
        for s in metadata.get("informative_strings", []):
            if isinstance(s, dict):
                value = s.get("value", "")
            else:
                value = str(s)
            if value:
                informative_values.append(value)
        LOG.debug(f"Reviewing {len(functions_list)} functions")
        if self.review_methods_list:
            self.run_review_methods_symbols(
                self.review_methods_list,
                functions_list,
                informative_values=informative_values,
            )
        if self.review_exe_list:
            self.run_review_methods_symbols(
                self.review_exe_list,
                functions_list,
                informative_values=informative_values,
            )

    def _gen_review_lists(self, exe_type: str, binary_type: str = "") -> None:
        """Generates the review lists based on the given executable type.

        Whole-binary reviews additionally accept rules registered under the
        *format* (``ELF``, ``PE``, ``MachO``). ``exe_type`` is a toolchain
        label — ``gobinary``, ``genericbinary``, or a ``machine-filetype``
        fallback such as ``x86_64-dyn`` — so a rule about a format's on-disk
        structure cannot enumerate the labels it must cover without guessing
        at machine names. Only BINARY_REVIEWS gets this: every other group
        keys off toolchain-specific evidence where the exact label matters.
        """
        self.review_methods_list = review_methods_dict.get(exe_type)
        self.review_exe_list = review_exe_dict.get(exe_type)
        self.review_symbols_list = review_symbols_dict.get(exe_type)
        self.review_imports_list = review_imports_dict.get(exe_type)
        self.review_entries_list = review_entries_dict.get(exe_type)
        self.review_functions_list = review_functions_dict.get(exe_type)
        binary_rules = list(review_binary_dict.get(exe_type) or [])
        if binary_type and binary_type != exe_type:
            binary_rules += review_binary_dict.get(binary_type) or []
        self.review_binary_list = binary_rules or None

    def process_review(self, f: str, exe_name: str) -> list[dict[str, Any]]:
        """Processes the review results for the given executable and review."""
        reviews: list[dict[str, Any]] = []
        if not self.results:
            return []
        for cid, evidence in self.results.items():
            aresult = {
                **(review_rules_cache.get(cid) or {}),
                "evidence": evidence,
                "filename": f,
                "exe_name": exe_name,
            }
            aresult.pop("patterns", None)
            reviews.append(aresult)
        return reviews

    def run_review_methods_symbols(
        self,
        review_list: list[dict[str, Any]] | None,
        functions_list: list[str],
        informative_values: list[str] | None = None,
    ) -> None:
        """Runs a review of methods and symbols based on the provided lists."""
        results = run_pattern_reviews(
            review_list,
            functions_list,
            EVIDENCE_LIMIT,
            informative_values=informative_values,
        )
        self.results |= results
