import re

from blint.lib.analysis import (
    EVIDENCE_LIMIT,
    review_entries_dict,
    review_exe_dict,
    review_functions_dict,
    review_imports_dict,
    review_methods_dict,
    review_rules_cache,
    review_symbols_dict,
)
from blint.lib.function_reviews import review_disassembled_functions
from blint.lib.review_utils import (
    build_loader_symbol_review_results,
    build_pii_review_results,
    run_pattern_reviews,
)
from blint.logger import LOG


class ReviewRunner:
    """Class for running reviews."""

    def __init__(self):
        self.results = {}
        self.review_methods_list = []
        self.review_exe_list = []
        self.review_symbols_list = []
        self.review_imports_list = []
        self.review_entries_list = []
        self.review_functions_list = []

    def run_review(self, metadata):
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
        self._gen_review_lists(exe_type)
        if (
            self.review_methods_list
            or self.review_exe_list
            or self.review_symbols_list
            or self.review_imports_list
            or self.review_entries_list
            or self.review_functions_list
        ):
            return self._review_lists(metadata)
        self.results |= build_loader_symbol_review_results(metadata, EVIDENCE_LIMIT)
        return self.results

    def _review_lists(self, metadata):
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
        self.results |= build_pii_review_results(metadata, EVIDENCE_LIMIT)
        self.results |= build_loader_symbol_review_results(metadata, EVIDENCE_LIMIT)
        return self.results

    def _review_imports(self, metadata):
        """Reviews imports in the metadata."""
        imports_list = [f.get("name", "") for f in metadata.get("imports", [])]
        LOG.debug(f"Reviewing {len(imports_list)} imports")
        self.run_review_methods_symbols(self.review_imports_list, imports_list)

    def _review_entries(self, metadata):
        """Reviews dynamic entries in the metadata."""
        entries_list = [
            f.get("name", "")
            for f in metadata.get("dynamic_entries", [])
            if f.get("tag") == "NEEDED"
        ]
        LOG.debug(f"Reviewing {len(entries_list)} dynamic entries")
        self.run_review_methods_symbols(self.review_entries_list, entries_list)

    def _review_symbols_exe(self, metadata):
        """Reviews symbols in the metadata."""
        symbols_list = [f.get("name", "") for f in metadata.get("dynamic_symbols", [])]
        symbols_list += [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        LOG.debug(f"Reviewing {len(symbols_list)} symbols")
        if self.review_symbols_list:
            self.run_review_methods_symbols(self.review_symbols_list, symbols_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(self.review_exe_list, symbols_list)

    def _review_functions(self, metadata):
        """Reviews disassembled functions based on their behavioural metadata."""
        disassembled_functions = metadata.get("disassembled_functions")
        if not disassembled_functions:
            return

        LOG.debug(f"Reviewing {len(disassembled_functions)} disassembled functions")
        results = review_disassembled_functions(
            self.review_functions_list,
            disassembled_functions,
            EVIDENCE_LIMIT,
        )
        self.results |= results

    def _methods_or_exe(self, metadata):
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

    def _gen_review_lists(self, exe_type):
        """Generates the review lists based on the given executable type."""
        self.review_methods_list = review_methods_dict.get(exe_type)
        self.review_exe_list = review_exe_dict.get(exe_type)
        self.review_symbols_list = review_symbols_dict.get(exe_type)
        self.review_imports_list = review_imports_dict.get(exe_type)
        self.review_entries_list = review_entries_dict.get(exe_type)
        self.review_functions_list = review_functions_dict.get(exe_type)

    def process_review(self, f, exe_name):
        """Processes the review results for the given executable and review."""
        reviews = []
        if not self.results:
            return []
        for cid, evidence in self.results.items():
            aresult = {
                **review_rules_cache.get(cid),
                "evidence": evidence,
                "filename": f,
                "exe_name": exe_name,
            }
            if "patterns" in aresult:
                del aresult["patterns"]
            reviews.append(aresult)
        return reviews

    def run_review_methods_symbols(self, review_list, functions_list, informative_values=None):
        """Runs a review of methods and symbols based on the provided lists."""
        results = run_pattern_reviews(
            review_list,
            functions_list,
            EVIDENCE_LIMIT,
            informative_values=informative_values,
        )
        self.results |= results
