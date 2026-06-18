from collections import defaultdict

from blint.logger import LOG


def coerce_rule_bool(value) -> bool:
    """Parse review-rule booleans defensively from YAML-like values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes", "1", "on"):
            return True
        if normalized in ("false", "no", "0", "off", ""):
            return False
        LOG.debug(
            "Unrecognized boolean string value %r in review rule; defaulting to False",
            value,
        )
        return False
    return bool(value)


def coerce_min_patterns(value) -> int:
    """Parse the minimum distinct pattern count safely, defaulting to 1."""
    try:
        return max(int(value), 1)
    except (TypeError, ValueError):
        return 1


def run_pattern_reviews(
    review_list,
    candidate_values,
    evidence_limit,
    *,
    informative_values=None,
):
    """Run pattern-based METHOD/EXE/SYMBOL/IMPORT/ENTRY reviews."""
    results = defaultdict(list)
    found_cid = defaultdict(int)
    found_pattern = defaultdict(int)
    found_function = {}
    informative_values = informative_values or []
    if not review_list:
        return results

    for review_methods in review_list:
        for cid, rule_obj in review_methods.items():
            if found_cid[cid] >= evidence_limit:
                continue
            patterns = rule_obj.get("patterns") or []
            exclude_patterns = [p.lower() for p in (rule_obj.get("exclude_patterns") or [])]
            min_patterns = coerce_min_patterns(rule_obj.get("min_patterns", 1))
            allow_shared_matches = coerce_rule_bool(rule_obj.get("allow_shared_matches"))
            include_informative_strings = coerce_rule_bool(
                rule_obj.get("include_informative_strings")
            )
            searchable_values = (
                candidate_values + informative_values
                if include_informative_strings
                else candidate_values
            )
            rule_results = []
            rule_matched_patterns = set()
            rule_matched_values = {}

            for pattern in patterns:
                if found_pattern[pattern] >= evidence_limit or found_cid[cid] >= evidence_limit:
                    continue
                for candidate in searchable_values:
                    candidate_lower = candidate.lower()
                    if exclude_patterns and any(ex in candidate_lower for ex in exclude_patterns):
                        continue
                    if (
                        pattern.lower() in candidate_lower
                        and (allow_shared_matches or not found_function.get(candidate_lower))
                        and not rule_matched_values.get(candidate_lower)
                    ):
                        rule_results.append(
                            {
                                "pattern": pattern,
                                "function": candidate,
                            }
                        )
                        rule_matched_patterns.add(pattern)
                        rule_matched_values[candidate_lower] = True
                        break
            if len(rule_matched_patterns) < min_patterns:
                continue
            remaining = max(evidence_limit - found_cid[cid], 0)
            for result in rule_results[:remaining]:
                results[cid].append(result)
                found_cid[cid] += 1
                found_pattern[result["pattern"]] += 1
                if not allow_shared_matches:
                    found_function[result["function"].lower()] = True
    return results


def build_special_symbol_review(symbol_names, cid, evidence_limit):
    """Build simple pattern=function evidence for special-case symbol reviews."""
    results = defaultdict(list)
    for symbol_name in symbol_names[0:evidence_limit]:
        results[cid].append({"pattern": symbol_name, "function": symbol_name})
    return results


def build_pii_review_results(metadata, evidence_limit):
    """Build the legacy PII_READ review result set from metadata."""
    pii_names = [f.get("name", "") for f in metadata.get("pii_symbols", [])]
    return build_special_symbol_review(pii_names, "PII_READ", evidence_limit)


def build_loader_symbol_review_results(metadata, evidence_limit):
    """Build the legacy LOADER_SYMBOLS review result set from metadata."""
    loader_names = [f.get("name", "") for f in metadata.get("first_stage_symbols", [])]
    return build_special_symbol_review(loader_names, "LOADER_SYMBOLS", evidence_limit)
