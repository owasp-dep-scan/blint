# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import concurrent
import concurrent.futures
from functools import lru_cache
import os
import sys
from contextlib import closing

import apsw

from blint.config import BLINTDB_LOC, MIN_MATCH_SCORE, SYMBOLS_LOOKUP_BATCH_LEN
from blint.logger import LOG

DEBUG_MODE = os.getenv("SCAN_DEBUG_MODE") == "debug"
db_conn: apsw.Connection = None
DB_FILE_SEP = "///" if sys.platform == "win32" else "//"


def get(db_file: str = BLINTDB_LOC, read_only=True) -> apsw.Connection:
    if not os.path.exists(db_file):
        return
    if not db_file.startswith("file:") and db_file != ":memory:":
        db_file = f"file:{DB_FILE_SEP}{os.path.abspath(db_file)}"
    global db_conn
    ro_flags = apsw.SQLITE_OPEN_URI | apsw.SQLITE_OPEN_NOFOLLOW | apsw.SQLITE_OPEN_READONLY
    db_conn = apsw.Connection(db_file, flags=ro_flags)
    return db_conn


def return_batch_binaries_detected(symbols_list):
    """
    Current scoring algorithm along with batching
    """
    # Detected binaries and their score
    binaries_detected_dict = {}
    # The export ids that led to the match
    binaries_eid_dict = {}
    if not isinstance(symbols_list, list):
        raise TypeError(f"Incorrect type symbols_lists should be List not {type(symbols_list)}")

    # Errors not being caught here
    output_list = get_bid_using_ename_batch(symbols_list)

    eid_list = [it[0] for it in output_list]
    bid_2d_list = [it[1] for it in output_list]
    for it in range(len(eid_list)):
        bid_list = bid_2d_list[it].split(",")
        score = 1 / len(bid_list)
        for bid in bid_list:
            matching_binaries = find_binary_from_db(bid)
            if matching_binaries:
                for (bname, pname, purl) in matching_binaries:
                    binaries_eid_dict[purl] = eid_list
                    if purl in binaries_detected_dict:
                        binaries_detected_dict[purl] += score
                    else:
                        binaries_detected_dict[purl] = score
    return binaries_detected_dict, binaries_eid_dict


def get_bid_using_ename_batch(batch_export_name):
    """Retrieves binary IDs associated with a batch of export names from a SQLite database.

    This function queries the database to find binary IDs linked to specific export names in a batch.
    It uses the BLINTDB_LOC environment variable to connect to the SQLite database and performs a grouped query.

    Args:
        batch_export_name (list): A list of export names to search for in the database.

    Returns:
        list: A list of tuples containing export IDs and their corresponding concatenated binary IDs.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    with closing(connection.cursor()) as c:
        place_holders = "?, " * (len(batch_export_name) - 1) + "?"
        if len(batch_export_name) > 0:
            output_string = f"SELECT eid, group_concat(bid) from BinariesExports where eid IN (SELECT rowid from Exports where infunc IN ({place_holders})) group by eid"
            c.execute(output_string, batch_export_name)
        res = c.fetchall()
    return res


@lru_cache(maxsize=1000)
def find_binary_from_db(bid):
    """Retrieves the binary name for a given binary ID from a SQLite database. The function performs a lookup to fetch the corresponding binary name.

    This function connects to a SQLite database using the BLINTDB_LOC environment variable and executes a query to retrieve the binary name based on the provided binary ID. If no matching binary is found, it returns None.

    Args:
        bid (int): The binary identifier to search for in the database.

    Returns:
        str or None: The name of the binary if found, otherwise None.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    res = connection.execute(
        "SELECT bname, pname, purl from Binaries JOIN Projects on Binaries.pid = Projects.pid WHERE Binaries.bid = ?",
        (bid,))
    return frozenset(res.fetchall())


def detect_binaries_utilized(symbols_list) -> tuple[set, dict]:
    """Simple Voting algorithm
    for a given symbols. e.g. XRenderAddGlyphs
    we count the number of binaries associated to this function
    e.g. which is one in this example XRenderAddGlyphs
    is associated with 'libXrender-0.9.10/libxrender.so'.
    so one is added to score, we want all the detections to have a score greater than MIN_MATCH_SCORE.
    """
    if not symbols_list:
        return set(), {}
    bin_detected_dict = {}
    binaries_eid_dict = {}
    eid_list = [symbol["name"] for symbol in symbols_list]
    LOG.debug(f"Attempting to find the binaries for {len(eid_list)} symbols.")
    # creates a 2D array with SYMBOLS_LOOKUP_BATCH_LEN, SYMBOLS_LOOKUP_BATCH_LEN eids are processed in a single query
    eid_2d_list = [eid_list[i: i + SYMBOLS_LOOKUP_BATCH_LEN] for i in range(0, len(eid_list), SYMBOLS_LOOKUP_BATCH_LEN)]

    # for eid in eid_list:
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures_bin_detected = {
            executor.submit(return_batch_binaries_detected, it_eid_list): it_eid_list
            for it_eid_list in eid_2d_list
        }
        for future in concurrent.futures.as_completed(futures_bin_detected):
            single_binaries_detected_dict, binaries_eid_dict = future.result()
            for purl, score in single_binaries_detected_dict.items():
                if purl in bin_detected_dict:
                    bin_detected_dict[purl] += score
                else:
                    bin_detected_dict[purl] = score
    # create a set() and remove false positives
    binary_detected = {purl for purl, score in bin_detected_dict.items() if score > MIN_MATCH_SCORE}
    binary_evidence_eids = {}
    for purl, eids in binaries_eid_dict.items():
        if purl in binary_detected:
            binary_evidence_eids[purl] = eids
    return binary_detected, binary_evidence_eids
