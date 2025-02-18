# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import concurrent
import concurrent.futures
import os
import sys
from contextlib import closing

import apsw

from blint.logger import LOG

DEBUG_MODE = os.getenv("SCAN_DEBUG_MODE") == "debug"
db_conn: apsw.Connection = None
DB_FILE_SEP = "///" if sys.platform == "win32" else "//"

def get(db_file: str = os.getenv("BLINTDB_LOC"), read_only=True) -> apsw.Connection:
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
    binaries_detected_dict = {}
    if type(symbols_list) != list:
        raise TypeError(f"Incorrect type symbols_lists should be List not {type(symbols_list)}")

    # Errors not being caught here
    output_list = get_bid_using_ename_batch(symbols_list)

    eid_list = [it[0] for it in output_list]
    bid_2d_list = [it[1] for it in output_list]
    for it in range(len(eid_list)):
        bid_list = bid_2d_list[it].split(",")
        score = 1 / len(bid_list)
        for bid in bid_list:
            bname = get_bname(bid)
            if bname in binaries_detected_dict:
                binaries_detected_dict[bname] += score
            else:
                binaries_detected_dict[bname] = score
    return binaries_detected_dict


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
            # print(output_string)
            c.execute(output_string, batch_export_name)
        res = c.fetchall()
    return res


def get_bname(bid):
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
    with closing(connection.cursor()) as c:
        c.execute("SELECT bname from Binaries where bid=?", (bid,))
        res = c.fetchall()
    return res[0][0] if res else None


def detect_binaries_utilized(sybmols_list) -> set:
    """Simple Voting algorithm
    for a given symbols. e.g. XRenderAddGlyphs
    we count the number of binaries associated to this function
    e.g. which is one in this example XRenderAddGlyphs
    is associated with 'libXrender-0.9.10/libxrender.so'.
    so one is added to score, we want all the detections to have a score greater than 1.
    """
    bin_detected_dict = {}

    eid_list = [symbol["name"] for symbol in sybmols_list]
    # creates a 2D array with batch_len, batch_len eids are processed in a single query
    batch_len = 1000
    eid_2d_list = [eid_list[i : i + batch_len] for i in range(0, len(eid_list), batch_len)]

    LOG.debug(f"Created {len(eid_2d_list)} processes created")
    # for eid in eid_list:
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures_bin_detected = {
            executor.submit(return_batch_binaries_detected, it_eid_list): it_eid_list
            for it_eid_list in eid_2d_list
        }
        for future in concurrent.futures.as_completed(futures_bin_detected):
            single_binaries_detected_dict = future.result()
            for fname, score in single_binaries_detected_dict.items():
                if fname in bin_detected_dict:
                    bin_detected_dict[fname] += score
                else:
                    bin_detected_dict[fname] = score
    # create a set() and remove false positives
    binary_detected = {bname for bname, score in bin_detected_dict.items() if score > 1}

    LOG.debug(f"Output for binary_detected: {len(binary_detected)}")
    return binary_detected

def get_export_id(export_name):
    """Retrieves the export ID for a given export name from a SQLite database. The function performs a lookup to fetch the corresponding export identifier.

    This function connects to a SQLite database using the BLINTDB_LOC environment variable and executes a query to retrieve the export ID based on the provided export name. If no matching export is found, it returns None.

    Args:
        export_name (str): The name of the export to search for in the database.

    Returns:
        int or None: The export ID if found, otherwise None.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    with closing(connection.cursor()) as c:
        c.execute("SELECT rowid from Exports where infunc=?", (export_name,))
        res = c.fetchall()
    return res[0][0] if res else None


def get_bid_using_fid(eid):
    """Retrieves binary IDs associated with a specific export ID from a SQLite database. The function performs a lookup to fetch the corresponding binary identifiers.

    This function connects to a SQLite database using the BLINTDB_LOC environment variable and executes a query to retrieve binary IDs based on the provided export ID. If no matching binary IDs are found, it returns None.

    Args:
        eid (int): The export identifier to search for in the database.

    Returns:
        list or None: A list of binary IDs if found, otherwise None.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    with closing(connection.cursor()) as c:
        c.execute("SELECT bid from BinariesExports where eid=?", (eid,))
        res = c.fetchall()
    return map(lambda x: x[0], res) if res else None


def get_pname(bid):
    """Retrieves the project name associated with a given binary ID from a SQLite database. The function performs a two-step lookup to fetch the corresponding project name.

    This function connects to a SQLite database using the BLINTDB_LOC environment variable and executes queries to first find the project ID linked to the binary, and then retrieve the project name. If no matching project is found at either stage, it returns None.

    Args:
        bid (int): The binary identifier to search for in the database.

    Returns:
        str or None: The name of the project associated with the binary if found, otherwise None.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    with closing(connection.cursor()) as c:
        c.execute("SELECT pid from Binaries where bid=?", (bid,))
        res = c.fetchall()
        if not res:
            return None
        pid = res[0][0]
        c.execute("SELECT pname from Projects where pid=?", (pid,))
        res = c.fetchall()
        if not res:
            return None
    return res[0][0]


def get_pname_bname(bname):
    """Retrieves the project name associated with a given binary name from a SQLite database. The function performs a two-step lookup to fetch the corresponding project name.

    This function connects to a SQLite database using the BLINTDB_LOC environment variable and executes queries to first find the project ID linked to the binary name, and then retrieve the project name. If no matching project is found at either stage, it returns None.

    Args:
        bname (str): The binary name to search for in the database.

    Returns:
        str or None: The name of the project associated with the binary name if found, otherwise None.

    Raises:
        apsw.Error: If there are any database connection or query execution issues.
    """
    connection = get()
    if not connection:
        return None
    with closing(connection.cursor()) as c:
        c.execute("SELECT pid from Binaries where bname=?", (bname,))
        res = c.fetchall()
        if not res:
            return None
        pid = res[0][0]
        c.execute("SELECT pname from Projects where pid=?", (pid,))
        res = c.fetchall()
        if not res:
            return None
    return res[0][0]
