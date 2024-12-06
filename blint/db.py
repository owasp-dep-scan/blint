# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import concurrent.futures
import sqlite3
import os
from contextlib import closing
from pathlib import Path
from rich.progress import Progress

import concurrent

def get_bnames_ename(symbols_name):
    bin_name = []
    eid = get_export_id(symbols_name)
    bid_list = get_bid_using_fid(eid)
    if bid_list:
        # TODO: voting algorithm goes here
        bin_name.extend(get_bname(bid) for bid in bid_list)
    return bin_name

def return_binaries_detected(eid):
    binaries_detected_dict = {}
    bid_list = get_bid_using_fid(eid)
    if not bid_list:
        return {}
    bid_list = list(bid_list)
    score = 1/len(bid_list)
    for bid in bid_list:
        bname = get_bname(bid)
        if bname in binaries_detected_dict:
            binaries_detected_dict[bname] += score
        else:
            binaries_detected_dict[bname] = score
    return binaries_detected_dict

def detect_binaries_utilized(sybmols_list) -> set:
    # Simple Voting algorithm
    # for a given symbols. e.g. XRenderAddGlyphs
    # we count the number of binaries associated to this function
    # e.g. which is one in this example XRenderAddGlyphs is associated with 'libXrender-0.9.10/libxrender.so'.
    # so one is added to score, we want all the detections to have a score greater than 1.
    bin_detected_dict = {}

    eid_list = [get_export_id(symbol['name']) for symbol in sybmols_list]
    # for eid in eid_list:
    with concurrent.futures.ProcessPoolExecutor(max_workers=13) as executor:
        for single_eid, single_binaries_detected_dict in zip(eid_list, executor.map(return_binaries_detected, eid_list)):
            
            for fname, score in single_binaries_detected_dict.items():
                if fname in bin_detected_dict:
                    bin_detected_dict[fname] += score
                else:
                    bin_detected_dict[fname] = score
            # TODO: remove these
            # print(f"completed for: {single_eid}")

    # create a 
    binary_detected = {bname for bname, score in bin_detected_dict.items() if score > 1}

    # TODO: remove
    for b in binary_detected:
        print(f"{b}: {bin_detected_dict[b]}")
    
    return binary_detected


def get_export_id(export_name):
    BLINTDB_LOC = os.getenv("BLINTDB_LOC")
    with closing(sqlite3.connect(BLINTDB_LOC)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT rowid from Exports where infunc=?", (export_name,))
            res = c.fetchall()
        connection.commit()
    return res[0][0] if res else None


def get_bid_using_fid(eid):
    BLINTDB_LOC = os.getenv("BLINTDB_LOC")
    with closing(sqlite3.connect(BLINTDB_LOC)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT bid from BinariesExports where eid=?", (eid,))
            res = c.fetchall()
        connection.commit()
    return map(lambda x: x[0], res) if res else None


def get_bname(bid):
    BLINTDB_LOC = os.getenv("BLINTDB_LOC")
    with closing(sqlite3.connect(BLINTDB_LOC)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT bname from Binaries where bid=?", (bid,))
            res = c.fetchall()
        connection.commit()
    return res[0][0] if res else None


def get_pname(bid):
    BLINTDB_LOC = os.getenv("BLINTDB_LOC")
    with closing(sqlite3.connect(BLINTDB_LOC)) as connection:
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
        connection.commit()
    return res[0][0]


def get_pname_bname(bname):
    BLINTDB_LOC = os.getenv("BLINTDB_LOC")
    with closing(sqlite3.connect(BLINTDB_LOC)) as connection:
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
        connection.commit()
    return res[0][0]
