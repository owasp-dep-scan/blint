# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import sqlite3
import os
from contextlib import closing
from pathlib import Path

def get_bnames_ename(symbols_name):
    bin_name = []
    eid = get_export_id(symbols_name)
    bid_list = get_bid_using_fid(eid)
    if bid_list:
        # TODO: voting algorithm goes here
        bin_name.extend(get_bname(bid) for bid in bid_list)
    return bin_name

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
