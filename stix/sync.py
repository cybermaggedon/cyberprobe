
import time
import sys
import os
import sqlite3

import stix_store

class Synchroniser:

    def add(s, item):
        pass

    def remove(s, item):
        pass

    def get_external(s):
        return set()

    def get_internal(s):
        return set()

    def check(s):

        external = s.get_external()
        internal = s.get_internal()

        added = external.difference(internal)
        removed = internal.difference(external)

        for item in removed:
            s.remove(item)

        for item in added:
            s.add(item)

class DbSynchroniser(Synchroniser):

    def __init__(s, dir, db):

        s.dir = dir
        s.db = db

    def remove_internal(s, id):
        print "Delete", id
        pass

    def add_internal(s, file):
        id = "FIXME: Need id."
        print "Add", file, id
        return id

    def remove(s, item):
        conn = sqlite3.connect(s.db)
        c = conn.cursor()

        c.execute("SELECT id FROM sync WHERE file = ?", (item[0],))
        r = c.fetchone()
        id = r[0]

        s.remove_internal(id)

        c.execute("DELETE FROM sync WHERE file = ?", (item[0],))
        conn.commit()

    def add(s, item):
        id = s.add_internal(item[0])
        conn = sqlite3.connect(s.db)
        c = conn.cursor()
        c.execute("INSERT INTO sync VALUES (?, ?, ?)", (id, item[0], item[1]))
        conn.commit()

    def initialise(s):
        
        conn = sqlite3.connect(s.db)
        c = conn.cursor()

        c.execute("CREATE TABLE IF NOT EXISTS sync "
                  "(id text, file text, time real)")

        conn.commit()

    def get_external(s):

        external = set()

        for dir in os.listdir(s.dir):

            dir = os.path.join(s.dir, dir)

            for file in os.listdir(dir):
                file = os.path.join(dir, file)
                external.add((file, os.stat(file).st_mtime))

        return external

    def get_internal(s):

        conn = sqlite3.connect(s.db)
        c = conn.cursor()
        c.execute("SELECT file, time FROM sync");

        internal = set()
        while True:
            r = c.fetchone()
            if r == None: break
            internal.add((r[0], r[1]))

        return internal

