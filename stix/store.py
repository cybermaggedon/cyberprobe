
import uuid
from stix.core import STIXPackage
import sqlite3
import threading
from StringIO import StringIO
import time
from urlparse import urlparse
from taxii_client import TaxiiClient
from taxii_query import TaxiiDefaultQuery
from lxml import etree

class Sender(threading.Thread):

    def __init__(s, dbname, subscription):
        s.running = True
        s.dbname = dbname
        s.subscription = subscription
        s.cond = threading.Condition()
        threading.Thread.__init__(s)

    def stop(s):
        s.running = False
        s.cond.acquire()
        s.cond.notify()
        s.cond.release()

    def publish(s, content, collection, url):
        u = urlparse(url)
        c = TaxiiClient(u.hostname, u.port)
        c.push(collection=collection, content=content)

    def run(s):

        s.conn = sqlite3.connect(s.dbname)

        c = s.conn.cursor()

        s.cond.acquire()

        while s.running:
            s.cond.wait()

            if not s.running: break

            c.execute("SELECT id FROM push_queue WHERE subs_id = ?", 
                      (s.subscription["id"],))

            while True:

                row = c.fetchone()

                if row == None: break

                c2 = s.conn.cursor()
                c2.execute("SELECT content FROM content WHERE id = ?", 
                           (row[0],))
                row2 = c2.fetchone()

                s.publish(row2[0], s.subscription["collection"], 
                          s.subscription["url"])

                c.execute("DELETE FROM push_queue WHERE id = ? AND subs_id = ?",
                          (row[0], s.subscription["id"]))

                s.conn.commit()

        s.cond.release()

class Store:

    def __init__(s, dbname):
        s.dbname = dbname
        s.conn = sqlite3.connect(s.dbname)

        s.senders = {}
        s.senders_lock = threading.Lock()

        s.subscriptions = {}

        s.query_engine = TaxiiDefaultQuery()

    def __del__(s):
        s.senders_lock.acquire()
        for sndr in s.senders:
            s.senders[sndr].stop()
            s.senders[sndr].join()
        s.senders_lock.release()

    def subscribe(s, query, collection, url):

        id = str(uuid.uuid1())

        if not s.subscriptions.has_key(collection):
            s.subscriptions[collection] = {}

        s.subscriptions[collection][id] = {}
        s.subscriptions[collection][id]["active"] = True
        s.subscriptions[collection][id]["query"] = query
        s.subscriptions[collection][id]["collection"] = collection
        s.subscriptions[collection][id]["url"] = url
        s.subscriptions[collection][id]["id"] = id

        c = s.conn.cursor()

        if query == None:
            query = ""
        else:
            query = query.to_xml()

        c.execute("INSERT INTO subscription VALUES (?, ?, ?, ?, ?)",
                  (id, 1, query, url, collection))
        s.conn.commit()

        s.senders_lock.acquire()
        thr = Sender(s.dbname, s.subscriptions[collection][id])
        s.senders[id] = thr
        thr.start()
        s.senders_lock.release()

        return id

    def initialise(s):

        try: s.conn.execute("DROP TABLE collection");
        except: pass

        try: s.conn.execute("DROP TABLE content");
        except: pass

        try: s.conn.execute("DROP TABLE subscription");
        except: pass

        try: s.conn.execute("DROP TABLE push_queue");
        except: pass

        s.conn.execute("CREATE TABLE collection "
                       "(id text, collection text)");

        s.conn.execute("CREATE TABLE content "
                       "(id text, time real, content text)");

        s.conn.execute("CREATE TABLE subscription "
                       "(id text, active integer, query text, url text,"
                       "collection text)")

        s.conn.execute("CREATE TABLE push_queue "
                       "(id text, subs_id text)")

    def store(s, content, collections):
        
        # Parse XML
        doc = etree.parse(StringIO(content))
        package = STIXPackage.from_xml(StringIO(content))
        id = str(uuid.uuid1())
        c = s.conn.cursor()
        c.execute("INSERT INTO content VALUES (?, ?, ?)", 
                  (id, time.time(), content))

        for collection in collections:
            c.execute("INSERT INTO collection VALUES (?, ?)", (id, collection))

        senders = []

        for collection in collections:
            
            if not s.subscriptions.has_key(collection): continue

            for subs in s.subscriptions[collection]:

                subs_id = s.subscriptions[collection][subs]["id"]
                query = s.subscriptions[collection][subs]["query"]

                # Apply query here.
                ret = s.query_engine.apply_query_criteria(query.criteria, doc)

                if not ret:
                    continue

                c.execute("INSERT INTO push_queue VALUES (?, ?)", 
                          (id, subs_id))

                senders.append(subs_id)

        s.conn.commit()

        s.senders_lock.acquire()

        for sender in senders:

            s.senders[sender].cond.acquire()
            s.senders[sender].cond.notify()
            s.senders[sender].cond.release()

        s.senders_lock.release()

    def unsubscribe(s, id):

        s.senders_lock.acquire()

        if s.senders.has_key(id):
            
            collection = s.senders[id].subscription["collection"]

            s.senders[id].stop()
            s.senders[id].join()
            del s.senders[id]
            del s.subscriptions[collection][id]

            c = s.conn.cursor()

            c.execute("DELETE FROM subscription WHERE id = ?", (id,))

            s.conn.commit()

        s.senders_lock.release()

