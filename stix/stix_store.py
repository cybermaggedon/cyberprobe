
from gmt import GMT
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
import libtaxii.taxii_default_query as tdq
import datetime

class STIXSender(threading.Thread):

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

class STIXStore:

    def __init__(s, dbname, initialise=False):
        s.dbname = dbname
        s.conn = sqlite3.connect(s.dbname)

        if initialise:
            s.initialise()

        s.senders = {}
        s.senders_lock = threading.Lock()

        s.subscriptions = {}

    def restart_subscriptions(s):

        c = s.conn.cursor()
        
        try:

            c.execute("SELECT id, active, query, url, collection "
                      "FROM subscription")

            while True:

                row = c.fetchone()

                if row == None: break

                query = tdq.DefaultQuery.from_xml(row[2])

                s.subscribe_impl(row[0], query, row[4], row[3])

        except: pass

    def __del__(s):
        s.senders_lock.acquire()
        for sndr in s.senders:
            s.senders[sndr].stop()
            s.senders[sndr].join()
        s.senders_lock.release()

    def get_collections(s):

        c = s.conn.cursor()

        c.execute("SELECT DISTINCT collection FROM collection")

        collections = []

        while True:

            row = c.fetchone()

            if row == None: break

            collections.append(row[0])

        return collections

    def get_documents(s, collection):

        c = s.conn.cursor()

        c.execute("SELECT content.id, time FROM content, collection "
                  "WHERE content.id = collection.id AND collection = ?", 
                  (collection,))

        docs = []

        return c.fetchall()

    def get_document(s, id):

        c = s.conn.cursor()

        c.execute("SELECT content FROM content WHERE id = ?", (id,))

        row = c.fetchone()

        if row == None:
            raise ValueError("No such document")

        return row[0]

    def subscribe(s, query, collection, url):

        id = str(uuid.uuid1())

        c = s.conn.cursor()

        if query == None:
            query_xml = ""
        else:
            query_xml = query.to_xml()

        c.execute("INSERT INTO subscription VALUES (?, ?, ?, ?, ?)",
                  (id, 1, query_xml, url, collection))
        s.conn.commit()

        s.subscribe_impl(id, query, collection, url)

        return id

    def subscribe_impl(s, id, query, collection, url):

        s.senders_lock.acquire()

        if not s.subscriptions.has_key(collection):
            s.subscriptions[collection] = {}

        s.subscriptions[collection][id] = {}
        s.subscriptions[collection][id]["active"] = True
        s.subscriptions[collection][id]["query"] = query
        s.subscriptions[collection][id]["collection"] = collection
        s.subscriptions[collection][id]["url"] = url
        s.subscriptions[collection][id]["id"] = id

        thr = STIXSender(s.dbname, s.subscriptions[collection][id])
        s.senders[id] = thr
        thr.start()

        s.senders_lock.release()

    def destroy(s):

        try: s.conn.execute("DROP TABLE collection");
        except: pass

        try: s.conn.execute("DROP TABLE content");
        except: pass

        try: s.conn.execute("DROP TABLE subscription");
        except: pass

        try: s.conn.execute("DROP TABLE push_queue");
        except: pass

    def initialise(s):

        s.conn.execute("CREATE TABLE IF NOT EXISTS collection "
                       "(id text, collection text)");

        s.conn.execute("CREATE TABLE IF NOT EXISTS content "
                       "(id text, time real, content text)");

        s.conn.execute("CREATE TABLE IF NOT EXISTS subscription "
                       "(id text, active integer, query text, url text,"
                       "collection text)")

        s.conn.execute("CREATE TABLE IF NOT EXISTS push_queue "
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
                ret = TaxiiDefaultQuery.apply_query_criteria(query.criteria, 
                                                             doc)

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

        return id

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

    def get_matching(s, collection, begin, end, query, fn):

        docs = s.get_documents(collection)

        # Get the time (now)
        now = datetime.datetime.now(GMT())

        # Start constructing the content block list
        matches = []

        # Need to record the newest timestamp of all the data files, this 
        # variable keeps track.
        latest = None

        # Iterate over file list.
        for doc in docs:

            # Stat in order to get the last modification time.
            then = datetime.datetime.fromtimestamp(float(doc[1]), GMT())

            # Check whether file's modification time falls within the
            # begin/end bounds.
            if begin:
                if begin >= then:
                    continue
            if end:
                if end < then:
                    continue

            # Open the file and read contents.
            content = s.get_document(doc[0])

            if query != None:

                # Parse XML
                content_xml = etree.parse(StringIO(content))

                ret = TaxiiDefaultQuery.apply_query_criteria(query.criteria, 
                                                             content_xml)

                if not ret:
                    continue

            # Keep the 'latest' time up to date.
            if latest == None or then > latest:
                latest = then

            fn(content, doc[0])

        # If there's no latest (i.e. there were no content blocks in scope,
        # then use current time.
        if latest == None:
            latest = now

        return latest
