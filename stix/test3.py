#!/usr/bin/env python

import libtaxii as t
import libtaxii.messages_11 as tm11
import BaseHTTPServer
import time
from stix.core import STIXPackage, STIXHeader
import StringIO
import argparse
import libtaxii.taxii_default_query as tdq
from lxml import etree
import sys
import gmt
from stix_store import STIXStore
from taxii_server import TAXIIHandler, TAXIIServer

# Uses a directory containing STIX documents.  Directory structure is...
#   <data_dir/<collection>/<document>

############################################################################
# Request handler
############################################################################
class Handler(TAXIIHandler):

    def received(s, content, collection):

        # Hack XML header on.
        package = STIXPackage.from_xml(StringIO.StringIO(content))
        print "Received",package.id_

    # Handling a TAXII PollRequest
    def get_matching(s, collection, begin, end, query, handle):
        pass
#        return s.store.get_matching(collection, begin, end, query, handle)


class CollectionManager:

    def __init__(s, data_dir):
        pass

############################################################################
# Main body
############################################################################

# Parse command line arguments
p = argparse.ArgumentParser(description="TAXII server")
p.add_argument("--host", dest="host", default="localhost", 
               help="Host to start the HTTP service on. "
               "Defaults to localhost.")
p.add_argument("--port", dest="port", default="8080", 
               help="Port where the Poll Service is hosted. Defaults to "
               "8080.")
p.add_argument("--data_dir", dest="data_dir", default="data/", 
               help="Directory where the STIX data is stored. Defaults to "
               "'data'.")
args = p.parse_args()

Handler.store = STIXStore(args.data_dir)

# Construct HTTP server
server = TAXIIServer(args.host, int(args.port), Handler)
server.run()

