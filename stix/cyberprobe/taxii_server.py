
import http.server
import time
import argparse

import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.taxii_default_query as tdq

# Uses a directory containing STIX documents.  Directory structure is...
#   <data_dir/<collection>/<document>

############################################################################
# TAXII request handler
############################################################################
class TAXIIHandler(http.server.BaseHTTPRequestHandler):

    def get_matching(s, collection, begin, end, query, handle):
        return None

    # Receive inbox data
    def received(s, content, collection):
        pass

    def subscribe(s, collection, query, inbox):
        raise NotImplementedError("Not implemented")

    # Send a TAXII response payload
    def respond(s, body):

        # Send HTTP response
        s.send_response(200)
        s.send_header("Content-type", "text/xml")
        s.send_header("Content-length", len(body))
        s.send_header("X-TAXII-Content-Type", 
                      "urn:taxii.mitre.org:message:xml:1.1")
        s.send_header("X-TAXII-Protocol", 
                      "urn:taxii.mitre.org:protocol:http:1.0")
        s.send_header("X-TAXII-Services", 
                      "urn:taxii.mitre.org:services:1.1")
        s.end_headers()
        s.wfile.write(body)

    # Handling a TAXII InboxMessage
    def handle_inbox_message(s, msg):

        # Process each content block
        for cb in msg.content_blocks:

            content = cb.content

            for collection in msg.destination_collection_names:
                
                s.received(content, collection)

        resp = tm11.StatusMessage(message_id=tm11.generate_message_id(),
                                  in_response_to=msg.message_id,
                                  status_type=tm11.ST_SUCCESS)

        # Respond
        s.respond(resp.to_xml())
    
    # Handling a TAXII PollRequest
    def handle_poll_request(s, msg):

        collection = msg.collection_name
        query = msg.poll_parameters.query
        begin = msg.exclusive_begin_timestamp_label
        end = msg.inclusive_end_timestamp_label

        # Start constructing the content block list
        cbs = []

        def handle(content, file):

            print("Adding %s..." % file)
    
            # Create content block.
            cb = tm11.ContentBlock(tm11.ContentBinding(t.CB_STIX_XML_11), 
                                   content)

            # Append content block to list.
            cbs.append(cb)

        print("Building response...")

        latest = s.get_matching(collection, begin, end, query, handle)

        print("Done")

        # Create poll response.
        resp = tm11.PollResponse(message_id=tm11.generate_message_id(),
                                 in_response_to=msg.message_id,
                                 collection_name=msg.collection_name,
                                 inclusive_end_timestamp_label=latest,
                                 content_blocks=cbs,
                                 more=False)

        # Send response
        s.respond(resp.to_xml())
        
    # Handling a TAXII DiscoveryRequest
    def handle_discovery_request(s, msg):
        
        # Create poll response.
        resp = tm11.DiscoveryResponse(message_id=tm11.generate_message_id(),
                                      in_response_to=msg.message_id)

        # Send response
        s.respond(resp.to_xml())

    # Handling a TAXII CollectionInformationRequest
    def handle_collection_information_request(s, msg):
        
        # Create poll response.
        msg_id=tm11.generate_message_id()
        resp = tm11.CollectionInformationResponse(message_id=msg_id,
                                      in_response_to=msg.message_id)

        # Send response
        s.respond(resp.to_xml())

    # Handling a TAXII CollectionInformationRequest
    def handle_manage_collection_subscription_request(s, msg):

        print(msg.to_xml(True))
        
        # Create poll response.
        msg_id=tm11.generate_message_id()
        cn=msg.collection_name
        resp_id=msg.message_id
        action=msg.action
        query=msg.subscription_parameters.query
        subs_id=msg.subscription_id
        inbox=msg.push_parameters.inbox_address

        if query:
            print(query.to_xml())

        if action == tm11.ACT_SUBSCRIBE:

            subs_id = s.subscribe(collection=cn, query=query, 
                                  inbox=inbox)

            si = tm11.ManageCollectionSubscriptionResponse.SubscriptionInstance(
                subscription_id=subs_id,
                status=tm11.SS_ACTIVE
            )

            resp = tm11.ManageCollectionSubscriptionResponse(
                message_id=msg_id,
                collection_name=cn,
                in_response_to=resp_id,
                subscription_instances=[si]
            )

            # Send response
            s.respond(resp.to_xml())

    # HTTP head request
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    # HTTP POST request
    def do_POST(s):

        # Get the HTTP bdoy
        varLen = int(s.headers['Content-Length'])
        data = s.rfile.read(varLen)

        # Parse body as TAXII message.
        msg = tm11.get_message_from_xml(data)

        # If it's a poll request, handle it.
        if type(msg) == tm11.PollRequest:
            s.handle_poll_request(msg)
            return

        if type(msg) == tm11.InboxMessage:
            s.handle_inbox_message(msg)
            return

        if type(msg) == tm11.DiscoveryRequest:
            s.handle_discovery_request(msg)
            return

        if type(msg) == tm11.CollectionInformationRequest:
            s.handle_collection_information_request(msg)
            return

        if type(msg) == tm11.ManageCollectionSubscriptionRequest:
            s.handle_manage_collection_subscription_request(msg)
            return

        # Sorry, I only handle inbox and poll requests.

        resp = tm11.StatusMessage(message_id=tm11.generate_message_id(),
                                  in_response_to=msg.message_id,
                                  status_type=tm11.ST_FAILURE,
                                  message="Your request type not supported.")
        s.respond(resp.to_xml())

############################################################################
# TAXII Server
############################################################################
class TAXIIServer(http.server.HTTPServer):

    def __init__(self, host, port, handler):
        self.host = host
        self.port = port
        http.server.HTTPServer.__init__(self, (host, port), handler)

    def run(self):
        print(time.asctime(), "Server Starts - %s:%d" % (self.host, self.port))

        # Serve indefinitely.
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            self.server_close()
            print(time.asctime(), "Server Stops - %s:%d" %
                  (self.host, self.port))

