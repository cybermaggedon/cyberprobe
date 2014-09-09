import sys
import argparse
import dateutil.parser
import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc
import libtaxii.taxii_default_query as tdq
from stix.core import STIXPackage, STIXHeader
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.port_object import Port
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
import StringIO
import datetime

class TaxiiClient:

    def __init__(s, host="localhost", port=8080):
        s.host = host
        s.port = port

    def create_query(s, query):

        criterion = []

        for q in query:

            type, value = q.split(":", 1)
            
            if type == "address":
                target = "//Address_Value"
            elif type == "addresstype":
                target = "//Object/Properties/@category"
            elif type == "hostname":
                target = "//Hostname_Value"
            elif type == "port":
                target = "//Port_Value"
            elif type == "hash":
                target = "//Hash/Simple_Hash_Value"
            elif type == "id":
                target = "/STIX_Package/@id"
            elif type == "source":
                target = "//Information_Source/Identity/@idref"
            else:
                raise TypeError("Don't understand type '" + type + "'")

            params = {'value':value, 'match_type': 'case_sensitive_string'}

            test = tdq.DefaultQuery.Criterion.Test(capability_id=tdq.CM_CORE,
                                                   relationship='equals', 
                                                   parameters=params)
            
            cron = tdq.DefaultQuery.Criterion(target=target, test=test, 
                                              negate=False)

            criterion.append(cron)

        criteria = tdq.DefaultQuery.Criteria(operator=tdq.OP_AND, 
                                         criterion=criterion)
        
        qry=tdq.DefaultQuery(t.CB_STIX_XML_11, criteria)

        return qry

    # Perform a TAXII poll
    def poll(s, path="/", collection="default", query=None, 
                     begin_ts=None, end_ts=None):
    
        if query != None:
            query=s.create_query(query)
            poll_params=tm11.PollRequest.PollParameters(query=query)
        else:
            poll_params=tm11.PollRequest.PollParameters()
            
        # Create poll request
        poll_req = tm11.PollRequest(message_id=tm11.generate_message_id(),
                                    collection_name=collection,
                                    exclusive_begin_timestamp_label=begin_ts,
                                    inclusive_end_timestamp_label=end_ts,
                                    poll_parameters=poll_params)
            
        # Convert to XML for request body
        poll_req_xml = poll_req.to_xml(True)

        # Create HTTP client
        client = tc.HttpClient()
        client.setProxy('noproxy') 

        # Call TAXII service, using the body
        resp = client.callTaxiiService2(s.host, path, 
                                        t.VID_TAXII_XML_11,
                                        poll_req_xml, s.port)
        
        # Get response
        resp = t.get_message_from_http_response(resp, '0')
            
        pkgs = []

        # Process each content block
        for cb in resp.content_blocks:
            
            content = cb.content
            
            # Hack an XML header on the top?! and add the payload body.
            content = "<?xml version=\"1.0\"?>\n" + content
            
            # Parse the payload, should be a STIX document.
            package = STIXPackage.from_xml(StringIO.StringIO(content))

            pkgs.append(package)
            
        return resp.inclusive_end_timestamp_label, pkgs

    # Perform a TAXII discovery
    def perform_discovery(path="/"):

        # Create discovery request
        req = tm11.DiscoveryRequest(message_id=tm11.generate_message_id())
        
        # Convert to XML for request body
        req_xml = req.to_xml()
        
        # Create HTTP client
        client = tc.HttpClient()
        client.setProxy('noproxy') 
        
        # Call TAXII service, using the body
        resp = client.callTaxiiService2(host, path, t.VID_TAXII_XML_11,
                                        req_xml, port)

        # Get response
        resp = t.get_message_from_http_response(resp, '0')
        
        print resp.to_xml()

    # Perform a TAXII CollecitonInformationRequest
    def perform_collection_information(path="/"):
            
        # Create discovery request
        msg_id=tm11.generate_message_id()
        req = tm11.CollectionInformationRequest(message_id=msg_id)
        
        # Convert to XML for request body
        req_xml = req.to_xml()
            
        # Create HTTP client
        client = tc.HttpClient()
        client.setProxy('noproxy') 
        
        # Call TAXII service, using the body
        resp = client.callTaxiiService2(host, path, t.VID_TAXII_XML_11,
                                        req_xml, port)

        # Get response
        resp = t.get_message_from_http_response(resp, '0')

        print resp.to_xml()
        
    def subscribe(s, path="/", collection="default", query=None):

        if query != None:
            query = s.create_query(query)
        else:
            query = None

        params = tm11.SubscriptionParameters(query=query)

        # Create request
        msg_id=tm11.generate_message_id()
        req = tm11.ManageCollectionSubscriptionRequest(
            message_id=msg_id,
            collection_name=collection,
            action=tm11.ACT_SUBSCRIBE,
            subscription_parameters=params
        )

        # Convert to XML for request body
        req_xml = req.to_xml()
        
        # Create HTTP client
        client = tc.HttpClient()
        client.setProxy('noproxy') 

        # Call TAXII service, using the body
        resp = client.callTaxiiService2(s.host, path, t.VID_TAXII_XML_11,
                                        req_xml, s.port)

        # Get response
        resp = t.get_message_from_http_response(resp, '0')

        print resp.to_xml()

    # Perform a TAXII ManageCollectionSubscription
    def perform_manage_collection_subscription(path="/", act="status",
                                               collection="default"):
        
        if act == "subscribe":
            action = tm11.ACT_SUBSCRIBE
        elif act == "unsubscribe":
            action = tm11.ACT_UNSUBSCRIBE
        elif act == "pause":
            action = tm11.ACT_PAUSE
        elif act == "resume":
            action = tm11.ACT_RESUME
        elif act == "status":
            action = tm11.ACT_STATUS
        else:
            print "Need a subscription action I recognise"
            sys.exit(1)

        # Create request
        msg_id=tm11.generate_message_id()
        req = tm11.ManageCollectionSubscriptionRequest(message_id=msg_id,
                                                       collection_name=collection,
                                                       action=action)

        # Convert to XML for request body
        req_xml = req.to_xml()

        # Create HTTP client
        client = tc.HttpClient()
        client.setProxy('noproxy') 

        # Call TAXII service, using the body
        resp = client.callTaxiiService2(host, path, t.VID_TAXII_XML_11,
                                        req_xml, port)

        # Get response
        resp = t.get_message_from_http_response(resp, '0')

        print resp.to_xml()
