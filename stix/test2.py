
import libtaxii.taxii_default_query as tdq
import threading
import store
import time
import sys

dbname = "bunchy.db"

stor = store.Store(dbname)

stor.initialise()

f = open('out1', 'r')
content1 = f.read()
f.close()

f = open('out2', 'r')
content2 = f.read()
f.close()

query1="""
    <taxii_11:Query format_id="urn:taxii.mitre.org:query:default:1.0" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1">
      <tdq:Default_Query xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" targeting_expression_id="urn:stix.mitre.org:xml:1.1">
        <tdq:Criteria operator="AND">
          <tdq:Criterion negate="false">
            <tdq:Target>//Address_Value</tdq:Target>
            <tdq:Test capability_id="urn:taxii.mitre.org:query:capability:core-1" relationship="equals">
              <tdq:Parameter name="match_type">case_sensitive_string</tdq:Parameter>
              <tdq:Parameter name="value">malware@malware.com</tdq:Parameter>
            </tdq:Test>
          </tdq:Criterion>
        </tdq:Criteria>
      </tdq:Default_Query>
    </taxii_11:Query>
"""

query2="""
    <taxii_11:Query format_id="urn:taxii.mitre.org:query:default:1.0" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1">
      <tdq:Default_Query xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" targeting_expression_id="urn:stix.mitre.org:xml:1.1">
        <tdq:Criteria operator="AND">
          <tdq:Criterion negate="false">
            <tdq:Target>//Information_Source/Identity/@idref</tdq:Target>
            <tdq:Test capability_id="urn:taxii.mitre.org:query:capability:core-1" relationship="equals">
              <tdq:Parameter name="match_type">case_sensitive_string</tdq:Parameter>
              <tdq:Parameter name="value">source:bunchy</tdq:Parameter>
            </tdq:Test>
          </tdq:Criterion>
        </tdq:Criteria>
      </tdq:Default_Query>
    </taxii_11:Query>
"""

query1 = tdq.DefaultQuery.from_xml(query1)
query2 = tdq.DefaultQuery.from_xml(query2)
try:

    subs_id1 = stor.subscribe(query1, collection="default", 
                              url="http://localhost:8080");

    subs_id2 = stor.subscribe(query2, collection="default", 
                              url="http://localhost:8081");

    for i in range(0, 40):
        stor.store(content1, ['default', 'bunchy'])

    for i in range(0, 40):
        stor.store(content2, ['default', 'bunchy'])

    stor.unsubscribe(subs_id1)
    stor.unsubscribe(subs_id2)

    stor = None

except KeyboardInterrupt:

    print "Interrupt."

sys.exit(0)
