
from stix_store import STIXStore
import libtaxii.taxii_default_query as tdq
import libtaxii as t
from taxii_client import TaxiiClient

s = STIXStore("data")

f = open("data/default/1", "r")
content = f.read()
f.close()

s.add_content(content, "bunchy")

f = open("data/default/2", "r")
content = f.read()
f.close()

s.add_content(content, "bunchy")

print(s.get_collections())

print(s.get_documents("bunchy"))

target = "//Information_Source/Identity/@idref"
value = "source:bunchy"
params = {'value':value, 'match_type': 'case_sensitive_string'}
test = tdq.DefaultQuery.Criterion.Test(capability_id=tdq.CM_CORE,
                                       relationship='equals', 
                                       parameters=params)
cron = tdq.DefaultQuery.Criterion(target=target, test=test, 
                                  negate=False)
criterion = [cron]
criteria = tdq.DefaultQuery.Criteria(operator=tdq.OP_AND, 
                                     criterion=criterion)
qry=tdq.DefaultQuery(t.CB_STIX_XML_11, criteria)

def printme(content, file):
    print("MATCH: ", file)

s.get_matching("bunchy", None, None, qry, printme)

tc = TaxiiClient()

ret = tc.perform_poll(collection="bunchy")
for r in ret:
    print("PACKAGE", r.id_)


