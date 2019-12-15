
import uuid
import json
import cyberprobe.logictree as lt
import cyberprobe.fsm_extract as fsme

class Indicators:
    def __init__(self, description=None, version=None, indicators=[]):
        self.description = description
        self.version = version
        self.indicators = indicators
    def add_indicator(self, i):
        self.indicators.append(i)
    def get(self, id):
        for v in self.indicators:
            if v.id == id:
                return v
        raise RuntimeError("No such indicator ID")
    def dump(self):
        rval = {}
        if self.description: rval["description"] = self.description
        if self.version: rval["version"] = self.version
        rval["indicators"] = [
            v.dump() for v in self.indicators
        ]
        return rval
    def dumps(self):
        return json.dumps(self.dump(), indent=4)

class Descriptor:
    def __init__(self, description=None, category=None,
                 author=None, source=None, prob=1.0,
                 type=None, value=None):
        self.description = description
        self.category = category
        self.author = author
        self.source = source
        self.type = type
        self.value = value
    def dump(self):
        rval = {}
        if self.description is not None:
            rval["description"] = self.description
        if self.category is not None:
            rval["category"] = self.category
        if self.author is not None:
            rval["author"] = self.author
        if self.source is not None:
            rval["source"] = self.source
        rval["type"] = self.type
        rval["value"] = self.value
        return rval
        
class Indicator:
    def __init__(self, descriptor, id=None):
        if id == None:
            id = str(uuid.uuid4())
        self.id = id
        self.descriptor = descriptor
    def dump(self):
        rval = {}
        rval["id"] = self.id
        rval["descriptor"] = self.descriptor.dump()
        rval.update(self.value.dump())
        return rval
    def extract_fsm(self):
        return fsme.extract(self.value)

def loads(data):
    obj = json.loads(data)
    return load(obj)

def load_descriptor(obj):
    des = Descriptor()
    if "description" in obj: des.description = obj["description"]
    if "category" in obj: des.category = obj["category"]
    if "author" in obj: des.author = obj["author"]
    if "source" in obj: des.source = obj["source"]
    if "prob" in obj: des.prob = obj["prob"]
    if "type" in obj: des.type = obj["type"]
    if "value" in obj: des.value = obj["value"]
    return des

def load_indicator(obj):
    des = load_descriptor(obj["descriptor"])
    ii = Indicator(des, id = obj["id"])
    ii.value = load_value(obj)
    return ii

def load_value(obj):
    if "type" in obj:
        return lt.Match(obj["type"], obj["value"])
    elif "or" in obj:
        return lt.Or([load_value(v) for v in obj["or"]])
    elif "and" in obj:
        return lt.And([load_value(v) for v in obj["and"]])
    elif "not" in obj:
        return lt.Not(load_value(obj["not"]))
    else:
        raise RuntimeError("Can't parse value")

def load(obj):
    i = Indicators()
    if "description" in obj: i.description = obj["description"]
    if "version" in obj: i.version = obj["version"]
    i.indicators = [
        load_indicator(v) for v in obj["indicators"]
    ]
    return i
    
