
"""
Cyberprobe indicators
"""

import uuid
import json
import cyberprobe.logictree as lt
import cyberprobe.fsm_extract as fsme

class Indicators:
    """
    Represents a set of indicators.
    """

    def __init__(self, description=None, version=None, indicators=[]):
        """ Constructor. """
        self.description = description
        self.version = version
        self.indicators = indicators

    def add_indicator(self, i):
        """ Adds an indicator """
        self.indicators.append(i)

    def get(self, id):
        """ Gets an indicator by ID. """
        for v in self.indicators:
            if v.id == id:
                return v
        raise RuntimeError("No such indicator ID")

    def dump(self):
        """
        Returns a dict object representing the indicator set which can be
        JSON serialized.
        """

        rval = {}
        if self.description: rval["description"] = self.description
        if self.version: rval["version"] = self.version
        rval["indicators"] = [
            v.dump() for v in self.indicators
        ]
        return rval

    def dumps(self):
        """ Dumps an indicator set to JSON string. """
        return json.dumps(self.dump(), indent=4)

class Descriptor:
    """
    A descriptor object represents the information associated with an event
    when a detection event occurs.
    """

    def __init__(self, description=None, category=None,
                 author=None, source=None, prob=1.0,
                 type=None, value=None):
        """ Constructor. """
        self.description = description
        self.category = category
        self.author = author
        self.source = source
        self.type = type
        self.value = value
        self.probability = prob

    def dump(self):
        """
        Returns a dict object representing the descriptor which can be JSON
        serialized.
        """

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
        rval["probability"] = self.probability
        return rval
        
class Indicator:
    """ Represents an indicator object. """

    def __init__(self, descriptor, id=None):
        """ Constructor """
        if id == None:
            id = str(uuid.uuid4())
        self.id = id
        self.descriptor = descriptor

    def dump(self):
        """
        Represents a dict object representing the indicator object
        which can be serialized.
        """
        rval = {}
        rval["id"] = self.id
        rval["descriptor"] = self.descriptor.dump()
        rval.update(self.value.dump())
        return rval

    def extract_fsm(self):
        """ Returns an FSM object from the indicator. """
        return fsme.extract(self.value)

def loads(data):
    """ Loads an indicator set from a JSON string. """
    obj = json.loads(data)
    return load(obj)

def load_descriptor(obj):
    """ Loads a descriptor from a Python dict object. """
    des = Descriptor()
    if "description" in obj: des.description = obj["description"]
    if "category" in obj: des.category = obj["category"]
    if "author" in obj: des.author = obj["author"]
    if "source" in obj: des.source = obj["source"]
    if "probability" in obj:
        des.probability = obj["probability"]
    else:
        des.probability = 1.0
    if "type" in obj: des.type = obj["type"]
    if "value" in obj: des.value = obj["value"]
    return des

def load_indicator(obj):
    """ Loads an indicator from a Python dict object """
    des = load_descriptor(obj["descriptor"])
    ii = Indicator(des, id = obj["id"])
    ii.value = load_value(obj)
    return ii

def load_value(obj):
    """ Loads an value from a Python dict object """
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
    """ Loads an indicator set from a Python dict object """
    i = Indicators()
    if "description" in obj: i.description = obj["description"]
    if "version" in obj: i.version = obj["version"]
    i.indicators = [
        load_indicator(v) for v in obj["indicators"]
    ]
    return i
    
