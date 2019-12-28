

"""
Represents a decision tree built from boolean logic operators.
"""

import sys

class Element:
    """ Base class for logic operators. """
    id = 1
    def __init__(self):
        """ Constructor """
        self.id = "s" + str(Element.id)
        self.par = None
        Element.id = Element.id + 1
        
    def is_active(self, state):
        """ Returns true if the element is active in provided state """
        if not self in state: return False
        if not state[self].active: return False
        return True

class ElementState:
    """ Tracks state of an element. """
    def __init__(self):
        """ Constructor """
        self.active = False
            
class And(Element):
    """ Represents an AND operator """
    
    def __init__(self, e):
        """ Constructor """
        self.e = e
        for e in self.e:
            e.par = self
        Element.__init__(self)

    def walk(self, fn, state=None):
        """ Walks the tree of nodes, depth-first """
        for e in self.e:
            e.walk(fn, state)
        fn(self, state)

    def get_elt(self, id):
        """ Walks the tree, hunting for a node with provided ID """
        if id == self.id:
            return self
        for v in self.e:
            elt = v.get_elt(id)
            if elt is not None:
                return elt
        return None

    def evaluate(self, state):
        """
        Causes node evaluation, which means studying the state and
        working out if other state transitions should take place higher
        in the tree.
        """

        if not self in state: state[self] = ElementState()
        if state[self].active: return

        count=0

        for v in self.e:
            if v in state:
                if state[v].active:
                    count += 1

        if count != len(self.e): return

        state[self].active = True
        # print(self.id, "is true (AND)")
        # dump_state(state)
        if self.par != None: self.par.evaluate(state)

    def record_end(self, state):
        """ Records the end of scanning, and works out the impact on state. """
        for v in self.e:
            v.record_end(state)

    def dump_logic_tree(self, indent=0):
        """ Dumps out a logic tree in human-readable form """

        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: and" % self.id)
        for v in self.e:
            v.dump_logic_tree(indent+1)

    def dump(self):
        """ Returns a Python dict object representing the state. """
        return {
            "and": [ v.dump() for v in self.e ]
        }
     
class Or(Element):

    def __init__(self, e):
        """ Constructor """
        self.e = e
        for e in self.e:
            e.par = self
        Element.__init__(self)

    def walk(self, fn, state=None):
        """ Walks the tree of nodes, depth-first """
        for e in self.e:
            e.walk(fn, state)
        fn(self, state)

    def get_elt(self, id):
        """ Walks the tree, hunting for a node with provided ID """
        if id == self.id:
            return self
        for v in self.e:
            elt = v.get_elt(id)
            if elt is not None:
                return elt
        return None

    def evaluate(self, state):
        """
        Causes node evaluation, which means studying the state and
        working out if other state transitions should take place higher
        in the tree.
        """

        if not self in state: state[self] = ElementState()
        if state[self].active: return

        count=0

        for v in self.e:
            if v in state:
                if state[v].active: count += 1

        if count == 0: return

        state[self].active = True
        # print(self.id, "is true (OR)")
        #            dump_state(state)
        if self.par != None: self.par.evaluate(state)

    def record_end(self, state):
        """ Records the end of scanning, and works out the impact on state. """
        for v in self.e:
            v.record_end(state)

    def dump_logic_tree(self, indent=0):
        """ Dumps out a logic tree in human-readable form """
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: or" % self.id)
        for v in self.e:
            v.dump_logic_tree(indent+1)

    def dump(self):
        """ Returns a Python dict object representing the state. """
        return {
            "or": [ v.dump() for v in self.e ]
        }
                     
class Not(Element):

    def __init__(self, e):
        """ Constructor """
        self.e = e
        self.e.par = self
        Element.__init__(self)

    def walk(self, fn, state=None):
        """ Walks the tree of nodes, depth-first """
        self.e.walk(fn, state)
        fn(self, state)

    def get_elt(self, id):
        """ Walks the tree, hunting for a node with provided ID """
        if id == self.id:
            return self
        elt = self.e.get_elt(id)
        if elt is not None:
            return elt
        return None

    def evaluate(self, state):
        """
        Causes node evaluation, which means studying the state and
        working out if other state transitions should take place higher
        in the tree.
        """
        pass

    def record_end(self, state):
        """ Records the end of scanning, and works out the impact on state. """

        if not self in state: state[self] = ElementState()
        if state[self].active: return

        self.e.record_end(state)
        if self.e in state:
            if state[self.e].active:
                return

        state[self].active = True
        # print(self.id, "is true (NOT)")
        #            dump_state(state)
        if self.par != None: self.par.evaluate(state)

    def dump_logic_tree(self, indent=0):
        """ Dumps out a logic tree in human-readable form """
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: not" % self.id)
        self.e.dump_logic_tree(indent+1)

    def dump(self):
        """ Returns a Python dict object representing the state. """
        return {
            "not": self.e.dump()
        }
                    
class Match(Element):

    def __init__(self, type, value):
        """ Constructor """
        self.type = type
        self.value = value
        self.par = None
        Element.__init__(self)

    def walk(self, fn, state=None):
        """ Walks the tree of nodes, depth-first """
        fn(self, state)

    def get_elt(self, id):
        """ Walks the tree, hunting for a node with provided ID """
        if id == self.id:
            return self
        return None

    def evaluate(self, state):
        """
        Causes node evaluation, which means studying the state and
        working out if other state transitions should take place higher
        in the tree.
        """
        pass

    def activate(self, state):
        """
        Activates a node
        """
        if not self in state: state[self] = ElementState()
        if state[self].active: return

        state[self].active = True
        if self.par != None: self.par.evaluate(state)

    def record_end(self, state):
        """ Records the end of scanning, and works out the impact on state. """
        pass

    def dump_logic_tree(self, indent=0):
        """ Dumps out a logic tree in human-readable form """
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: \"%s: %s\"" % (self.id, self.type, self.value))

    def dump(self):
        """ Returns a Python dict object representing the state. """
        return {
            "type": self.type,
            "value": self.value
        }
           
def parse_logic_tree(obj):
    """
    Parses an Python dict object representing a logic tree, returning
    a logic tree.
    """
    if type(obj) == str:
        return Match(obj)

    if type(obj) != dict:
        raise Exception("Bullshit input")

    if "and" in obj:
        ch = [parse_logic_tree(v) for v in obj["and"]]
        return And(ch)

    if "or" in obj:
        ch = [parse_logic_tree(v) for v in obj["or"]]
        return Or(ch)

    if "not" in obj:
        ch = parse_logic_tree(obj["not"])
        return Not(ch)

    if obj["type"] == "match":
        return Match(obj["value"])

def dump_logic_tree(obj, indent=0):
    """ Dumps out a logic tree in human-readable form """
    obj.dump_logic_tree()

