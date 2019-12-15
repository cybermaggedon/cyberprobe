
import sys

class Element:
    id = 1
    def __init__(self):
        self.id = "s" + str(Element.id)
        self.par = None
        Element.id = Element.id + 1
        
    def is_active(self, state):
        if not self in state: return False
        if not state[self].active: return False
        return True

class ElementState:
      def __init__(self):
            self.active = False
            
class And(Element):
    def __init__(self, e):
        self.e = e
        for e in self.e:
            e.par = self
        Element.__init__(self)
    def walk(self, fn, state=None):
        for e in self.e:
            e.walk(fn, state)
        fn(self, state)

    def state_elt(self):
        return self

    def get_elt(self, id):
        if id == self.id:
            return self
        for v in self.e:
            elt = v.get_elt(id)
            if elt is not None:
                return elt
        return None

    def evaluate(self, state):

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
        for v in self.e:
            v.record_end(state)

    def dump_logic_tree(self, indent=0):
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: and" % self.id)
        for v in self.e:
            v.dump_logic_tree(indent+1)

    def dump(self):
        return {
            "and": [ v.dump() for v in self.e ]
        }
     
class Or(Element):
    def __init__(self, e):
        self.e = e
        for e in self.e:
            e.par = self
        Element.__init__(self)
    def walk(self, fn, state=None):
        for e in self.e:
            e.walk(fn, state)
        fn(self, state)
    def state_elt(self):
        return self.par.state_elt()
    def get_elt(self, id):
        if id == self.id:
            return self
        for v in self.e:
            elt = v.get_elt(id)
            if elt is not None:
                return elt
        return None

    def evaluate(self, state):

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
        for v in self.e:
            v.record_end(state)

    def dump_logic_tree(self, indent=0):
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: or" % self.id)
        for v in self.e:
            v.dump_logic_tree(indent+1)

    def dump(self):
        return {
            "or": [ v.dump() for v in self.e ]
        }
                     
class Not(Element):
    def __init__(self, e):
        self.e = e
        self.e.par = self
        Element.__init__(self)
    def walk(self, fn, state=None):
        self.e.walk(fn, state)
        fn(self, state)
    def state_elt(self):
        return self
    def get_elt(self, id):
        if id == self.id:
            return self
        elt = self.e.get_elt(id)
        if elt is not None:
            return elt
        return None

    def evaluate(self, state):
        pass

    def record_end(self, state):

        if not self in state: state[self] = ElementState()
        if state[self].active: return

        if self.e in state:
            if state[self.e].active:
                return

        state[self].active = True
        # print(self.id, "is true (NOT)")
        #            dump_state(state)
        if self.par != None: self.par.evaluate(state)

    def dump_logic_tree(self, indent=0):
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: not" % self.id)
        self.e.dump_logic_tree(indent+1)

    def dump(self):
        return {
            "not": self.e.dump()
        }
                    
class Match(Element):
    def __init__(self, type, value):
        self.type = type
        self.value = value
        self.par = None
        Element.__init__(self)
    def walk(self, fn, state=None):
        fn(self, state)
    def state_elt(self):
        return self.par.state_elt()
    def get_elt(self, id):
        if id == self.id:
            return self
        return None

    def evaluate(self, state):
        pass

    def activate(self, state):
        if not self in state: state[self] = ElementState()
        if state[self].active: return

        state[self].active = True
        if self.par != None: self.par.evaluate(state)

    def record_end(self, state):
        pass

    def dump_logic_tree(self, indent=0):
        for v in range(0, indent): sys.stdout.write("  ")
        print("%s: \"%s: %s\"" % (self.id, self.type, self.value))

    def dump(self):
        return {
            "type": self.type,
            "value": self.value
        }
           
def parse_logic_tree(obj):
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
    obj.dump_logic_tree()

