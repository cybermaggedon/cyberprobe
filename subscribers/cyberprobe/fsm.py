
import json
import cyberprobe.indicators as ind
import cyberprobe.fsm_extract as fsme

class FsmCollection:

    def __init__(self):
        pass

    @classmethod
    def load_from(cls, inds):
        fsc = cls()
        fsc.fsmindicators = inds
        fsc.fsms = [Fsm.load_from(v) for v in inds.indicators]

        activators = {}
        for v in fsc.fsms:
            a = v.get_activator_terms()
            for w in a:
                if w not in activators:
                    activators[w] = []
                activators[w].append(v)
        fsc.activators = activators

        return fsc

    def init_state(self):
        self.state = {}

    def update(self, term):

        if term in self.activators:
            for fsm in self.activators[term]:
                if fsm not in self.state:
                    self.state[fsm] = fsm.init_state()

        for v in self.state:
            self.state[v].update(term)

    def get_hits(self):
        return [
            v.indicator for v in self.state if self.state[v].state == "hit"
        ]
            
class Fsm:
    
    def __init__(self):
        pass

    @classmethod
    def load_from(cls, ind):
        fsm = cls()
        fsm.indicator = ind
        f = fsme.extract(ind.value)
        fsm.fsm = fsme.mapify(f)
        return fsm

    def dump(self):
        for k in self.fsm:
            ins, term = k
            print("%s -- %s:%s -> %s" %
                  (ins, term[0], term[1], self.fsm[k]))

    def get_activator_terms(self):
        inits=[]
        for ins, term in self.fsm:
            if ins == 'init':
                inits.append(term)
        return inits

    def init_state(self):
        s = FsmState('init')
        s.fsm = self
        return s

class FsmState:

    def __init__(self, state):
        self.state = state

    def is_hit(self):
        return self.state == 'hit'

    def is_fail(self):
        return self.state == 'fail'

    def update(self, term):
        key = (self.state, term)
        if key in self.fsm.fsm:
#            print("Term %s takes us %s -> %s" %
#                  (term, self.state, self.fsm.fsm[key]))
            self.state = self.fsm.fsm[key]
