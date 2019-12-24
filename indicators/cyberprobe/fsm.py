
"""
FSM utility class provides:
- Fsm: an FSM representing a single logictree rule.
- FsmState: State of a single FSM.
- FsmCollection: a set of FSMs representing a set of rules
"""

import json
import cyberprobe.indicators as ind
import cyberprobe.fsm_extract as fsme

# Represents a set of FSMs formed from a set of rules, and the current
# scan state.
class FsmCollection:

    def __init__(self):
        """ Constructor """
        pass

    @classmethod
    def load_from(cls, inds):
        """ Loads an FSM collection from a set of Indicator objects """

        # Convert indiciators to a list of FSMs.
        fsc = cls()
        fsc.fsmindicators = inds
        fsc.fsms = [Fsm.load_from(v) for v in inds.indicators]

        # Loop over the list, building a map of activator terms which
        # will move beyond an FSMs 'init' term.  The rationale here is
        # that we only track FSMs which are active, but look out for the
        # activator terms which will cause an FSM to come into action.
        # This may prove to be a bad strategy if there are many FSMs with
        # block terms, because it means we will track many FSMs which do
        # nothing.  If that's so, more intelligent tracking of FSMs may be
        # needed.
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
        """
        Initialises state.  This is called at the start of scanning a
        new object.
        """
        self.state = {}

    def update(self, term):
        """
        Updates state based on seeing a term of the form (type, value).
        A special form is ('end', '') for the end of scanning.
        """

        # See if there is an FSM which would be activated by this term, and
        # add to the state list.
        if term in self.activators:
            for fsm in self.activators[term]:
                if fsm not in self.state:
                    self.state[fsm] = fsm.init_state()

        # Update all active FSMs, including any just added to the list.
        for v in self.state:
            self.state[v].update(term)

    def get_hits(self):
        """
        Return all Indicator hits.
        """
        return [
            v.indicator for v in self.state if self.state[v].state == "hit"
        ]

class Fsm:
    """ Represents an FSM (no scanning state) """

    def __init__(self):
        """ Constructor """
        pass

    @classmethod
    def load_from(cls, ind):
        """ Initialises an FSM from an Indicator """
        fsm = cls()
        fsm.indicator = ind
        f = fsme.extract(ind.value)
        fsm.fsm = fsme.mapify(f)
        return fsm

    def dump(self):
        """ Dumps out the FSM transitions, for debug """
        for k in self.fsm:
            ins, term = k
            print("%s -- %s:%s -> %s" %
                  (ins, term[0], term[1], self.fsm[k]))

    def get_activator_terms(self):
        """
        Gets the list of terms which transition from the 'init' state, i.e.
         cause the FSM to be active.
        """
        inits=[]
        for ins, term in self.fsm:
            if ins == 'init':
                inits.append(term)
        return inits

    def init_state(self):
        """
        Initializes a state object to track the FSM state.
        """
        s = FsmState('init')
        s.fsm = self
        return s

# The state of scanning associated with a single FSM.
class FsmState:

    def __init__(self, state):
        """
        Constructor.
        """
        self.state = state

    def is_hit(self):
        """ 
        True if FSM state has reached 'hit'
        """
        return self.state == 'hit'

    def is_fail(self):
        """
        True if FSM state has reached 'fail'
        """
        return self.state == 'fail'

    def update(self, term):
        """
        Advance the FSM state based on a term.
        """
        key = (self.state, term)
        if key in self.fsm.fsm:
            self.state = self.fsm.fsm[key]
