
import cyberprobe.fsm_extract as fsme
import cyberprobe.logictree as lt

def is_not(e, ret):
    """
    A walker function used to find the FSM 'basic' states in a logic tree.
    Use with lt.walk:
      state=set()
      tree.walk(find_states, state)
    The basic states are the places in the tree where state information can
    stored: Children of AND and children of NOT.  NOT nodes are never themselves
    basic state nodes.
    """
    if type(e) == lt.Not:
        ret['value'] = True

def contains_not(e):
    ret = { 'value': False }
    e.walk(is_not, ret)
    return ret['value']

# Represents a set of FSMs formed from a set of rules, and the current
# scan state.
class LtsCollection:

    def __init__(self):
        """ Constructor """
        pass

    @staticmethod
    def get_activator_terms(ind):
        """
        Gets the list of terms which transition from the 'init' state, i.e.
         cause the FSM to be active.
        """
        terms=set()
        ind.value.walk(fsme.find_match_terms, terms)
        return terms

    @classmethod
    def load_from(cls, inds):
        """ Loads an FSM collection from a set of Indicator objects """

        # Convert indiciators to a list of FSMs.
        sc = cls()
        sc.indicators = inds

        # Loop over the list, building a map of activator terms which
        # will move beyond an FSMs 'init' term.  The rationale here is
        # that we only track FSMs which are active, but look out for the
        # activator terms which will cause an FSM to come into action.
        # This may prove to be a bad strategy if there are many FSMs with
        # block terms, because it means we will track many FSMs which do
        # nothing.  If that's so, more intelligent tracking of FSMs may be
        # needed.
        activators = {}
        nots = []
        for v in sc.indicators.indicators:

            terms = LtsCollection.get_activator_terms(v)
            for node in terms:
                term = (node.type, node.value)
                if term not in activators:
                    activators[term] = []
                activators[term].append(node)
            if contains_not(v.value):
                nots.append(v)

        sc.activators = activators
        sc.nots = nots

        return sc

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

        if term == ('end', ''):
            for v in self.nots:
                v.value.record_end(self.state)
            return

        if term in self.activators:
            for sc in self.activators[term]:
                sc.activate(self.state)

    def get_hits(self):
        """
        Return all Indicator hits.
        """
        return [
            v for v in self.indicators.indicators
            if v.value in self.state and
            self.state[v.value].active == True
        ]
