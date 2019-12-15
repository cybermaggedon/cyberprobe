
import itertools
import cyberprobe.logictree as lt

# A walker function used to find the FSM 'basic' states in a logic tree.
# Use with lt.walk:
#   state=set()
#   tree.walk(find_states, state)
def find_states(e, states):
    if e.par == None:
        return
    if type(e) == lt.Not:
        return
    if type(e.par) == lt.And:
        states.add(e)
    if type(e.par) == lt.Not:
        states.add(e)

# A walker function used to find the FSM match states in a logic tree.
# Use with lt.walk:
#   terms=set()
#   tree.walk(find_match_terms, terms)
def find_match_terms(e, states):

    if type(e) == lt.Match:
        states.add(e)

# Converts a combination state (list of states) into a string representing
# the combination state.
# e.g. ["s4", "s3", "s8"] -> "s3-4-8"
def name_combined_state(sts, tree):
    if len(sts) == 0: return "init"
    if tree.id in sts: return "hit"
    rval = "s"
    sep = ""
    for st in sorted([v.id for v in sts]):
        if st.startswith("s"): st = st[1:]
        rval += sep + st
        sep = "-"
    return rval

class FsmExtractor:
    def __init__(self):
        self.tree = None

    def find_states(self):
        basic_states=set()
        self.tree.walk(find_states, basic_states)

        state_combis = []
        for i in range(0, len(basic_states)+1):
            cs = itertools.combinations(basic_states, i)
            for c in cs:
                c = set(c)
                state_combis.append(c)

        return basic_states, state_combis

    def find_terms(self):

        terms=set()
        self.tree.walk(find_match_terms, terms)
        return terms

    def evaluate_term(self, instate, term):

        state = {}
        for elt in instate:
            state[elt] = lt.ElementState()
            state[elt].active = True
            elt.evaluate(state)

        if term != "end":
            term.activate(state)
            term = (term.type, term.value)
        else:
            self.tree.record_end(state)
            term = ('end', '')

        instate = name_combined_state(instate, self.tree)

        if self.tree.is_active(state):
            outstate = "hit"
        else:
            outstate = set([v for v in state if v in self.basic_states and v.is_active(state)])
            outstate = name_combined_state(outstate, self.tree)

        transition = (instate, [term], outstate)

        return transition


    def flatten(self, fsm):

        # Flatten the FSM, so that 2nd elt is a list of terms that will make
        # the transition happen.
        fsm2 = {}
        for v in fsm:
            key = (v[0], v[2])
            if not key in fsm2:
                fsm2[key] = []
            for w in v[1]:
                fsm2[key].append(w)

        fsm = []
        for v in fsm2:
            fsm.append((v[0], fsm2[v], v[1]))

        return fsm

    def make_strategy(self, terms):

        strategy = {}
        
        for term in terms:

            # Basic case, tree consists entirely of a term.
            if term.par == None:
                # List really should be empty, but WTH.
                if term not in strategy: strategy[term] = []
                strategy[term].append(term)
                continue

            # Term has a parent because of above condition.

            # The Or cases are great.
            if type(term.par) == lt.Or:
                if term.par not in strategy:
                    strategy[term.par] = []
                strategy[term.par].append(term)
                continue

            # This is overcooked in terms of checking, but does the right
            # thing.
            if term not in strategy:
                strategy[term] = []
            strategy[term].append(term)

        return strategy

    def extract_transitions(self, combis, terms):
                            
        fsm = []

        # A strategy optimizes all the hunting for places to look in the tree
        # all terms triggering an OR are reduced to a single 'evaluate_term'
        # call because the result will be the same in all cases.
        strategy = self.make_strategy(terms)

        for instate in combis:

            for line in strategy:

                # Shouldn't happen.
                if len(strategy[line]) == 0: continue

                term = strategy[line][0]

                transition = self.evaluate_term(instate, term)
                # Ignore non-state transitions
                if transition[0] != transition[2]:

                    for term in strategy[line]:
                        fsm.append((transition[0], [(term.type, term.value)],
                                    transition[2]))

            transition = self.evaluate_term(instate, "end")
            if transition[0] != transition[2]:
                fsm.append(transition)

        return fsm

    def remove_invalid_transitions(self, fsm):
      
        # Get a list of states which can lead to 'hit'.  All other states are
        # fail states, because you can't travel to hit.
        hitstates = set(["hit"])
        while True:
            nhs = hitstates.copy()
            for v in fsm:
                if v[2] in hitstates:
                    hitstates.add(v[0])
            if nhs == hitstates:
                break

        # Rework the 'fail' state into the FSM.  Fail states are states
        # from which it is not possible to arrive at hit.
        fsm2 = []
        for v in fsm:

            # Remove transitions which lead from fail states
            if v[0] not in hitstates:
                continue

            # Transitions to states which can't lead to hits are fails.
            if v[2] in hitstates:
                fsm2.append(v)
            else:
                fsm2.append((v[0], v[1], 'fail'))

        fsm = fsm2

        while True:

            # Get a list of navigable states, which is states it is possible
            # to navigate to.  Add 'init' because it's the start state, and
            # you never navigate to it.
            navstates=set(['init'])
            for v in fsm:
                navstates.add(v[2])
            
            fsm2 = []

            for v in fsm:
                if v[0] in navstates:
                    fsm2.append(v)

            if fsm == fsm2:
                break

            fsm = fsm2

        return fsm
        
    def extract(self, tree):

        self.tree = tree
        (basic_states, state_combis) = self.find_states()

        # pass through to function above.  FIXME:
        self.basic_states = basic_states

        terms = self.find_terms()

        fsm = self.extract_transitions(state_combis, terms)

        fsm = self.flatten(fsm)

        fsm = self.remove_invalid_transitions(fsm)

        fsm = self.flatten(fsm)

        self.fsm = fsm
          
def extract(a):
    fsm = FsmExtractor()
    fsm.extract(a)
    return fsm.fsm

def mapify(fsm):

    fsm2 = {}

    for v in fsm:
        for w in v[1]:
            key=(v[0], w)
            fsm2[key] = v[2]

    return fsm2
    
