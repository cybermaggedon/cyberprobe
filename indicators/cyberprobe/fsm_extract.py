
"""
Converts a logictree into an FSM.  The rationale is that an FSM provides a
highly optimized way to evaluate a logic tree.  The conversion from
logictree form to FSM is expensive, but only needs to be performed once.
The subsequent FSM can be repeatedly applied.

Use:
  import cyberprobe.fsm_extract as fsme
  import cyberprobe.logictree as lt
  a = lt.And([lt.Match("ipv4", "10.0.0.1"), lt.Match("ipv4", "192.168.0.1")])
  fsm = fsme.extract(a)
  m = fsme.mapify(fsm)
"""

import itertools
import cyberprobe.logictree as lt

def find_states(e, states):
    """
    A walker function used to find the FSM 'basic' states in a logic tree.
    Use with lt.walk:
      state=set()
      tree.walk(find_states, state)
    The basic states are the places in the tree where state information can
    stored: Children of AND and children of NOT.  NOT nodes are never themselves
    basic state nodes.
    """
    if e.par == None:
        return
    if type(e) == lt.Not:
        return
    if type(e.par) == lt.And:
        states.add(e)
    if type(e.par) == lt.Not:
        states.add(e)

def find_match_terms(e, states):
    """
    A walker function used to find the FSM match states in a logic tree.
    Use with lt.walk:
      terms=set()
      tree.walk(find_match_terms, terms)
    """
    if type(e) == lt.Match:
        states.add(e)

def name_combined_state(sts, tree):
    """
    Converts a combination state (list of states) into a string representing
    the combination state.
    e.g. ["s4", "s3", "s8"] -> "s3-4-8"
    """
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
    """ FSM extractor knows how to convert a logictree to an FSM """

    def __init__(self):
        """ Constructor. """
        self.tree = None

    def find_states(self):
        """ Studies a logictree and finds the FSM states """

        # Get the 'basic' states, nodes which represent the state of a
        # sub-expression.  This is children of AND and NOT operations, 
        # removing all NOTs.
        basic_states=set()
        self.tree.walk(find_states, basic_states)

        # The full tree state can be represented as a combination of basic
        # states.
        state_combis = []
        for i in range(0, len(basic_states)+1):
            cs = itertools.combinations(basic_states, i)
            for c in cs:
                c = set(c)
                state_combis.append(c)

        return basic_states, state_combis

    def find_terms(self):
        """ Finds the match terms in a logic tree """
        terms=set()
        self.tree.walk(find_match_terms, terms)
        return terms

    def evaluate_term(self, instate, term):
        """
        Takes a logictree state, and works out what happens when a term node
        is triggered.  Returns the updated state.  States is a dict which maps
        a node to an ElementState object.  Term is a (key, value) tuple.
        As a special case, the term can be the string "end" to mark end of
        scanning.
        Input state is a tuple of active elements.
        """

        # Convert input state tuple to a state map
        state = {}
        for elt in instate:
            state[elt] = lt.ElementState()
            state[elt].active = True
            elt.evaluate(state)

        # Activate the appropriate term.  'End' is a special case.
        if term != "end":
            term.activate(state)
            term = (term.type, term.value)
        else:
            self.tree.record_end(state)
            term = ('end', '')

        # Convert the input state to a symbol unique to the state
        instate = name_combined_state(instate, self.tree)

        # If the root node of the state is 'active' we'll give that a
        # special state name which is 'hit'.  Otherwise get the
        # combined state name symbol.
        if self.tree.is_active(state):
            outstate = "hit"
        else:
            outstate = set([v for v in state
                            if v in self.basic_states and v.is_active(state)])
            outstate = name_combined_state(outstate, self.tree)

        # Construct the FSM transition.
        transition = (instate, [term], outstate)
        return transition

    def flatten(self, fsm):
        """
        Flattens an FSM.  Edges of the form (src, [term...] dest) are
        coalesced to a single edge containing all terms.
        """

        # Flatten the FSM, so that 2nd elt is a complete list of terms that
        # will make the transition happen.

        # Convert to dict.
        fsm2 = {}
        for v in fsm:
            key = (v[0], v[2])
            if not key in fsm2:
                fsm2[key] = []
            for w in v[1]:
                fsm2[key].append(w)

        # Convert back to list.
        fsm = []
        for v in fsm2:
            fsm.append((v[0], fsm2[v], v[1]))

        return fsm

    def make_strategy(self, terms):
        """
        Form a strategy for discovering all term invocations.  The less
        optimal approach would be to try all terms for all state combinations.
        This function optimises that - all terms which are children of an
        OR result in the same outcome when any of them are executed.
        """

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
        """
        Studies a logic tree discovering the FSM state transitions for
        all combinations of states and terms.
        """
                            
        fsm = []

        # A strategy optimizes all the hunting for places to look in the tree
        # all terms triggering an OR are reduced to a single 'evaluate_term'
        # call because the result will be the same in all cases.
        strategy = self.make_strategy(terms)

        # For all combination states...
        for instate in combis:

            # Loop through strategy steps.
            for line in strategy:

                # Shouldn't happen.
                if len(strategy[line]) == 0: continue

                # Get the term to try.
                term = strategy[line][0]

                # Work out what transition happens.
                transition = self.evaluate_term(instate, term)

                # Ignore non-state transitions
                if transition[0] != transition[2]:

                    # The result will be the same for all terms in this
                    # strategy line.
                    for term in strategy[line]:
                        fsm.append((transition[0], [(term.type, term.value)],
                                    transition[2]))

            # Deal with the special 'end' case, and record the transition
            # unless it's a noop.
            transition = self.evaluate_term(instate, "end")
            if transition[0] != transition[2]:
                fsm.append(transition)

        return fsm

    def remove_invalid_transitions(self, fsm):
        """
        An FSM optimisation step.  Removes all states and transitions which
        can't be reached.  Also works out nodes from which it is not possible
        to get to a 'hit' state.  Those can be called 'fail'.
        """
      
        # Get a list of states which can lead to 'hit'.  All other states are
        # fail states, because you can't travel to hit.  Do this by starting
        # with a set containing just the 'hit' state, and keep adding states
        # which can get there.  Then re-iterate adding all states that get
        # to that state.
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

        # Remove transitions which can't be reached from init.  There will
        # areas of the FSM which cannot be reached, and this can be chopped
        # out from the FSM.
        while True:

            # Get a list of navigable states, which is states it is possible
            # to navigate to.  Add 'init' because it's the start state, and
            # you never navigate to it.
            navstates=set(['init'])
            for v in fsm:
                navstates.add(v[2])
            
            fsm2 = []

            # Remove all transitions which don't go from navigable states.
            for v in fsm:
                if v[0] in navstates:
                    fsm2.append(v)

            # This won't succeed in a single operation.  Keep going until
            # chopping out transitions results in no change.
            if fsm == fsm2:
                break

            fsm = fsm2

        return fsm

    def extract(self, tree):
        """
        Extract an FSM from a tree.
        """

        # Store the tree, and get the combination states.
        self.tree = tree
        (basic_states, state_combis) = self.find_states()

        # Store basic states, used by support methods.
        self.basic_states = basic_states

        # Get all match terms.
        terms = self.find_terms()

        # First pass, get the FSM.
        fsm = self.extract_transitions(state_combis, terms)

        # First pass flattening of the tree.  This is largely cosmetic, but
        # may make subsequent operates quicker.
        fsm = self.flatten(fsm)

        # Remove innavigable areas of the FSM, and reduce all failure paths
        # down to a single 'fail' state.
        fsm = self.remove_invalid_transitions(fsm)

        # Final flattening, the single 'fail' state will open up more
        # flattening options
        fsm = self.flatten(fsm)

        self.fsm = fsm

def extract(a):
    """ Convert a logictree to an FSM """
    fsm = FsmExtractor()
    fsm.extract(a)
    return fsm.fsm

def mapify(fsm):
    """
    Convert an FSM (src, [term, ...], dest) to a dict (src, term) -> dest
    which is more convenient for traversing.
    """

    fsm2 = {}

    for v in fsm:
        for w in v[1]:
            key=(v[0], w)
            fsm2[key] = v[2]

    return fsm2
    
