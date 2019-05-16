# Base class for vGraph matching algs

# Typically there is some type of preprocessing that must be applied to 
# all target and query graphs.  This is captured in the prepare function.

# Then the match function takes a query and target graph and actually
# performs matching.  In some cases it may assume that prepare has already
# been called on the data.
class Matcher:

    def __init__(self):
        pass

    def match(self, q, t, q_prepared, t_prepared):
        raise NotImplementedError

    def prepare_query(self, q):
        raise NotImplementedError

    def prepare_target(self, t):
        raise NotImplementedError
