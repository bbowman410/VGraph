from matcher import Matcher
from networkx.algorithms import isomorphism
import networkx as nx

class ExactMatcher(Matcher):


    def __init__(self):
        pass

    def match(self, q, t, q_prepared, t_prepared):
        GM = isomorphism.DiGraphMatcher(t,q, node_match=self.custom_node_match,edge_match=self.custom_edge_match)
        res = GM.subgraph_is_isomorphic()
        if res:
            return {}, 100
        else:
            return {}, 0 


    def prepare_query(self, q):
        return q

    def prepare_target(self, t):
        return t


    def custom_node_match(self,n1, n2):
        if n1['type'] == n2['type']:
            return True
        else:
             return False

    def custom_edge_match(self,e1, e2):
        if e1['type'] == e2['type']:
            return True
        else:
             return False
