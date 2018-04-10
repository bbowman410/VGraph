import sys
from DBInterface import DBInterface
import networkx as nx

if len(sys.argv) != 3:
    print "Usage: python gen_cpg.py <function_id> <output_file>"
    exit()

function_id = sys.argv[1]
output_file = sys.argv[2]

print "Function id: %s" % function_id
print "output file: %s" % output_file

db = DBInterface()

G =  nx.Graph()

nodes = db.runGremlinQuery("queryNodeIndex('functionId:%s')" % function_id)
edges = db.runGremlinQuery("queryNodeIndex('functionId:%s').outE()" % function_id)

for n in nodes:
    G.add_node(n._id)
    G.add_node(n._id)
    G.node[n._id]['code'] = n['code']
    G.node[n._id]['childNum'] = n['childNum']
    G.node[n._id]['type'] = n['type']
    G.node[n._id]['functionId'] = n['functionId']

for e in edges:
    G.add_edge(e.start_node._id, e.end_node._id)
    G[e.start_node._id][e.end_node._id]['type'] = e.type


nx.write_gpickle(G, output_file)

