from exact_matcher import ExactMatcher
import networkx as nx
EM=ExactMatcher()
G = nx.DiGraph()
H = nx.DiGraph()
G.add_edge('0','1')
H.add_edge('2','3')
H.add_edge('3','4')
G.node['0']['type'] = 'type_1'
G.node['0']['code'] = 'something else'
G.node['1']['type'] = 'type_1'
G.node['0']['type'] = 'type_0'
H.node['2']['type'] = 'type_0'
H.node['3']['type'] = 'type_1'
H.node['4']['type'] = 'type_2'
G['0']['1']['type'] = 'edge_type_0'
H['2']['3']['type'] = 'edge_type_0'
H['3']['4']['type'] = 'edge_type_2'
res = EM.match(G,H,None,None)
print(res)
res = EM.match(G,H,None,None)
print(res)


vgraph = nx.read_gpickle('../../vgraph_db/ffmpeg/CVE-2014-8547/0b39ac6f54505a538c21fe49a626de94c518c903/gifdec.c/gif_read_image_pvg.gpickle')

vuln_func = nx.read_gpickle('../../vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2014-8547/vuln/0b39ac6f54505a538c21fe49a626de94c518c903/gifdec.c/graph/gif_read_image.gpickle')

test = nx.DiGraph()
test.add_node('2128756')
test.node['2128756']['type'] = 'Symbol'
test.node['2128756']['code'] = 'pass'

test.add_node('2128631')
test.node['2128631']['type'] = 'ExpressionStatement'
test.node['2128631']['code'] = 'y1 = pass ? 2 : 4'

test.add_edge('2128631','2128756')
test['2128631']['2128756']['type'] = 'USE'

print("vgraph num nodes: %d" % len(vgraph.nodes()))
print("vuln func num nodes: %d" % len(vuln_func.nodes()))

print("Testing big match...")
res = EM.match(test,vuln_func,None,None)

print(res)
