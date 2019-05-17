import os
import sys
import networkx as nx
import pickle as pkl
import tale

# Some nodes we don't want to pivot through while growing the graph
SKIP_TYPES=['CFGEntryNode', 'CFGExitNode', 'FunctionDef']
MIN_NODES=50
MIN_CONTEXT_NODES=50


def get_important_ndoes(G,p=0.1):
    ''' 
    This function returns a list of "important" nodes which will be used during matching.  We use node degree to determine importance.  Although we should not avoid the common nodes with high degree.
 
    p is the fraction of nodes to return
    '''
    # import based on degree
    node_degree_dict = {}
    nodes_to_return = int(len(G.nodes()) * p)
    for n in G.nodes:
        node_degree_dict[n] = G.degree(n)

    important_nodes = []

    for node_id, degree in reversed(sorted(node_degree_dict.iteritems(), key=lambda (k,v): (v,k))):

        important_nodes.append(node_id)
        nodes_to_return -= 1

        if nodes_to_return <= 0:
            break

    return important_nodes

def get_bfs_trees(G,important_nodes):
    '''
    This function generates the undirected BFS tree for each important node in the graph G.  This BFS tree will be used by the matching algorithms to direct the match path.
    '''
    bfs_trees = {}
    for n in important_nodes:
        bfs_trees[n] = nx.bfs_tree(G.to_undirected(), n)

    return bfs_trees



# We want our graphs to remain connected, so we do that
def connect_graph(small_graph, big_graph):
    small_graph_undirected = small_graph.to_undirected()
    big_graph_undirected = big_graph.to_undirected()

    while not nx.is_connected(small_graph_undirected):
    
        # Get list of ccs 
        ccs = list(nx.connected_components(small_graph_undirected))

        # sort ccs based on size (first element is biggest cc)
        ccs.sort(key=len, reverse=True)

        # merge largest two ccs by shortest path between them
        sp = None
        for n1 in ccs[0]:
            for n2 in ccs[1]:
                # Find shortest path in big graph
                sp_n1_n2 = nx.shortest_path(big_graph_undirected, n1, n2)
                if sp is None or len(sp_n1_n2) < len(sp):
                    sp = sp_n1_n2
        # now we know the shortest path from biggest_cc to other cc
        for n in sp:
            small_graph.add_node(n)
            small_graph.node[n]['type'] = big_graph.node[n]['type']
            small_graph.node[n]['code'] = big_graph.node[n]['code']
    
        # Need to add edges now so we know when to stop
        for n in sp:
            for neighbor in big_graph[n]:
                if neighbor in sp:
                    small_graph.add_edge(n,neighbor)
                    small_graph[n][neighbor]['type'] = big_graph[n][neighbor]['type']
                
        # Update undirected version
        small_graph_undirected = small_graph.to_undirected()


# Grow a graph by expanding to neighbors num_hops away
def expand_graph(small_graph, big_graph, num_hops=1):
    for _ in range(num_hops):
        # loop through all nodes in small graph and add neighbors
        
        small_nodes = list(small_graph.nodes)[:]

        for n in small_nodes:
            for neighbor in big_graph.successors(n):
                small_graph.add_node(neighbor)
                small_graph.node[neighbor]['type'] = big_graph.node[neighbor]['type']
                small_graph.node[neighbor]['code'] = big_graph.node[neighbor]['code']
                small_graph.add_edge(n, neighbor)
                small_graph[n][neighbor]['type'] = big_graph[n][neighbor]['type']
            for neighbor in big_graph.predecessors(n):
                small_graph.add_node(neighbor)
                small_graph.node[neighbor]['type'] = big_graph.node[neighbor]['type']
                small_graph.node[neighbor]['code'] = big_graph.node[neighbor]['code']
                small_graph.add_edge(neighbor, n)
                small_graph[neighbor][n]['type'] = big_graph[neighbor][n]['type']
                
                    
                

        #nodes_to_add = []
        #for n in small_graph.nodes:
        #    for neighbor in big_graph.successors(n):
        #        nodes_to_add.append(neighbor)
        #    for neighbor in big_graph.predecessors(n):
        #        nodes_to_add.append(neighbor)

        #for n in nodes_to_add:
        #    if big_graph.node[n]['type'] in SKIP_TYPES:
        #        continue # skip it

        #    if n not in small_graph.nodes:
        #        small_graph.add_node(n)
        #        small_graph.node[n]['type'] = big_graph.node[n]['type']
        #        if 'code' in big_graph.node[n]:
        #            small_graph.node[n]['code'] = big_graph.node[n]['code']


def print_statistics(file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size,context_graph_size):
    print "%s\t%d\t%d\t%d\t%d\t%d\t%d" % (file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size, context_graph_size)


def add_edges(graph_nodes_only, full_graph):
    '''
    This function adds any edges between nodes in the first graph based on the edges found in the second graph
    '''
    # finish graph by adding relevant edges
    for n in graph_nodes_only.nodes:
        for neighbor in full_graph[n]:
            if neighbor in graph_nodes_only.nodes:
                graph_nodes_only.add_edge(n,neighbor)
                graph_nodes_only[n][neighbor]['type'] = full_graph[n][neighbor]['type']


def align(src_graph, dst_graph):
    '''
    Take as input two graphs and align the common nodes.
    '''

    src_to_dst_mapping = {}
    dst_to_src_mapping = {}

    # First lets match CFGEntryNode, CFGExitNode, and FunctionDef to get our skeleton
    for src_node in src_graph.nodes:
        if src_graph.node[src_node]['type'] == 'CFGEntryNode':
            for dst_node in dst_graph.nodes:
                if dst_graph.node[dst_node]['type'] == 'CFGEntryNode':
                    src_to_dst_mapping[src_node] = dst_node
                    dst_to_src_mapping[dst_node] = src_node
                    break
        elif src_graph.node[src_node]['type'] == 'CFGExitNode':
            for dst_node in dst_graph.nodes:
                if dst_graph.node[dst_node]['type'] == 'CFGExitNode':
                    src_to_dst_mapping[src_node] = dst_node
                    dst_to_src_mapping[dst_node] = src_node
                    break
        elif src_graph.node[src_node]['type'] == 'FunctionDef':
            for dst_node in dst_graph.nodes:
                if dst_graph.node[dst_node]['type'] == 'FunctionDef':
                    src_to_dst_mapping[src_node] = dst_node
                    dst_to_src_mapping[dst_node] = src_node
                    break

    # Now match all other nodes as best we can
    for src_node in src_graph.nodes:
        if src_node in src_to_dst_mapping.keys():
            continue
        for dst_node in dst_graph.nodes:
            if dst_node in dst_to_src_mapping.keys():
                continue 

            if src_graph.node[src_node]['code'] == dst_graph.node[dst_node]['code'] and src_graph.node[src_node]['type'] == dst_graph.node[dst_node]['type'] and src_graph.in_degree(src_node) == dst_graph.in_degree(dst_node) and src_graph.out_degree(src_node) == dst_graph.out_degree(dst_node):
                src_to_dst_mapping[src_node] = dst_node
                dst_to_src_mapping[dst_node] = src_node
                break # to next src node

    return src_to_dst_mapping, dst_to_src_mapping

###############################################

if len(sys.argv) != 5:
    print "Usage: python gen_vgraph.py <vuln_graph> <patch_graph> <output_path> <output_name>"
    exit()

# Read inputs
vuln_graph = sys.argv[1]
patch_graph = sys.argv[2]
output_path = sys.argv[3]
output_name= sys.argv[4]

# vgraph ID
vuln_function = output_path + '/' + output_name

# Graph Outputs
pvg_output_file = output_path + '/' + output_name  + "_pvg.gpickle"
nvg_output_file = output_path + '/' + output_name + "_nvg.gpickle"
cvg_output_file = output_path + '/' + output_name + "_cvg.gpickle"

# Important Node Outputs
pvg_imp_nodes_output_file = output_path + '/' + output_name + "_pvg_imp_nodes.pkl"
nvg_imp_nodes_output_file = output_path + '/' + output_name + "_nvg_imp_nodes.pkl"
cvg_imp_nodes_output_file = output_path + '/' + output_name + "_cvg_imp_nodes.pkl"

# BFS Outputs 
pvg_bfs_trees_output_file = output_path + '/' + output_name + "_pvg_bfs_trees.pkl"
nvg_bfs_trees_output_file = output_path + '/' + output_name + "_nvg_bfs_trees.pkl"
cvg_bfs_trees_output_file = output_path + '/' + output_name + "_cvg_bfs_trees.pkl"

# Read in the vulnerable and patched graphs
V = nx.read_gpickle(vuln_graph)
P = nx.read_gpickle(patch_graph)
print "V size: %d" % len(V.nodes)
print "P size: %d" % len(P.nodes)

# Align the vulnerable and patch graphs
# We could probably do this in a more clever way from source code and diff files
v_to_p_mapping, p_to_v_mapping = align(V,P)

print "Number of shared nodes (SN): %d" % len(v_to_p_mapping)
print "Positive vGraph base size (V - SN): %d" % (len(V.nodes) - len(v_to_p_mapping))
print "Negative vGraph base size (P-SN): %d" % (len(P.nodes) - len(v_to_p_mapping))

if len(V.nodes) == len(P.nodes) == len(v_to_p_mapping):
    # All V nodes were in P and vica versa.  So no way to model vulnerability.
    print "ERROR: V == P (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes),len(v_to_p_mapping), 0, 0,0)
    exit()

#################### positive vGraph GENERATION #############################
if len(v_to_p_mapping) == len(V.nodes):
    # all V nodes are in patch.  So treat all nodes in V as positive core graph
    pvg = V.copy()
else:
    pvg = nx.DiGraph()
    # Add all nodes in V that were missing from P (i.e. removed from patch)
    for v_node in set(V.nodes).difference(set(v_to_p_mapping.keys())):
        pvg.add_node(v_node)
        pvg.node[v_node]['type'] = V.node[v_node]['type']
        pvg.node[v_node]['code'] = V.node[v_node]['code']
        pvg.node[v_node]['style'] = 'o'
            
    add_edges(pvg, V)
    connect_graph(pvg, V) # we need a connected graph to do our matching

    # Keep adding nodes until we meet our minimum node size
    while len(pvg.nodes) < MIN_NODES and len(pvg.nodes) < len(V.nodes):
        expand_graph(pvg, V)

    pvg_imp_nodes=get_important_nodes(pvg)
    pvg_bfs_trees=get_bfs_trees(pvg, pvg_imp_nodes)

################## negative vGraph GENERATION ############################
if len(v_to_p_mapping) == len(P.nodes):
    # All P nodes are shared with V.  So all nodes in P are negative core graph
    # as with above, this could probably be modified to use heuristic to only
    # include nodes which are related to the nodes removed from V
    nvg = P.copy()
else:
    nvg = nx.DiGraph()
    # Add all nodes in P that were missing from V (i.e. added during patch)
    for p_node in set(P.nodes).difference(set(p_to_v_mapping.keys())):
        nvg.add_node(p_node)
        nvg.node[p_node]['type'] = P.node[p_node]['type']
        nvg.node[p_node]['code'] = P.node[p_node]['code']
        nvg.node[p_node]['style'] = 'o'

    add_edges(nvg, P)
    connect_graph(nvg, P)
    while len(nvg.nodes) < MIN_NODES and len(nvg.nodes) < len(P.nodes):
        expand_graph(nvg, P)

    nvg_imp_nodes=get_important_nodes(pvg)
    nvg_bfs_trees=get_bfs_trees(nvg, nvg_imp_nodes)

#################### context vGraph #############################
# For each node in pos, neg graphs
# add nodes in context space that have edges into those graphs
cvg = nx.DiGraph()
for n in v_to_p_mapping: # These are all shared nodes
    if n in pvg.nodes or v_to_p_mapping[n] in nvg.nodes:
        # these nodes were added during expand_graph
        # skip them so we dont overlap (or should we overlap??)
        continue

    added=False
    for n2 in list(V.predecessors(n)) + list(V.successors(n)):
        if n2 in pvg.nodes:
            # Found context node because it has incoming or outgoing edge into PVG
            cvg.add_node(n)
            cvg.node[n]['type'] = V.node[n]['type']
            cvg.node[n]['code'] = V.node[n]['code']
            added=True
            break
    if added: 
        continue # already added so just move on
    # otherwise lets check patch nodes

    for n2 in list(P.predecessors(v_to_p_mapping[n])) + list(P.successors(v_to_p_mapping[n])):
        if n2 in nvg.nodes:
            # Found context node because it has incoming or outgoing edge into NVG
            cvg.add_node(n)
            cvg.node[n]['type'] = V.node[n]['type']
            cvg.node[n]['code'] = V.node[n]['code']
            break

add_edges(cvg, V) # shared nodes so V==P for these nodes
connect_graph(cvg, V)

# Expand until minimum length is met
while len(cvg.nodes) < MIN_CONTEXT_NODES and len(cvg) < (len(V.nodes) - len(pvg.nodes)):
    expand_graph(cvg, V)

cvg_imp_nodes=get_important_nodes(cvg)
cvg_bfs_trees=get_bfs_trees(cvg, cvg_imp_nodes)


###############    Final Sanity Checks: ###########################
if len(pvg.nodes) < MIN_NODES or len(nvg.nodes) < MIN_NODES or len(cvg.nodes)< MIN_NODES:
    print "ERROR: vGraph too small (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes), len(cvg.nodes) )
    exit()

if not nx.is_connected(pvg.to_undirected()):
    print "ERROR: PVG not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes), len(cvg.nodes) )
    exit()

if not nx.is_connected(nvg.to_undirected()):
    print "ERROR: NVG not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes), len(cvg.nodes) )
    exit()

if not nx.is_connected(cvg.to_undirected()):
    print "ERROR: CVG not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes), len(cvg.nodes) )
    exit()

# If we get here we are good
if not os.path.exists(output_path):
    os.makedirs(output_path)

# Write vGraph files
nx.write_gpickle(pvg, pvg_output_file)
nx.write_gpickle(nvg, nvg_output_file)
nx.write_gpickle(cvg, cvg_output_file)

# Write important nodes files
pkl.dump(pvg_imp_nodes, open(pvg_imp_nodes_output_file, 'w'))
pkl.dump(nvg_imp_nodes, open(nvg_imp_nodes_output_file, 'w'))
pkl.dump(cvg_imp_nodes, open(cvg_imp_nodes_output_file, 'w'))

# Write BFS trees
pkl.dump(pvg_bfs_trees, open(pvg_bfs_trees_output_file, 'w'))
pkl.dump(nvg_bfs_trees, open(nvg_bfs_trees_output_file, 'w'))
pkl.dump(cvg_bfs_trees, open(cvg_bfs_trees_output_file, 'w'))

# Print final statistics
print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes), len(nvg.nodes), len(cvg.nodes))
