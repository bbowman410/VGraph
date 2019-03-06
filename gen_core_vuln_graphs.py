import os
import sys
import networkx as nx
import pickle as pkl
import tale

# Some nodes we don't want to pivot through while growing the graph
SKIP_TYPES=['CFGEntryNode', 'CFGExitNode', 'FunctionDef']
MIN_NODES=30

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


def print_statistics(file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size):
    print "%s\t%d\t%d\t%d\t%d\t%d" % (file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size)


def add_edges(graph_nodes_only, full_graph):
    # finish graph by adding relevant edges
    for n in graph_nodes_only.nodes:
        for neighbor in full_graph[n]:
            if neighbor in graph_nodes_only.nodes:
                graph_nodes_only.add_edge(n,neighbor)
                graph_nodes_only[n][neighbor]['type'] = full_graph[n][neighbor]['type']


# This function is for matching nodes from vuln/patch graphs
# This means majority of the graph structure will be the same
# So we can take some shortcuts here
def heuristic_match(src_graph, dst_graph):
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
    print "Usage: python gen_core_vuln_graphs.py <vuln_graph> <patch_graph> <output_path> <output_name>"
    exit()

vuln_graph = sys.argv[1]
patch_graph = sys.argv[2]
output_path = sys.argv[3]
output_name= sys.argv[4]
vuln_function = output_path + '/' + output_name
pvg_output_file = output_path + '/' + output_name  + "_pvg.gpickle"
nvg_output_file = output_path + '/' + output_name + "_nvg.gpickle"
context_mapping_output_file = output_path + '/' + output_name + ".context_mapping"
context_graph_output_file = output_path + '/' + output_name + "_context.gpickle"

# Read graphs
V = nx.read_gpickle(vuln_graph)
P = nx.read_gpickle(patch_graph)
print "V size: %d" % len(V.nodes)
print "P size: %d" % len(P.nodes)

# Heuristic graph match
v_to_p_mapping, p_to_v_mapping = heuristic_match(V,P)

print "Number of shared nodes (SN): %d" % len(v_to_p_mapping)
print "Positive vGraph base size (V - SN): %d" % (len(V.nodes) - len(v_to_p_mapping))
print "Negative vGraph base size (P-SN): %d" % (len(P.nodes) - len(v_to_p_mapping))

if len(V.nodes) == len(P.nodes) == len(v_to_p_mapping):
    # This case doesn't make sense.  Clearly this vulnerability does not show manifest itself
    # in a way that will work with our method.
    print "ERROR: V == P (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes),len(v_to_p_mapping), 0, 0)
    exit()

#################### positive vGraph GENERATION #############################
if len(v_to_p_mapping) == len(V.nodes):
    # all V nodes are in patch.  So treat all nodes in V as positive core graph
    # This could probably be modified to use a heuristic to include only the nodes
    # which are related to the new nodes in patch graph in some way.
    pvg = V.copy()
else:
    pvg = nx.DiGraph()
    # Add all nodes in V that were missing from P (i.e. removed from patch)
    for v_node in set(V.nodes).difference(set(v_to_p_mapping.keys())):
        pvg.add_node(v_node)
        pvg.node[v_node]['type'] = V.node[v_node]['type']
        pvg.node[v_node]['code'] = V.node[v_node]['code']
        
    add_edges(pvg, V)
    connect_graph(pvg, V)
    while len(pvg.nodes) < MIN_NODES and len(pvg.nodes) < len(V.nodes):
        expand_graph(pvg, V)

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

    add_edges(nvg, P)
    connect_graph(nvg, P)
    while len(nvg.nodes) < MIN_NODES and len(nvg.nodes) < len(P.nodes):
        expand_graph(nvg, P)

#################### context vGraph #############################
context_graph = nx.DiGraph()
for n in v_to_p_mapping:
    if n in pvg.nodes or v_to_p_mapping[n] in nvg.nodes:
        # these nodes were added during expand_graph
        # skip them so we dont overlap (or should we overlap??)
        continue

    # othrwise these are truely context nodes
    context_graph.add_node(n)
    context_graph.node[n]['type'] = V.node[n]['type']
    context_graph.node[n]['code'] = V.node[n]['code']

add_edges(context_graph, V)
connect_graph(context_graph, V)

if len(pvg.nodes) < MIN_NODES or len(nvg.nodes) < MIN_NODES or len(context_graph.nodes)< MIN_NODES:
    print "ERROR: vGraph too small (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

# Sanity checks.  These should always be connected...
if not nx.is_connected(pvg.to_undirected()):
    print "ERROR: pvg not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

if not nx.is_connected(nvg.to_undirected()):
    print "ERROR: nvg not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

if not nx.is_connected(context_graph.to_undirected()):
    print "ERROR: context not connected"
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

# If we get here we are good
if not os.path.exists(output_path):
    os.makedirs(output_path)

# Write vGraph files
nx.write_gpickle(pvg, pvg_output_file)
nx.write_gpickle(nvg, nvg_output_file)
nx.write_gpickle(context_graph, context_graph_output_file)

# Write mapping of pvg to nvg so we know what nodes are context nodes
pkl.dump(v_to_p_mapping, open(context_mapping_output_file, 'w'))

# Print final statistics
print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(v_to_p_mapping), len(pvg.nodes), len(nvg.nodes))
