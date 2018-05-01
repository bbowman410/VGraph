import sys
import networkx as nx
import pickle as pkl

def expand_graph(small_graph, big_graph, num_hops):
    for unused in range(num_hops):
        # loop through all nodes in small graph and add neighbors
        nodes_to_add = []
        for n in small_graph.nodes:
            for neighbor in big_graph[n]:
                nodes_to_add.append(neighbor)

        for n in nodes_to_add:
            if n not in small_graph.nodes:
                small_graph.add_node(n)
                small_graph.node[n]['type'] = big_graph.node[n]['type']


def print_statistics(file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size):
    print "%s\t%d\t%d\t%d\t%d\t%d" % (file_path, v_size, p_size, num_shared_nodes, pcvg_size, ncvg_size)


def add_edges(graph_nodes_only, full_graph):
    # finish graph by adding relevant edges
    for n in graph_nodes_only.nodes:
        for neighbor in full_graph[n]:
            if neighbor in graph_nodes_only.nodes:
                graph_nodes_only.add_edge(n,neighbor)
                graph_nodes_only[n][neighbor]['type'] = full_graph[n][neighbor]['type']


def heuristic_match(src_graph, dst_graph):
    node_mapping = {}
    for src_node in src_graph.nodes:
        for dst_node in dst_graph.nodes:
            if dst_node in [ n for (n,s) in node_mapping.values() ]:
                continue # we don't want to double match
            if src_graph.node[src_node]['code'] == dst_graph.node[dst_node]['code'] and src_graph.node[src_node]['type'] == dst_graph.node[dst_node]['type']:
                node_mapping[src_node] = (dst_node, 2) # This is how TALE repors scores.. so just using this format for convenience
                break

    return node_mapping

###############################################

if len(sys.argv) != 3:
    print "Usage: python gen_core_vuln_graphs.py <function_name> <in-out dir>"
    exit()

function_name = sys.argv[1]
in_out_dir = sys.argv[2]
vuln_function = in_out_dir + "/vuln/" + function_name + ".gpickle"
patch_function = in_out_dir + "/patch/" + function_name + ".gpickle"

pCVG_output_file = in_out_dir + function_name + "_pfg.gpickle"
pCVG_important_nodes_output_file = in_out_dir + function_name + "_pfg.important_nodes"

nCVG_output_file = in_out_dir + function_name + "_nfg.gpickle"
nCVG_important_nodes_output_file = in_out_dir + function_name + "_nfg.important_nodes"

# Read graphs
V = nx.read_gpickle(vuln_function)
P = nx.read_gpickle(patch_function)

# Keep list of important nodes for graph matching prioritization
pCVG_important_nodes = []
nCVG_important_nodes = []

# If we don't do this it takes WAY to long to do the heuristic match
if len(V.nodes) > 2000 or len(P.nodes) > 2000:
    print "ERROR: CPG too big (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes),0,0,0)
    exit()

# Heuristic graph match
node_mapping = heuristic_match(V,P)

#print "Number of shared nodes (SN): %d" % len(node_mapping)
#print "PFG base size (V - SN): %d" % (len(V.nodes) - len(node_mapping))
#print "NFG base size (P-SN): %d" % (len(P.nodes) - len(node_mapping))
if len(V.nodes) == len(P.nodes) == len(node_mapping):
    # This case doesn't make sense.  Clearly this vulnerability does not show manifest itself
    # in a way that will work with our method.
    print_statistics(vuln_function, len(V.nodes), len(P.nodes),len(node_mapping), 0, 0)
    exit()

#################### pCVG GENERATION #############################
if len(node_mapping) == len(V.nodes):
    # all V nodes are in patch.  So treat all nodes in V as positive core graph
    # This could probably be modified to use a heuristic to include only the nodes
    # which are related to the new nodes in patch graph in some way.
    pCVG = V.copy()
    for n in pCVG.nodes:
        pCVG_important_nodes.append(n)
else:
    pCVG = nx.Graph()
    # positive Core Vulnerability Graph (pCVG) includes all nodes in V that were removed in P
    for v_node in set(V.nodes).difference(set(node_mapping.keys())):
        pCVG.add_node(v_node)
        pCVG.node[v_node]['type'] = V.node[v_node]['type']
        pCVG.node[v_node]['code'] = V.node[v_node]['code']
    # We keep track of the core nodes for our graph matching algorithm later
    for n in pCVG.nodes:
        pCVG_important_nodes.append(n)

    # expand graph to gain some context
    expand_graph(pCVG, V, 2)

    # Add all edges to our graph nodes
    add_edges(pCVG, V)

################## nCVG GENERATION ############################
if len(node_mapping) == len(P.nodes):
    # All P nodes are shared with V.  So all nodes in P are negative core graph
    # as with above, this could probably be modified to use heuristic to only
    # include nodes which are related to the nodes removed from V
    nCVG = P.copy()
    for n in nCVG.nodes:
        nCVG_important_nodes.append(n)
else:
    nCVG = nx.Graph()
    # negative Core Vulnerability Graph (nCVG) includes all nodes in P that were missing in V
    for p_node in set(P.nodes).difference(set([nid for (nid,score) in node_mapping.values()])):
        nCVG.add_node(p_node)
        nCVG.node[p_node]['type'] = P.node[p_node]['type']
        nCVG.node[p_node]['code'] = P.node[p_node]['code']
    # We keep track of the core nodes for our graph matching algorithm later
    for n in nCVG.nodes:
        nCVG_important_nodes.append(n)

    # expand graph to gain some context
    expand_graph(nCVG, P, 2)

    # Add all edges to our graph nodes
    add_edges(nCVG, P)


# Last minute sanity check to make sure our representation will work
if len(pCVG.nodes) < 50 or len(pCVG_important_nodes) < 10:
    print "ERROR: pCVG too small (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pCVG.nodes),len(nCVG.nodes) )
    exit()

# Write core graph files
nx.write_gpickle(pCVG, pCVG_output_file)
nx.write_gpickle(nCVG, nCVG_output_file)

# Write important nodes
pkl.dump(pCVG_important_nodes, open(pCVG_important_nodes_output_file, 'wb'))
pkl.dump(nCVG_important_nodes, open(nCVG_important_nodes_output_file, 'wb'))

print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pCVG.nodes), len(nCVG.nodes))


