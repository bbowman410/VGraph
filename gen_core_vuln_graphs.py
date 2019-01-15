import os
import sys
import networkx as nx
import pickle as pkl
import tale

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
                if 'code' in big_graph.node[n]:
                    small_graph.node[n]['code'] = big_graph.node[n]['code']



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
            if src_graph.node[src_node]['code'] == dst_graph.node[dst_node]['code'] and src_graph.node[src_node]['type'] == dst_graph.node[dst_node]['type'] and src_graph.degree(src_node) == dst_graph.degree(dst_node):
                node_mapping[src_node] = (dst_node, 2) # This is how TALE repors scores.. so just using this format for convenience
                break

    return node_mapping

###############################################

if len(sys.argv) != 5:
    print "Usage: python gen_core_vuln_graphs.py <vuln_graph> <patch_graph> <output_path> <output_name>"
    exit()

vuln_graph = sys.argv[1]
patch_graph = sys.argv[2]
output_path = sys.argv[3]
output_name= sys.argv[4]
vuln_function = output_path + '/' + output_name
#function_name = sys.argv[1]
#input_dir = sys.argv[2]
#output_dir = sys.argv[3]
#vuln_function = in_out_dir + "/vuln/" + function_name + ".gpickle"
#patch_function = in_out_dir + "/patch/" + function_name + ".gpickle"

pvg_output_file = output_path + '/' + output_name  + "_pvg.gpickle"
#pvg_important_nodes_output_file = in_out_dir + function_name + "_pfg.important_nodes"

nvg_output_file = output_path + '/' + output_name + "_nvg.gpickle"
#nvg_important_nodes_output_file = in_out_dir + function_name + "_nfg.important_nodes"

context_mapping_output_file = output_path + '/' + output_name + ".context_mapping"

#CVG_size_file = in_out_dir + function_name + "_size"

# Read graphs
V = nx.read_gpickle(vuln_graph)
P = nx.read_gpickle(patch_graph)
print "V size: %d" % len(V.nodes)
print "P size: %d" % len(P.nodes)

# Keep list of important nodes for graph matching prioritization
#pvg_important_nodes = []
#nvg_important_nodes = []

# If we don't do this it takes WAY to long to do the heuristic match
#if len(V.nodes) > 2000 or len(P.nodes) > 2000:
#    print "ERROR: CPG too big (%s)" % vuln_function
#    print_statistics(vuln_function, len(V.nodes), len(P.nodes),0,0,0)
#    exit()

# Heuristic graph match
node_mapping = heuristic_match(V,P)
print "Number of shared nodes (SN): %d" % len(node_mapping)
print "Positive vGraph base size (V - SN): %d" % (len(V.nodes) - len(node_mapping))
print "Negative vGraph base size (P-SN): %d" % (len(P.nodes) - len(node_mapping))

#for entry in node_mapping:
#    print '================'
#    print V.node[entry]
#    print P.node[node_mapping[entry][0]]

if len(V.nodes) == len(P.nodes) == len(node_mapping):
    # This case doesn't make sense.  Clearly this vulnerability does not show manifest itself
    # in a way that will work with our method.
    print "ERROR: V == P (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes),len(node_mapping), 0, 0)
    exit()

#################### positive vGraph GENERATION #############################
if len(node_mapping) == len(V.nodes):
    # all V nodes are in patch.  So treat all nodes in V as positive core graph
    # This could probably be modified to use a heuristic to include only the nodes
    # which are related to the new nodes in patch graph in some way.
    pvg = V.copy()
    #for n in pvg.nodes:
    #    pvg_important_nodes.append(n)
else:
    pvg = nx.Graph()
    # positive Core Vulnerability Graph (pvg) includes all nodes in V that were removed in P
    for v_node in set(V.nodes).difference(set(node_mapping.keys())):
        pvg.add_node(v_node)
        pvg.node[v_node]['type'] = V.node[v_node]['type']
        pvg.node[v_node]['code'] = V.node[v_node]['code']
    # We keep track of the core nodes for our graph matching algorithm later
    #for n in pvg.nodes:
    #    pvg_important_nodes.append(n)

    # expand graph to gain some context
    expand_graph(pvg, V, 2)

    # Add all edges to our graph nodes
    add_edges(pvg, V)

################## negative vGraph GENERATION ############################
if len(node_mapping) == len(P.nodes):
    # All P nodes are shared with V.  So all nodes in P are negative core graph
    # as with above, this could probably be modified to use heuristic to only
    # include nodes which are related to the nodes removed from V
    nvg = P.copy()
    #for n in nvg.nodes:
    #    nvg_important_nodes.append(n)
else:
    nvg = nx.Graph()
    # negative Core Vulnerability Graph (nvg) includes all nodes in P that were missing in V
    for p_node in set(P.nodes).difference(set([nid for (nid,score) in node_mapping.values()])):
        nvg.add_node(p_node)
        nvg.node[p_node]['type'] = P.node[p_node]['type']
        nvg.node[p_node]['code'] = P.node[p_node]['code']
    # We keep track of the core nodes for our graph matching algorithm later
    #for n in nvg.nodes:
    #    nvg_important_nodes.append(n)

    # expand graph to gain some context
    expand_graph(nvg, P, 2)

    # Add all edges to our graph nodes
    add_edges(nvg, P)

# Generate NHI for vGraph
pvg_nhi = tale.generate_nh_index(pvg)
nvg_nhi = tale.generate_nh_index(nvg)

# Generate NHI for original vuln and patch functions
v_nhi = tale.generate_nh_index(V)
p_nhi = tale.generate_nh_index(P)

# Test positive vGraph against original vulnerable function
vuln_pos_score, vuln_pos_mapping, vuln_imp_node_score = tale.match(pvg, V, pvg_nhi,v_nhi, None, {}) 

# Prematched node determination.. not doing prematching of nodes anymore?
#vuln_context_nodes = set(vuln_pos_mapping.keys()).intersection(set(node_mapping.keys()))
# now we essentially want to pre-match those nodes in the nvg
#vuln_prematched_nodes = {}
#for n in vuln_context_nodes:
    # 2 things we need to do here - convert our pvg node to a nvg node with the
    # context mapping, and set the match in the target graph to the same as
    # what was in the pos_node_mapping (if it was mapped)
#    if n in vuln_pos_mapping and node_mapping[n][0] in nvg:
#        vuln_prematched_nodes[node_mapping[n][0]] = vuln_pos_mapping[n]

# Evaluating nvg
#vuln_neg_score, vuln_neg_mapping, vuln_neg_imp_node_score = tale.match(nvg, V, nvg_nhi, v_nhi, nvg_important_nodes, vuln_prematched_nodes)

# Test negative vGraph against original vulnerable function
vuln_neg_score, vuln_neg_mapping, vuln_neg_imp_node_score = tale.match(nvg, V, nvg_nhi, v_nhi, None, {}) # screw prematching nodes

## Now do it all again for patch
patch_pos_score, patch_pos_mapping, patch_imp_node_score = tale.match(pvg, P, pvg_nhi,p_nhi, None, {}) 
# Prematched node determination
#patch_context_nodes = set(patch_pos_mapping.keys()).intersection(set(node_mapping.keys()))
# now we essentially want to pre-match those nodes in the nvg
#patch_prematched_nodes = {}
#for n in patch_context_nodes:
    # 2 things we need to do here - convert our pvg node to a nvg node with the
    # context mapping, and set the match in the target graph to the same as
    # what was in the pos_node_mapping (if it was mapped)
#    if n in patch_pos_mapping and node_mapping[n][0] in nvg:
#        patch_prematched_nodes[node_mapping[n][0]] = patch_pos_mapping[n]

# Evaluating nvg
#patch_neg_score, patch_neg_mapping, patch_neg_imp_node_score = tale.match(nvg, V, nvg_nhi, v_nhi, nvg_important_nodes, patch_prematched_nodes)
patch_neg_score, patch_neg_mapping, patch_neg_imp_node_score = tale.match(nvg, P, nvg_nhi, p_nhi, None, {}) # Screw prematching nodes

# Now we can compare vuln_pos_score, vuln_neg_score, patch_pos_score, patch_neg_score
print "+vGraph vs. V score: %d" % vuln_pos_score
print "-vGraph vs. V score: %d" % vuln_neg_score
print "+vGraph vs. P score: %d" % patch_pos_score
print "-vGraph vs. P score: %d" % patch_neg_score
if vuln_pos_score < vuln_neg_score or patch_pos_score > patch_neg_score:
    print "ERROR: vGraph not able to determine difference b/t vuln and patch.  Aborting."
    # TODO: rather than abort, couldnt we just add more context until either (1) function is exhausted or (2) graph is expressive enough?
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

if len(pvg.nodes) < 30 or len(nvg.nodes) < 30:
    print "ERROR: vGraph too small (%s)" % vuln_function
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pvg.nodes),len(nvg.nodes) )
    exit()

# If we get here, then were good!
if not os.path.exists(output_path):
    os.makedirs(output_path)


# Write vGraph files
nx.write_gpickle(pvg, pvg_output_file)
nx.write_gpickle(nvg, nvg_output_file)

# Write important nodes
#pkl.dump(pvg_important_nodes, open(pvg_important_nodes_output_file, 'wb'))
#pkl.dump(nvg_important_nodes, open(nvg_important_nodes_output_file, 'wb'))

# Write mapping of pvg to nvg so we know what nodes are context nodes
pkl.dump(node_mapping, open(context_mapping_output_file, 'w'))

# Write size
#CVG_size = (len(V.node) + len(P.nodes)) / 2
#pkl.dump(CVG_size, open(CVG_size_file, 'wb'))

print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pvg.nodes), len(nvg.nodes))


