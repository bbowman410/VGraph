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

context_mapping_output_file = in_out_dir + function_name + ".context_mapping"

CVG_size_file = in_out_dir + function_name + "_size"

# Read graphs
V = nx.read_gpickle(vuln_function)
print len(V.edges())
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
print "V size: %d" % len(V.nodes)
print "P size: %d" % len(P.nodes)
print "Number of shared nodes (SN): %d" % len(node_mapping)
print "PFG base size (V - SN): %d" % (len(V.nodes) - len(node_mapping))
print "NFG base size (P-SN): %d" % (len(P.nodes) - len(node_mapping))

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

# sanity check...
pcvg_index = set([])
for (a,b) in pCVG.edges():
    pcvg_index.add((pCVG.node[a]['type'], pCVG[a][b]['type'], pCVG.node[b]['type']))
    pcvg_index.add((pCVG.node[b]['type'], pCVG[b][a]['type'], pCVG.node[a]['type'])) # reverse it also
v_index = set([])
for (a,b) in V.edges():
    v_index.add((V.node[a]['type'], V[a][b]['type'], V.node[b]['type']))
    v_index.add((V.node[b]['type'], V[b][a]['type'], V.node[a]['type']))# reverse it also

#print "index set overlap score"
overlap = pcvg_index.intersection(v_index)
missing = pcvg_index - v_index
#print "MISSSSING============"
#for entry in missing:
#    print entry
#print "HAS===========" 
#for entry in v_index:
#    print entry
#print "%d" % ((len(overlap)*100)/len(pcvg_index))
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
# Instead of doing this check... lets just see if it can differentiate between
# vuln & patch...



################## NEW STUFF
pCVG_nhi = tale.generate_nh_index(pCVG)
nCVG_nhi = tale.generate_nh_index(nCVG)
v_nhi = tale.generate_nh_index(V)
p_nhi = tale.generate_nh_index(P)
vuln_pos_score, vuln_pos_mapping, vuln_imp_node_score = tale.match(pCVG, V, pCVG_nhi,v_nhi, pCVG_important_nodes, {}) 
# Prematched node determination
vuln_context_nodes = set(vuln_pos_mapping.keys()).intersection(set(node_mapping.keys()))
# now we essentially want to pre-match those nodes in the nCVG
vuln_prematched_nodes = {}
for n in vuln_context_nodes:
    # 2 things we need to do here - convert our pCVG node to a nCVG node with the
    # context mapping, and set the match in the target graph to the same as
    # what was in the pos_node_mapping (if it was mapped)
    if n in vuln_pos_mapping and node_mapping[n][0] in nCVG:
        vuln_prematched_nodes[node_mapping[n][0]] = vuln_pos_mapping[n]

# Evaluating nCVG
#vuln_neg_score, vuln_neg_mapping, vuln_neg_imp_node_score = tale.match(nCVG, V, nCVG_nhi, v_nhi, nCVG_important_nodes, vuln_prematched_nodes)
vuln_neg_score, vuln_neg_mapping, vuln_neg_imp_node_score = tale.match(nCVG, V, nCVG_nhi, v_nhi, nCVG_important_nodes, {}) # screw prematching nodes

## Now do it all again for patch
patch_pos_score, patch_pos_mapping, patch_imp_node_score = tale.match(pCVG, P, pCVG_nhi,p_nhi, pCVG_important_nodes, {}) 
# Prematched node determination
patch_context_nodes = set(patch_pos_mapping.keys()).intersection(set(node_mapping.keys()))
# now we essentially want to pre-match those nodes in the nCVG
patch_prematched_nodes = {}
for n in patch_context_nodes:
    # 2 things we need to do here - convert our pCVG node to a nCVG node with the
    # context mapping, and set the match in the target graph to the same as
    # what was in the pos_node_mapping (if it was mapped)
    if n in patch_pos_mapping and node_mapping[n][0] in nCVG:
        patch_prematched_nodes[node_mapping[n][0]] = patch_pos_mapping[n]

# Evaluating nCVG
#patch_neg_score, patch_neg_mapping, patch_neg_imp_node_score = tale.match(nCVG, V, nCVG_nhi, v_nhi, nCVG_important_nodes, patch_prematched_nodes)
patch_neg_score, patch_neg_mapping, patch_neg_imp_node_score = tale.match(nCVG, P, nCVG_nhi, p_nhi, nCVG_important_nodes, {}) # Screw prematching nodes

# Now we can compare vuln_pos_score, vuln_neg_score, patch_pos_score, patch_neg_score
print "+vGraph vs. V score: %d" % vuln_pos_score
print "-vGraph vs. V score: %d" % vuln_neg_score
print "+vGraph vs. P score: %d" % patch_pos_score
print "-vGraph vs. P score: %d" % patch_neg_score
if vuln_pos_score < vuln_neg_score or patch_pos_score > patch_neg_score:
    print "ERROR: vGraph not able to determine difference b/t vuln and patch.  Aborting."
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pCVG.nodes),len(nCVG.nodes) )
    exit()

#if len(pCVG.nodes) < 200:
#    print "ERROR: pCVG too small (%s)" % vuln_function
#    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pCVG.nodes),len(nCVG.nodes) )
#    exit()


# Write core graph files
nx.write_gpickle(pCVG, pCVG_output_file)
nx.write_gpickle(nCVG, nCVG_output_file)

# Write important nodes
pkl.dump(pCVG_important_nodes, open(pCVG_important_nodes_output_file, 'wb'))
pkl.dump(nCVG_important_nodes, open(nCVG_important_nodes_output_file, 'wb'))

# Write mapping of pCVG to nCVG so we know what nodes are context nodes
pkl.dump(node_mapping, open(context_mapping_output_file, 'wb'))

# Write size
CVG_size = (len(V.node) + len(P.nodes)) / 2
pkl.dump(CVG_size, open(CVG_size_file, 'wb'))

print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(node_mapping), len(pCVG.nodes), len(nCVG.nodes))


