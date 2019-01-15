import networkx as nx
from difflib import SequenceMatcher

# Generate neighborhood index for all nodes in graph g
def generate_nh_index(g):
    nh_idx = {}
    for n in g.nodes:
        nh_idx[n] = node_nh_idx(g,n)
    return nh_idx

# Generate neighhood index for an individual node
def node_nh_idx(g, n):
    d = {}
    d['label'] = g.node[n]['type']
    if 'code' in g.node[n]:
        d['code'] = g.node[n]['code']
    d['degree'] = g.degree(n)
    d['nbConnection'] = 0
    d['nbArray'] = []
    d['edgeArray'] = []
    for nb in g.neighbors(n):
        # Building list of labels
        if g.node[nb]['type'] not in d['nbArray']:
            d['nbArray'].append(g.node[nb]['type'])

        if g[n][nb]['type'] not in d['edgeArray']:
            d['edgeArray'].append(g[n][nb]['type'])

        # Keeping track of neighbor connectedness
        d['nbConnection'] = d['nbConnection'] + len(set(g.neighbors(nb)).intersection(set(g.neighbors(n))))

    # Double counted...so divide by two
    d['nbConnection'] = d['nbConnection'] / 2
    return d

# Entry function for matching two graphs
def match(query_graph, target_graph, query_nh_index, target_nh_index, r = 0.1, p = 0.5, prematched_nodes = None):
  
    # Determine the important nodes in our query graph
    important_nodes = find_important_nodes(query_graph, p)

    # Match the important nodes to our target graph
    weight_mappings = match_important_nodes(important_nodes, query_nh_index, target_nh_index, prematched_nodes, r)
   
    # Grow the match
    res = grow_match(query_graph, target_graph, query_nh_index, target_nh_index, weight_mappings, prematched_nodes, r)

    # Calculate overall match score
    # Each match can have a weight (aka score) of at most 2
    total_possible_score = 2 * len(query_graph.nodes)
    achieved_score = 0
    for n in res:
        achieved_score += res[n][1]

    overall_score = int((achieved_score * 100) / total_possible_score)
    
    if overall_score > 100:
        print "Well this is not right.."
        print "Length of query graph: %d" % len(query_graph.nodes)
        print "Length of target graph: %d" % len(target_graph.nodes)
        print "Length of mapping: %d" % len(res)
     

    return (overall_score, res)



def grow_match(query_graph, target_graph, query_nh_index, target_nh_index, weight_mapping, prematched_nodes, r):
    processing_queue = []
    if prematched_nodes is not None:
        final_results = prematched_nodes
    else:
        final_results = {}
    # Add our important nodes to the processing queue
    # we build weight_mapping_helper which will make it easier to sort
    weight_mapping_helper = {}
    for n in weight_mapping:
        weight_mapping_helper[n] = weight_mapping[n][1] # This is the score

    # Add to processing_queue with highest scores first (FIFO)
    for n, v in reversed(sorted(weight_mapping_helper.iteritems(), key=lambda(k,v):(v,k))):
        # This is adding our 1-1 mapping of important nodes to processing queue
        processing_queue.append((n, weight_mapping[n][0]))

    while len(processing_queue) > 0:
        # adding single match to final result
        (n_query, n_target) = processing_queue.pop(0)
        final_results[n_query] = (n_target, weight_mapping[n_query][1])

        # Need to check neighbors of n_query not yet matched
        nb_query = set(query_graph.neighbors(n_query)).difference(set(final_results.keys()))

        # Get all nodes 2 hops away, not in our final results
        nb_query_2_hops = []
        for x in query_graph.neighbors(n_query):
            nb_query_2_hops = set(nb_query_2_hops).union(set(query_graph.neighbors(x)))
        nb_query_2_hops = set(nb_query_2_hops).difference(set(nb_query)).difference(set(final_results.keys()))

        # Get all db nodes that are neighbors of last matching db node which are not
        # in final result or processing queue
        nb_target = set(target_graph.neighbors(n_target)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

        # target nodes that are 2 hops away
        nb_target_2_hops = []
        for x in target_graph.neighbors(n_target):
            nb_target_2_hops = set(nb_target_2_hops).union(set(target_graph.neighbors(x)))
        nb_target_2_hops = set(nb_target_2_hops).difference(set(nb_target)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

        # Sanity check on these sets...
        query_final = final_results.keys()
        target_final = final_results.values()
        query_processing = [ a for (a,b) in processing_queue ]
        target_processing = [ b for (a,b) in processing_queue ]
        for n in nb_query:
            if n in query_final:
                print "Found node in final query mapping"
                exit()
        for n in nb_query_2_hops:
            if n in query_final:
                print "Found 2-hop node in final query mapping"
                exit()

        for n in nb_target:
            if n in [ a for (a,b) in target_final]:
                print "Found db node in final db mapping"
                exit()
            if n in target_processing:
                print "Found db node in processing db mapping"
                exit()
        for n in nb_target_2_hops:
            if n in [ a for (a,b) in target_final]:
                print "Found 2-hop db node in final db mapping"
                exit()
            if n in target_processing:
                print "Found 2-hop db node in processing db mapping"
                exit()

        # Lets check to see if weight_mapping is still 1-1
        test = {}
        for k,v in final_results.iteritems():
            if v in test:
                print "NOT 1-1!"
                print v
                print test[v]
                print k
                print "databse node %d mapped to query nodes: %d and %d" % (v, test[v], k)
                exit()

            else:
                test[v] = k


        match_nodes(query_nh_index, target_nh_index, nb_query, nb_target, processing_queue, weight_mapping, r)
        match_nodes(query_nh_index, target_nh_index, nb_query, nb_target_2_hops, processing_queue, weight_mapping, r)
        match_nodes(query_nh_index, target_nh_index, nb_query_2_hops, nb_target, processing_queue, weight_mapping, r)

    return final_results

def match_nodes(query_nh_index, target_nh_index, query_nodes, target_nodes, processing_queue, weight_mapping, r):
    for q in query_nodes:
        best_match = None
        for target in target_nodes:
            (is_match, score) = match_and_score_nhi(query_nh_index[q], target_nh_index[target], r)
            if is_match:
                if best_match is None:
                    best_match = (target, score)
                else:
                    if score > best_match[1]:
                        best_match = (target, score)
	if best_match is None:
            # Unable to match this node...just skip it...
            continue

	if q not in [a for (a,b) in processing_queue]:
	    if best_match[0] in [b for (a,b) in processing_queue]:
	        print "somehow we are tryping to add a DB node thats already in processing queu"
	        exit()
            processing_queue.append((q, best_match[0]))
	    weight_mapping[q] = best_match
	    target_nodes.remove(best_match[0])
	else:
	    # This node already in processing q
	    # need to check score and see if we should replace
	    if best_match[1] > weight_mapping[q][1]:
	        processing_queue[processing_queue.index((q, weight_mapping[q][0]))] = (q, best_match[0])
	        weight_mapping[q] = best_match
	        target_nodes.remove(best_match[0])



def find_matching_nodes(query_nh_index, target_nh_index, query_node, r):
    # we want to return all nodes in target graph that match our query node
    query_nhi = query_nh_index[query_node]
    matching_target_nodes = []
    for node, nh_idx in target_nh_index.iteritems():
	is_match, score = match_and_score_nhi(query_nhi, nh_idx, r)
	if is_match:
	    matching_target_nodes.append((node, score))
    return matching_target_nodes

def find_important_nodes(graph, p):
    """ Returns a list of important nodes (based on degree, top P_imp percent) """
    #P_imp = 0.2

    # import based on degree centrality
    node_degree_dict = {}
    nodes_to_return = int(len(graph.nodes) * p)
    for n in graph.nodes:
        node_degree_dict[n] = graph.degree(n)

    important_nodes = []
    for node_id, degree in reversed(sorted(node_degree_dict.iteritems(), key=lambda (k,v): (v,k))):
        important_nodes.append(node_id)
        nodes_to_return = nodes_to_return - 1
        if nodes_to_return <= 0:
            break
    return important_nodes


def match_important_nodes(important_nodes, query_nh_index, target_nh_index, prematched_nodes, r):
    # First we will find a 1-many mapping for each important node to a target node
    node_mapping = {}
    for n in important_nodes:
        node_mapping[n] = []
        matching_nodes = find_matching_nodes(query_nh_index, target_nh_index, n, r)

        # any node that was already prematched should be removed
        if prematched_nodes is not None:
            matching_nodes_clean = []
            for (node, score) in matching_nodes:
                if node not in [nid for (nid, s) in prematched_nodes.values()]:
                    matching_nodes_clean.append((node, score))

            matching_nodes = matching_nodes_clean

        if(len(matching_nodes) == 0):
	    # we failed to match this important node in the entire target graph
            continue

        
        for (node, score) in matching_nodes:
	    node_mapping[n].append((node, score))

    # I had some problems with keys overlapping in query -> target
    # The keys are just set by NetworkX and are unique to every graph, but not across graphs
    index = 0
    query_node_converter = []
    for n in node_mapping.keys():
        query_node_converter.append(n)

    db_node_converter = []
    for list_of_mappings in node_mapping.values():
        for (db_node, score) in list_of_mappings:
            if db_node not in db_node_converter:
	        db_node_converter.append(db_node)

    # now we have a unique mapping for each node in both graphs
    G = nx.Graph()
    for query_node, list_of_mappings in node_mapping.iteritems():
        query_converted_id = query_node_converter.index(query_node)
        G.add_node(query_converted_id) # These will be node ids 0..len(query_node_converter)
        for (db_node, score) in list_of_mappings:
            db_converted_id = db_node_converter.index(db_node) + len(query_node_converter)
            # Clever way to make db_converted_id unique from query by just adding length of array
	    if db_converted_id not in G.nodes:
	        G.add_node(db_converted_id)

	    G.add_edge(query_converted_id, db_converted_id)
	    G[query_converted_id][db_converted_id]['weight'] = score

    # now we will just use max weight matching provided by NetworkX
    max_weight_matching = nx.max_weight_matching(G)
    #print type(max_weight_matching)
    #max_weight_matching_dict = {}
    #for (k,v) in max_weight_matching:
    #	max_weight_matching_dict[k] = v
    #max_weight_matching = max_weight_matching_dict
    node_mapping_max_weight = {}

    for i, query_node in enumerate(query_node_converter):
        if i in max_weight_matching.keys():
            # This node is matched to max_weight_matching[i] == converted target node id
            db_converted_id = max_weight_matching[i] - len(query_node_converter)
	    node_mapping_max_weight[query_node] = (db_node_converter[db_converted_id], 2)

    return node_mapping_max_weight


def match_and_score_nhi(query_nhi, target_nhi, r):
    #rho = 0
    #rho = 0.1
    # This function will simultaneously match and score two neighborhood indices
    if query_nhi['label'] != target_nhi['label']:
        return (False, 0.)

    #if 'code' in query_nhi.keys() and 'code' in target_nhi.keys():
    #     #If highly similar code, short circuit other checks
    #     if SequenceMatcher(None, query_nhi['code'], target_nhi['code']).ratio() > 0.5:
    #         return (True, 2)
    #    else:
    #        return (False, 0)


    num_allowed_misses = int(r * query_nhi['degree'])

    # IV.2 test
    if target_nhi['degree'] < query_nhi['degree'] - num_allowed_misses:
        return (False, 0.)

    # IV.3 test
    nb_miss = abs(len(query_nhi['nbArray']) - len(set(query_nhi['nbArray']).intersection(set(target_nhi['nbArray']))))

    # new test on edge types
    nb_miss += abs(len(query_nhi['edgeArray']) - len(set(query_nhi['edgeArray']).intersection(set(target_nhi['edgeArray']))))

    if nb_miss > num_allowed_misses:
        return (False, 0.)

    # IV.4 test
    if target_nhi['nbConnection'] >= query_nhi['nbConnection']:
        nbc_miss = 0.
    else:
        nbc_miss = float(query_nhi['nbConnection'] - target_nhi['nbConnection'])

    if nbc_miss > num_allowed_misses:
        return (False, 0.)

    # Now we score the match
    if query_nhi['degree'] == 0:
        f_nb = 0.
    else:
        f_nb = float(nb_miss) / float(query_nhi['degree'])

    if query_nhi['nbConnection'] == 0:
        f_nbc = 0.
    else:
        f_nbc = float(nbc_miss) / float(query_nhi['nbConnection'])


    if nb_miss == 0:
        w = 2. - f_nbc
    else:
        w = 2. - (f_nb + (f_nbc / nb_miss))

    return (True, w)

if __name__ == "__main__":
    G = nx.Graph()
    G.add_node(0)
    G.add_node(1)
    G.add_node(2)
    G.add_node(3)
    G.node[0]['type'] = 'zero'
    G.node[1]['type'] = 'one'
    G.node[2]['type'] = 'two'
    G.node[3]['type'] = 'three'
    G.add_edge(0,1)
    G[0][1]['type'] = 'edge_1'
    G.add_edge(0,2)
    G[0][2]['type'] = 'edge_2'
    G.add_edge(0,3)
    G[0][3]['type'] = 'edge_3'
    G.add_edge(1,2)
    G[1][2]['type'] = 'edge_4'
    G.add_edge(2,3)
    G[2][3]['type'] = 'edge_5'

    H = nx.Graph()
    H.add_node(4)
    H.add_node(5)
    H.add_node(6)
    H.add_node(7)
    H.node[4]['type'] = 'zero'
    H.node[5]['type'] = 'one'
    H.node[6]['type'] = 'two'
    H.node[7]['type'] = 'three'
    H.add_edge(4,5)
    H[4][5]['type'] = 'edge_1'
    H.add_edge(4,6)
    H[4][6]['type'] = 'edge_2'
    H.add_edge(4,7)
    H[4][7]['type'] = 'edge_3'
    H.add_edge(5,6)
    H[5][6]['type'] = 'edge_4'
    H.add_edge(6,7)
    H[6][7]['type'] = 'edge_5'

    q_nh_index = generate_nh_index(G)
    t_nh_index = generate_nh_index(H)

    print q_nh_index
    print t_nh_index

    res = match(G, H, q_nh_index, t_nh_index, G.nodes)

    print res
