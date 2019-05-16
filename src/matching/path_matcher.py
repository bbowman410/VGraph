from matcher import Matcher

import networkx as nx
import copy

DEBUG=False

class PathMatcher(Matcher):

    def match(self, q, t, prepared_q_data, prepared_t_data):
        q_index, q_imp_nodes, q_imp_bfs = prepared_q_data
        t_index = prepared_t_data
        #for n in q_imp_nodes:
        #    for q in q_index:
        #        if q not in q_imp_bfs_f[n] and q not in q_imp_bfs_r[n]:
        #            print "WTF somehow node not in any bfs...%s" % q

        if DEBUG:
            print "=============Important nodes============="
            for node in q_imp_nodes:
                print node
                print q.node[node]
        #imp_node_matches = self.__match_imp_nodes_2(q_index, t_index, q_imp_nodes)
        imp_node_matches = self.__match_imp_nodes_3(q, t, q_index, t_index, q_imp_nodes)
        matches_sorted = imp_node_matches
        #for blah in reversed(sorted(imp_node_matches.iteritems(), key=lambda (k, v):q_index[k]['degree'])):
        #    matches_sorted.append((blah[0], blah[1][0], blah[1][1]))

        if DEBUG:
            print "Important node matching results:"
            print matches_sorted[:3]
            for (a,b,c,d) in matches_sorted[:3]:
                print a
                print q.node[a]
                print b
                print t.node[b]
        # Let's try each one and choose the best!
        best_mapping = {}
        best_score = 0.
        for (imp_q, imp_t, _, imp_score) in matches_sorted[:1]:# cap it at 3 attempts to get an importat node right.  Otherwise it can take just too long depending on size of graph
            # Forward BFS tree for this important node (precomputed)
            q_bfs_tree = q_imp_bfs[imp_q]

            q_depth_map = {}
            max_depth = self.__get_depth(q_bfs_tree, imp_q, q_depth_map)
  
            for n in q_index:
                q_index[n]['height'] = q_depth_map[n]

            # do same for target graph i guess?
            # This seems too expensive...
            #T_bfs_tree = nx.bfs_tree(T.to_undirected(), imp_t)
            #if DEBUG:
            #    print "bfs tree: %d" % len(T_bfs_tree)
            #T_weight_map = {}
            #max_weight = get_depth(T_bfs_tree, imp_t, T_weight_map)
            #for n in T.nodes:
            #    T_index[n]['height'] = T_weight_map[n]
            #if DEBUG:
            #    print "length of weight map: %d" % len(T_weight_map.keys())
            #    print "Max weight: %d" % max_weight


            # Step 5: Set important node match, and start growing 
            current_match = {}
            current_match[imp_q] = (imp_t, imp_score)
            score = self.__grow_match(q, t, q_bfs_tree, q_index, t_index, current_match, (imp_q,imp_t))
            score += imp_score# for our important node
            if score > best_score:
                best_score = score
                best_mapping = current_match

        final_score = (best_score / (1.0*len(q_index)))
        return best_mapping, final_score

    def prepare_query(self, q):
        # Step 1: Generate index
        q_index = {}
        for n in q.nodes:
            q_index[n] = self.__gen_node_index(q, n)

        # step 2: Identify important nodes
        q_imp_nodes = self.__get_important_nodes(q)

        # Step 3: for each important node, build forward and reverse BFS trees
        # No just do 1 bfs tree. This is the guide for the match.  the directionality of the edges
        # will be considered during matching.  i dont care if bfs tree node consists of forward/rev
        # edges.  all i care is that below it there is a bunch of nodes so i want to make sure
        # to give that node priority over others.  will 
        q_imp_bfs = {}
        for n in q_imp_nodes:
            q_imp_bfs[n] = nx.bfs_tree(q.to_undirected(), n)

        
      
        return (q_index, q_imp_nodes, q_imp_bfs)

    def prepare_target(self, t):
        t_index = {}
        for n in t.nodes:
            t_index[n] = self.__gen_node_index(t, n)

        return t_index

    def __gen_node_index(self, g, n):
        d = {}
        d['label'] = g.node[n]['type']
        d['degree'] = g.degree(n)
        d['in_degree'] = g.in_degree(n)
        d['out_degree'] = g.out_degree(n)
        if 'code' in g.node[n]:
            d['code'] = g.node[n]['code']
        else:
            d['code'] = ''

        # Look at neighborhood
        d['in_nbArray'] = set([])
        d['in_edgeArray'] = set([])
        d['out_nbArray'] = set([])
        d['out_edgeArray'] = set([])
        for succ in g.successors(n):
            d['out_nbArray'].add(g.node[succ]['type'])
            d['out_edgeArray'].add(g[n][succ]['type'])

        for pred in g.predecessors(n):
            d['in_nbArray'].add(g.node[pred]['type'])
            d['in_edgeArray'].add(g[pred][n]['type'])

        return d

    def __get_important_nodes(self, G, p=0.1):
        # import based on degree
        node_degree_dict = {}
        nodes_to_return = int(len(G.nodes) * p)
        for n in G.nodes:
            node_degree_dict[n] = G.degree(n)

        important_nodes = []

        for node_id, degree in reversed(sorted(node_degree_dict.iteritems(), key=lambda (k,v): (v,k))):
            important_nodes.append(node_id)
            nodes_to_return -= 1

            if nodes_to_return <= 0:
                break

        return important_nodes

 
    def __match_imp_nodes(self, q_index, t_index, imp_nodes):
        all_mappings = nx.Graph()
        for n in imp_nodes:
            for t in t_index.keys():
                score = self.__match_node(q_index[n], t_index[t])
                if score > 0.0:
                    all_mappings.add_edge('Q_%s'% n, 'T_%s'%t)
                    all_mappings['Q_%s'%n]['T_%s'%t]['weight'] = score

        if DEBUG:
            print "All mappings before max_weight_matching"
            print all_mappings.nodes()
            for (a,b) in all_mappings.edges():
                print "%s %s" % (a, b)
                print all_mappings[a][b]

        max_weight_mapping = nx.max_weight_matching(all_mappings)

        final_mapping = {}
        for n in imp_nodes:
            if 'Q_%s'%n in max_weight_mapping.keys():
                target = max_weight_mapping['Q_%s'%n]
                final_mapping[n] = (target[2:], all_mappings['Q_%s'%n][target]['weight'])

        return final_mapping

    # Ok new try.  This time were going to not matching important nodes.  were matching important
    # NEIGHBORHOOD.  This is defined as the 1-hop neighborhood with nighest combined degree
    def __match_imp_nodes_3(self, q_graph, t_graph, q_index, t_index, imp_nodes):
        # For each important node:
        #   Find match in target
        #   loop through query and target neighbors
        #   compute matches
        #   score of this important node is based on important node and neighbhood matches
        all_mappings = []
        for n in imp_nodes:
            for t in t_index.keys():
                score = self.__match_node(q_index[n], t_index[t])
                score_only_one = score
                if score > 0.0: # possible match
                    q_neibs = set(list(q_graph.predecessors(n))).union(set(list(q_graph.successors(n))))
                    t_neibs = set(list(t_graph.predecessors(t))).union(set(list(t_graph.successors(t))))
                    matching_n = nx.Graph()
                    for qn in q_neibs:
                        for tn in t_neibs:
                            score_nb = self.__match_node(q_index[qn], t_index[tn])
                            if score_nb > 0.0: 
                                matching_n.add_edge('Q_%s'%qn, 'T_%s'%tn)
                                matching_n['Q_%s'%qn]['T_%s'%tn]['weight'] = score_nb
                    # now we have neighborhood matching
                    max_weight_mapping = nx.max_weight_matching(matching_n)
                    for qn in max_weight_mapping:
                        tn = max_weight_mapping[qn]
                        score += matching_n[qn][tn]['weight'] # get the original weight
                    all_mappings.append((n,t,score, score_only_one)) # total neighborhood match score       
                        
        # Now we sort and return...
        # I think i want to sort this on score now...
        sorted_mappings = [ (a, b, c,d) for (a, b, c,d) in reversed(sorted(all_mappings, key=lambda (q,t,s,soo):s))]
        if DEBUG:
            print "==================Sorted mappings=============="
            for sm in sorted_mappings:
                print sm 

        return sorted_mappings
        
    # This function is broken.  It needs to be more robust when matching important nodes
    # If thanything, this should take the MOST time becuase an error here can be very bad for rest of
    # matching algorithm
    def __match_imp_nodes_2(self, q_index, t_index, imp_nodes):
        all_mappings = []
        for n in imp_nodes:
            for t in t_index.keys():
                score = self.__match_node(q_index[n], t_index[t])
                if score > 0.0: # found a possible match
                    all_mappings.append((n, t, score))
        # now lets sort
         
        sorted_mappings = [ (a, b, c) for (a, b, c) in reversed(sorted(all_mappings, key=lambda (q,t,s):(q_index[q]['degree'],s)))]
        if DEBUG:
            print "==================Sorted mappings=============="
            for sm in sorted_mappings:
                print sm 

        return sorted_mappings

    def __match_node(self, q_index, t_index):
        # Returns match score [0.0,1.0]
        # 0.0 = no match
        # >0.0 means partial match 

        r = 1. # threshold below which we don't consider it a partial match
        #r = 0.0 # percentage of allowed difference from query node

        if q_index['label'] != t_index['label']:
            return 0.

        # Minimum of <degree>, or absolute value of difference.  At most different by <degree>
        if q_index['in_degree'] < t_index['in_degree']:
            in_degree_delta = 0.
        else:
            # cap difference at most q_index['in_degree']
            in_degree_delta = min(q_index['in_degree'], abs(q_index['in_degree'] - t_index['in_degree']))

        if q_index['out_degree'] < t_index['out_degree']:
            out_degree_delta = 0.
        else:
            out_degree_delta = min(q_index['out_degree'], abs(q_index['out_degree'] - t_index['out_degree']))

        # These will contain neighbors/edges that are not covered in target
        in_nbArray_delta = q_index['in_nbArray'].difference(q_index['in_nbArray'].intersection(t_index['in_nbArray']))
        out_nbArray_delta = q_index['out_nbArray'].difference(q_index['out_nbArray'].intersection(t_index['out_nbArray']))
        in_edgeArray_delta = q_index['in_edgeArray'].difference(q_index['in_edgeArray'].intersection(t_index['in_edgeArray']))
        out_edgeArray_delta = q_index['out_edgeArray'].difference(q_index['out_edgeArray'].intersection(t_index['out_edgeArray']))

        #if q_index['in_degree'] > t_index['in_degree'] + int(r*q_index['in_degree']):
        #    return 0.
        #if in_degree_delta > int(r*q_index['in_degree']):
        #    return 0.     

        #if q_index['out_degree'] > t_index['out_degree'] + int(r*q_index['out_degree']):
        #    return 0.
        #if out_degree_delta > int(r*q_index['out_degree']):
        #    return 0.     

        #if len(in_nbArray_delta) > int(r*len(q_index['in_nbArray'])):
        #    return 0.

        #if len(out_nbArray_delta) > int(r*len(q_index['out_nbArray'])):
        #    return 0.

        #if len(in_edgeArray_delta) > int(r*len(q_index['in_edgeArray'])):
        #    return 0.

        #if len(out_edgeArray_delta) > int(r*len(q_index['out_edgeArray'])):
        #    return 0.

        #if DEBUG:
        #    print "Matched nodes:"
        #    print q_index
        #    print t_index
        #if r == 0.0:
        #    return 1.0

        # if we get here, then were good
        # If total mismatch, this would be our score
        total_possible_score = 0.
        total_possible_score += q_index['in_degree']
        total_possible_score += q_index['out_degree']
        total_possible_score += len(q_index['in_nbArray'])
        total_possible_score += len(q_index['out_nbArray'])
        total_possible_score += len(q_index['in_edgeArray'])
        total_possible_score += len(q_index['out_edgeArray'])

        # Compute final score as total mismatch score - actual score.  If actual score is total mismatch, we get 0.  If actual score is 0 (i.e. perfect match), then we get 1
        final_score = (total_possible_score - float(in_degree_delta + out_degree_delta + len(in_nbArray_delta)+len(out_nbArray_delta)+len(in_edgeArray_delta)+len(out_edgeArray_delta))) / total_possible_score
        if final_score < r:
            return 0.0
        else:
            return final_score

    def __get_depth(self, bfs_tree, node_id, depth_map):
        children = bfs_tree[node_id]

        if len(children) == 0:
            depth_map[node_id] = 1
            return 1
        else:
            weight = 1 # for current node
            for c in children:
                c_subtree = self.__get_depth(bfs_tree, c, depth_map)
                weight += c_subtree
            depth_map[node_id] = weight
            return weight

    def __grow_match(self, q, t, q_bfs_tree, q_index, t_index, current_match, match_root, recursion_id = ''):

        # Step 1: Get neighbors of the match root in both query and target graphs
        q_root = match_root[0]
        t_root = match_root[1]
        if DEBUG:
            print "%sGrowing match from root: (%s = > %s)" % (recursion_id, q_root, t_root)

        # BFS tree will direct what nodes we use next
        q_root_nbors_f = set(q_bfs_tree.neighbors(q_root)).intersection(set(q.successors(q_root))).difference(current_match.keys())
        q_root_nbors_r = set(q_bfs_tree.neighbors(q_root)).intersection(set(q.predecessors(q_root))).difference(current_match.keys())
        t_root_nbors_f = set(t.successors(t_root)).difference(set([a for (a,b) in current_match.values()])) 
        t_root_nbors_r = set(t.predecessors(t_root)).difference(set([a for (a,b) in current_match.values()])) 

        if (len(q_root_nbors_f) == 0 and len(q_root_nbors_r) == 0) or (len(t_root_nbors_f) == 0 and len(t_root_nbors_r) == 0):
            if DEBUG:
                print "%sNo neighbors.  End of match path" % (recursion_id)
            return 0.0

        # Step 2: Find ALL potential matchs of Query => Target.  A potential match is any match with a score > 0.0
        potential_matches_found = 0
        potential_matches = {}
        for q_nb in q_root_nbors_f.union(q_root_nbors_r):
            potential_matches[q_nb] = {}

        # Find potential matches for forward neighbors
        for q_nb_f in q_root_nbors_f:
            for t_nb_f in t_root_nbors_f:
                score = self.__match_node(q_index[q_nb_f], t_index[t_nb_f])
                if score > 0.0:
                    potential_matches[q_nb_f][t_nb_f] = score
                    potential_matches_found +=1

        # Find potential matches for backward neighbors
        for q_nb_r in q_root_nbors_r:
           for t_nb_r in t_root_nbors_r:
               score = self.__match_node(q_index[q_nb_r], t_index[t_nb_r])
               if score > 0.0:
                   potential_matches[q_nb_r][t_nb_r] = score
                   potential_matches_found +=1
                   
        # Another base-case condition checked here
        if potential_matches_found == 0:
            if DEBUG:
                print "%sNo potential matches found.  End of match path" % (recursion_id)
            return 0.0

        if DEBUG:
            print "%sPotential Matches:" % (recursion_id)
            print potential_matches

        # Step 3: At this point we know we have some potential matches to score 
        #  - Sort query matches based on height parameter (i.e., nodes with most children go first)
        #  - For every target node that matched with the query node
        #    - set match root as Q=>T and grow match from that root

        total_score = 0.0 # This is the total score of all matches below the current match root. This value gets popped up the call stack to previous caller
        for q_nb in reversed(sorted(list(potential_matches), key=lambda x: q_index[x]['height'])): # priority by height of node
            if DEBUG:
                print "%sMatching query node: %s, weight: %d" % (recursion_id, q_nb, q_index[q_nb]['height'])
                print q.node[q_nb]
            best_match = None
            for t_nb in set(potential_matches[q_nb].keys()).difference(set([a for (a,b) in current_match.values()])): # only first one cuz why not??
                # Found a potential match.  Lets follow the path and see where it leads
                if DEBUG:
                    print "%sFollowing match path: %s ==> %s" % (recursion_id,q_nb, t_nb)
                # Make deep copy of current_match dict
                current_match_copy = copy.deepcopy(current_match)
                # Set the new match root with potential match score
                current_match_copy[q_nb] = (t_nb, potential_matches[q_nb][t_nb])
                # Recursive call
                score = self.__grow_match(q, t,q_bfs_tree, q_index, t_index, current_match_copy, (q_nb, t_nb), recursion_id=recursion_id+'++')
                if DEBUG:
                    print "%sPotential %s ==> %s resulted in path score of %f" % (recursion_id, q_nb, t_nb, score)
                if best_match is None or score > best_match[2]:
                    # TODO Problem here: if there are multiple best_matches with same score...
                    # this algo just takes first one

                    # need to keep track of all matches with same score
                    best_match = (q_nb, t_nb, score, copy.deepcopy(current_match_copy)) # deep copy again? not sure if thats necesary

                if score >= q_index[q_nb]['height']:
                    # we matched the full path for this query node.  we can move onto next query node
                    if DEBUG:
                        print "%sFull path match.  Breaking" % (recursion_id)
                    break


            # No matching node found for this query node.  Move on to next q_nb
            if not best_match:
                if DEBUG:
                    print "Could not find a match for query node: %s" % q_nb
                continue

            # Step 4: We have a match for our q_nb.  Now we need to update our current_match dict with all matches
            #         that occured while matching that neighbor (could be an entire match path)
            if DEBUG:
                print "%sBest match: %s ==> %s (%f)" % (recursion_id, q_nb, best_match[1], best_match[2])
                print q.node[q_nb]
                print t.node[best_match[1]]
            # Update current match based on best path match
            for n in best_match[3]:
                if n not in current_match:
                    current_match[n] = best_match[3][n]
            # Set the best potential match as a real match
            current_match[q_nb] = (best_match[1], potential_matches[q_nb][best_match[1]])

            # Update total score for this match root and potential matched node
            total_score += (best_match[2] + potential_matches[q_nb][best_match[1]])

            # Onto the next q_nb

        # At this point we have evaluated each q_nb of match root for a t_nb of match root
        # We have chosen the best scoring match for each q_nb, ordered by how selective
        # that q_nb is in the total Q graph

        # Sanity check:  We know that the total_score should not be more than the height of

        # The total score below represents the summation of all q_nb match paths
        if DEBUG:
            print "%sTotal score: %f" % (recursion_id, total_score)


        return total_score





if __name__ == "__main__":
    # Simple graph test
    G = nx.DiGraph()
    G.add_edge('1','2')
    G.add_edge('2','3')
    G.add_edge('3','4')
    G.add_edge('1','5')
    G.add_edge('5','6')
    G.add_edge('1','7')
    G.node['1']['type'] = 'one'
    G.node['2']['type'] = 'two'
    G.node['3']['type'] = 'three'
    G.node['4']['type'] = 'four'
    G.node['5']['type'] = 'two'
    G.node['6']['type'] = 'three'
    G.node['7']['type'] = 'two'
    G['1']['2']['type'] = 'edge_1_2'
    G['2']['3']['type'] = 'edge_2_3'
    G['3']['4']['type'] = 'edge_3_4'
    G['1']['5']['type'] = 'edge_1_2'
    G['5']['6']['type'] = 'edge_2_3'
    G['1']['7']['type'] = 'edge_1_2'

    H = G.copy()
    H.node['4']['type'] = '2'

    # Create Pathmatcher
    pm = PathMatcher()
    # Prepare data
    prepared_q_data = pm.prepare_query(G)
    prepared_t_data = pm.prepare_target(H)
    # Perform matching
    results = pm.match(G, H, prepared_q_data, prepared_t_data)
    print results
    exit()

    #match(G, G)
    
    #exit()
#FN vgraph_db/linux/CVE-2008-5033/tvaudio.c/chip_command	vuln_src_db/vuln_patch_graph_db/linux/CVE-2008-5033/vuln/tvaudio.c/graph/chip_command.gpickle	0	76	90
#FN vgraph_db/ffmpeg/CVE-2014-8547/gifdec.c/gif_read_image	vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2014-8547/vuln/gifdec.c/graph/gif_read_image.gpickle	0	0	50
#FN vgraph_db/openssl/CVE-2015-1793/x509_vfy.c/X509_verify_cert	vuln_src_db/vuln_patch_graph_db/openssl/CVE-2015-1793/vuln/x509_vfy.c/graph/X509_verify_cert.gpickle	0	0	0
#FN vgraph_db/ffmpeg/CVE-2012-2775/alsdec.c/read_var_block_data	vuln_src_db/vuln_patch_graph_db/libav/CVE-2012-2775/vuln/alsdec.c/graph/read_var_block_data.gpickle	2	0	0





    vGraph_context = nx.read_gpickle('vgraph_db/ffmpeg/CVE-2012-2775/alsdec.c/read_var_block_data_context.gpickle')
    vGraph_pos = nx.read_gpickle('vgraph_db/ffmpeg/CVE-2012-2775/alsdec.c/read_var_block_data_pvg.gpickle')
    vGraph_neg = nx.read_gpickle('vgraph_db/ffmpeg/CVE-2012-2775/alsdec.c/read_var_block_data_nvg.gpickle')

    V = nx.read_gpickle('vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2012-2775/vuln/alsdec.c/graph/read_var_block_data.gpickle')
    P = nx.read_gpickle('vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2012-2775/patch/alsdec.c/graph/read_var_block_data.gpickle')

    mapping, score = match(vGraph_neg, V)

    print "Lenght of mapping:"
    print len(mapping)
    print "Score:"
    print score * 100
    
    exit()

    v_to_p_mapping, _ = heuristic_match(V, P)
    pos_imp_nodes = set(V.nodes).difference(set(v_to_p_mapping.keys()))
    neg_imp_nodes = set(P.nodes).difference(set(v_to_p_mapping.values()))
    expanded = set([])
    for n in neg_imp_nodes:
        expanded.add(n)
        for n in P.neighbors(n):
            expanded.add(n)
        
    neg_imp_nodes = expanded
    print "Num + nodes: %d" % len(pos_imp_nodes)
    print "Num - nodes: %d" % len(neg_imp_nodes)
   
  
    # perform match V against V
    mapping = match(P, V)
   
    # lets see how many pos imp nodes matched
    matches = 0
    for n in neg_imp_nodes:
        if n in mapping:
            matches += 1
    print "Neg Imp Nodes: %d / %d" % (matches, len(neg_imp_nodes)) 
