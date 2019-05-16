from matcher import Matcher

import networkx as nx


class TaleMatcher(Matcher):

    def __init__(self, p=0.2, r=0.1):
        self.p=p
        self.r=r

    def match(self, q, t, prepared_q_data, prepared_t_data):
        q_nh_idx, important_nodes = prepared_q_data
        t_nh_idx = prepared_t_data

        # Match the important nodes to our target graph
        weight_mappings = self.__match_imp_nodes(q_nh_idx, t_nh_idx, important_nodes)

        # Grow the match
        res = self.__grow_match(q, t, q_nh_idx, t_nh_idx, weight_mappings)

        # Calculate overall match score
        # Each match can have a weight (aka score) of at most 2
        total_possible_score = 2 * len(q.nodes)
        achieved_score = 0.
        for n in res:
            achieved_score += res[n][1]

        overall_score = float(achieved_score) / float(total_possible_score)

        return res, overall_score

    def prepare_target(self, t):
        t_nh_idx = self.__generate_nh_index(t)
        return t_nh_idx    

    def prepare_query(self, q):
        q_nh_idx = self.__generate_nh_index(q)
        important_nodes = self.__find_important_nodes(q)
        return (q_nh_idx, important_nodes)


    def __match_imp_nodes(self, q_index, t_index, imp_nodes):
        all_mappings = nx.Graph()
        for n in imp_nodes:
            for t in t_index.keys():
                score = self.__match_node(q_index[n], t_index[t])
                if score > 0.0:
                    all_mappings.add_edge('Q_%s'% n, 'T_%s'%t)
                    all_mappings['Q_%s'%n]['T_%s'%t]['weight'] = score

        max_weight_mapping = nx.max_weight_matching(all_mappings)

        final_mapping = {}
        for n in imp_nodes:
            if 'Q_%s'%n in max_weight_mapping.keys():
                target = max_weight_mapping['Q_%s'%n]
                final_mapping[n] = (target[2:], all_mappings['Q_%s'%n][target]['weight'])

        return final_mapping

    def __grow_match(self, q, t, q_nh_idx, t_nh_idx, weight_mapping):
        processing_queue = []
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
            nb_query = set(q.neighbors(n_query)).difference(set(final_results.keys()))

            # Get all nodes 2 hops away, not in our final results
            nb_query_2_hops = []
            for x in q.neighbors(n_query):
                nb_query_2_hops = set(nb_query_2_hops).union(set(q.neighbors(x)))
            nb_query_2_hops = set(nb_query_2_hops).difference(set(nb_query)).difference(set(final_results.keys()))

            # Get all target nodes that are neighbors of last matching db node which are not
            # in final result or processing queue
            nb_target = set(t.neighbors(n_target)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

            # target nodes that are 2 hops away
            nb_target_2_hops = []
            for x in t.neighbors(n_target):
                nb_target_2_hops = set(nb_target_2_hops).union(set(t.neighbors(x)))
            nb_target_2_hops = set(nb_target_2_hops).difference(set(nb_target)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

            self.__match_nodes(q_nh_idx, t_nh_idx, nb_query, nb_target, processing_queue, weight_mapping)
            self.__match_nodes(q_nh_idx, t_nh_idx, nb_query, nb_target_2_hops, processing_queue, weight_mapping)
            self.__match_nodes(q_nh_idx, t_nh_idx, nb_query_2_hops, nb_target, processing_queue, weight_mapping)

        return final_results


    def __match_node(self, query_nhi, target_nhi):
        '''This function will simultaneously match and score two neighborhood indices'''
        # IV.1 from paper
        if query_nhi['label'] != target_nhi['label']:
            return 0.

        # Compute allowed neighbor mismatch (nb_miss in paper)
        nb_allowed_misses = int(self.r * query_nhi['degree'])

     
        # Compute allowed neighbor connection missmatch (nbc_miss in paper)
        nbc_allowed_misses = nb_allowed_misses * ((nb_allowed_misses-1)/2) + (query_nhi['degree'] - nb_allowed_misses) * nb_allowed_misses

        # IV.2 from paper
        if target_nhi['degree'] < query_nhi['degree'] - nb_allowed_misses:
            return 0.

        # IV.3 test.  Also compute nb_miss for later
        nb_miss = abs(len(query_nhi['nbArray']) - len(set(query_nhi['nbArray']).intersection(set(target_nhi['nbArray']))))

        if nb_miss > nb_allowed_misses:
            return 0.

        # IV.4 test
        if target_nhi['nbConnection'] <  query_nhi['nbConnection'] - nbc_allowed_misses:
            return 0.

        # Compute actual nbc_miss 
        if target_nhi['nbConnection'] >= query_nhi['nbConnection']:
            nbc_miss = 0.
        else:
            nbc_miss = float(query_nhi['nbConnection'] - target_nhi['nbConnection'])

        #if nbc_miss > num_allowed_misses:
        #    return 0.

        #Now score match
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

        return w

   
    def __match_nodes(self, q_nh_idx, t_nh_idx, query_nodes, target_nodes, processing_queue, weight_mapping):
        for q in query_nodes:
            best_match = None
            for target in target_nodes:
                score = self.__match_node(q_nh_idx[q], t_nh_idx[target])
                if score > 0.:
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


    # Generate neighborhood index for all nodes in graph g
    def __generate_nh_index(self, g):
        nh_idx = {}
        for n in g.nodes:
            nh_idx[n] = self.__node_nh_idx(g,n)
        return nh_idx

    # Generate neighhood index for an individual node
    def __node_nh_idx(self, g, n):
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

            # Keeping track of neighbor connectedness
            d['nbConnection'] = d['nbConnection'] + len(set(g.neighbors(nb)).intersection(set(g.neighbors(n))))

        # Double counted...so divide by two
        d['nbConnection'] = d['nbConnection'] / 2
        return d

    def __find_important_nodes(self, graph):
        """ Returns a list of important nodes (based on degree, top p percent) """

        # import based on degree centrality
        node_degree_dict = {}
        nodes_to_return = int(len(graph.nodes) * self.p)
        for n in graph.nodes:
            node_degree_dict[n] = graph.degree(n)

        important_nodes = []
        for node_id, degree in reversed(sorted(node_degree_dict.iteritems(), key=lambda (k,v): (v,k))):
            important_nodes.append(node_id)
            nodes_to_return = nodes_to_return - 1
            if nodes_to_return <= 0:
                break

        return important_nodes



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
    tm = TaleMatcher()
    # Prepare data
    prepared_data = tm.prepare(G, H)
    # Perform matching
    results = tm.match(G, H, prepared_data)
    print results
