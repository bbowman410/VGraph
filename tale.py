import networkx as nx

# Python implementation of TALE approximate graph matching
#

class Tale:
    #P_imp = .2 # Choose top 10% of nodes for important nodes

    def __init__(self, rho=0.2, p_imp=0.2):
        self.rho = rho # percentage of neighborhood mismatch allowed when node matching
        self.P_imp = p_imp # percentage of nodes to return as top-k important nodes
        self.important_nodes = [] # This is a list of important nodes that can be specified by user


    def set_important_nodes(self, node_id_list):
        self.important_nodes = node_id_list

    def match(self, query_graph, db_graph):
        """ This function returns a total match score, and a dictionary ofquery_graph node -> (db_graph node, weight (match confidence)) """
        query_nh_index, db_nh_index = self.__generate_nh_index(query_graph, db_graph)
        query_important_nodes = self.__find_important_nodes(query_graph)
        weight_mappings = self.match_important_nodes(query_important_nodes, query_nh_index, db_nh_index)

        # so weight mapings will have (query_node) : ((db_node, db_node_weight))
        # This should be 1-1 mapping of (currently) important nodes
        # now we need to grow the result
        res = self.grow_match(query_graph, db_graph, query_nh_index, db_nh_index, weight_mappings)

        # Each match can have a weight (aka score) of at most 2
        total_possible_score = 2 * len(query_graph.nodes)
        achieved_score = 0
        for k,v in res.iteritems():
            achieved_score = achieved_score + v[1]

        real_score = (achieved_score * 100) / total_possible_score

        return (real_score, res)

    def grow_match(self, query_graph, db_graph, query_nh_index, db_nh_index, weight_mapping):
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
            (n_query, n_db) = processing_queue.pop(0)
            final_results[n_query] = (n_db, weight_mapping[n_query][1])

            # Need to check neighbors of n_query not yet matched
            nb_query = set(query_graph.neighbors(n_query)).difference(set(final_results.keys()))

            # Get all nodes 2 hops away, not in our final results
            nb_query_2_hops = []
            for x in query_graph.neighbors(n_query):
                nb_query_2_hops = set(nb_query_2_hops).union(set(query_graph.neighbors(x)))
            nb_query_2_hops = set(nb_query_2_hops).difference(set(nb_query)).difference(set(final_results.keys()))

            # Get all db nodes that are neighbors of last matching db node which are not
            # in final result or processing queue
            nb_db = set(db_graph.neighbors(n_db)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

            # DB nodes that are 2 hops away
            nb_db_2_hops = []
            for x in db_graph.neighbors(n_db):
                nb_db_2_hops = set(nb_db_2_hops).union(set(db_graph.neighbors(x)))
            nb_db_2_hops = set(nb_db_2_hops).difference(set(nb_db)).difference(set([a for (a,b) in final_results.values()])).difference(set([b for (a,b) in processing_queue]))

            # Sanity check on these sets...
            query_final = final_results.keys()
            database_final = final_results.values()
            query_processing = [ a for (a,b) in processing_queue ]
            database_processing = [ b for (a,b) in processing_queue ]
            for n in nb_query:
                if n in query_final:
                    print "Found node in final query mapping"
                    exit()
            for n in nb_query_2_hops:
                if n in query_final:
                    print "Found 2-hop node in final query mapping"
                    exit()

            for n in nb_db:
                if n in [ a for (a,b) in database_final]:
                    print "Found db node in final db mapping"
                    exit()
                if n in database_processing:
                    print "Found db node in processing db mapping"
                    exit()
            for n in nb_db_2_hops:
                if n in [ a for (a,b) in database_final]:
                    print "Found 2-hop db node in final db mapping"
                    exit()
                if n in database_processing:
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


            self.__match_nodes(query_nh_index, db_nh_index, nb_query, nb_db, processing_queue, weight_mapping)

            self.__match_nodes(query_nh_index, db_nh_index, nb_query, nb_db_2_hops, processing_queue, weight_mapping)
            self.__match_nodes(query_nh_index, db_nh_index, nb_query_2_hops, nb_db, processing_queue, weight_mapping)

        return final_results

    def __match_nodes(self, query_nh_index, db_nh_index, query_nodes, db_nodes, processing_queue, weight_mapping):
        for q in query_nodes:
            best_match = None
            for db in db_nodes:
                (is_match, score) = self.match_and_score_nhi(query_nh_index[q], db_nh_index[db])
                if is_match:
                    if best_match is None:
                        best_match = (db, score)
                    else:
                        if score > best_match[1]:
                            best_match = (db, score)

            # now we should have best_match
            if best_match is None:
                # Unable to match this node...just skip it
                continue

            if q not in [a for (a,b) in processing_queue]:
                if best_match[0] in [b for (a,b) in processing_queue]:
                    print "Somehow we are trying to add a DB node thats already in processing queue"
                    print "Node: %d" % best_match[0]
                    for a,b in processing_queue:
                        if b == best_match[0]:
                            print "processing queue entry: %d -> %d" % (a,b)
                    exit()
                processing_queue.append((q, best_match[0]))
                weight_mapping[q] = best_match
                db_nodes.remove(best_match[0])
            else:
                # this node already in processing q...
                # need to check scores
                if best_match[1] > weight_mapping[q][1]:
                    processing_queue[processing_queue.index((q,weight_mapping[q][0]))] = (q, best_match[0])
                    weight_mapping[q] = best_match
                    db_nodes.remove(best_match[0])






    def match_and_score_nhi(self, nhi_query, nhi_db):
        # This function will simultaneously match and score two neighborhood indices
        if nhi_query['label'] != nhi_db['label']:
            return (False, 0)

        num_allowed_misses = int(self.rho * nhi_query['degree'])

        # IV.2 test
        if nhi_db['degree'] < nhi_query['degree'] - num_allowed_misses:
            return (False, 0)

        # IV.3 test
        nb_miss = abs(len(nhi_query['nbArray']) - len(set(nhi_query['nbArray']).intersection(set(nhi_db['nbArray']))))
        if nb_miss > num_allowed_misses:
            return (False, 0)

        # IV.4 test
        if nhi_db['nbConnection'] >= nhi_query['nbConnection']:
            nbc_miss = 0
        else:
            nbc_miss = nhi_query['nbConnection'] - nhi_db['nbConnection']

        if nbc_miss > num_allowed_misses:
            return (False, 0)

        # Now we score the match
        if nhi_query['degree'] == 0:
            f_nb = 0
        else:
            f_nb = nb_miss / nhi_query['degree']

        if nhi_query['nbConnection'] == 0:
            f_nbc = 0
        else:
            f_nbc = nbc_miss / nhi_query['nbConnection']


        if nb_miss == 0:
            w = 2 - f_nbc
        else:
            w = 2 - (f_nb + (f_nbc / nb_miss))

        return (True, w)


    def __find_important_nodes(self, graph):
        """ Returns a list of important nodes (based on degree, top P_imp percent) """

        if len(self.important_nodes) > 0:
            return self.important_nodes

        # import based on degree centrality
        node_degree_dict = {}
        nodes_to_return = int(len(graph.nodes) * self.P_imp)
        for n in graph.nodes:
            node_degree_dict[n] = graph.degree(n)

        important_nodes = []
        for node_id, degree in reversed(sorted(node_degree_dict.iteritems(), key=lambda (k,v): (v,k))):
            important_nodes.append(node_id)
            nodes_to_return = nodes_to_return - 1
            if nodes_to_return <= 0:
                break
        return important_nodes

    def find_matching_nodes(self, q_nh_idx, db_nh_idx, q_node):
        # we want to return all nodes in db graph that match our query node
        query_nhi = q_nh_idx[q_node]
        matching_db_nodes = []
        for node, nh_idx in db_nh_idx.iteritems():
            is_match, score = self.match_and_score_nhi(query_nhi, nh_idx)
            if is_match:
                matching_db_nodes.append((node, score))
        return matching_db_nodes


    def match_important_nodes(self, q_nodes, q_nh_idx, db_nh_idx):
        # This will be our bipartite 1-many mapping from query graph to db graph
        node_mapping = {}
        for n in q_nodes:
            # These are our important query nodes
            node_mapping[n] = []
            # Now we want to match this node to db graph
            matching_nodes = self.find_matching_nodes(q_nh_idx, db_nh_idx, n)
            if(len(matching_nodes) == 0):
                # "Unable to match node...skipping"
                continue
            for (node, score) in matching_nodes:
                node_mapping[n].append((node, score))
        # NOTE: its possible that node_mapping has duplicate Node IDs between query
        # graph and database graph

        # In paper they did max weight bipartite matching
        # I'm just doing a greedy method
        #G_max_weight = nx.max_weight_matching(G)
        index = 0
        query_node_converter = []
        for n in node_mapping.keys():
            query_node_converter.append(n)

        db_node_converter = []
        for list_of_mappings in node_mapping.values():
            for (db_node, score) in list_of_mappings:
                if db_node not in db_node_converter:
                    db_node_converter.append(db_node)

        G = nx.Graph()
        for query_node, list_of_mappings in node_mapping.iteritems():
            query_converted_id = query_node_converter.index(query_node)
            G.add_node(query_converted_id)
            for (db_node, score) in list_of_mappings:
                db_converted_id = db_node_converter.index(db_node) + len(query_node_converter)
                if db_converted_id not in G.nodes:
                    G.add_node(db_converted_id)

                G.add_edge(query_converted_id, db_converted_id)
                G[query_converted_id][db_converted_id]['weight'] = score



        max_weight_matching = nx.max_weight_matching(G)
        node_mapping_max_weight = {}
        for i, query_node in enumerate(query_node_converter):
            if i in max_weight_matching.keys():
                db_converted_id = max_weight_matching[i] - len(query_node_converter)
                node_mapping_max_weight[query_node] = (db_node_converter[db_converted_id],2)








        #node_mapping_max_weight = self.__greedy_max_weight_matching(node_mapping)
        return node_mapping_max_weight


    def __greedy_max_weight_matching(self, node_weight_mapping):
        # TODO: Make this function better!
        used_db_nodes = [] # list of used up DB nodes so we get 1-1 mapping

        max_weight_mapping = {}

        # first take care of nodes that only have 1 match
        for (q_node, list_of_mappings) in node_weight_mapping.iteritems():
            if len(list_of_mappings) == 1:
                if list_of_mappings[0][0] in used_db_nodes:
                    # node already claimed by antoher match
                    continue
                else:
                    used_db_nodes.append(list_of_mappings[0][0])
                    max_weight_mapping[q_node] = list_of_mappings[0]
        # now do nodes with more than one match
        for (q_node, list_of_mappings) in node_weight_mapping.iteritems():
            if len(list_of_mappings) > 1:
                best = None
                for (node, score) in list_of_mappings:
                    if node not in used_db_nodes:
                        if best is None:
                            best = (node, score)
                        else:
                            if score > best[1]:
                                best = (node, score)
                if best is not None:
                    used_db_nodes.append(best[0])
                    max_weight_mapping[q_node] = best

        return max_weight_mapping




    def __compute_node_nh_idx(self, graph, node_id):
        d = {}
        d['label'] = graph.node[node_id]['type']
        d['degree'] = graph.degree(node_id)
        d['nbConnection'] = 0
        d['nbArray'] = []
        for nb in graph.neighbors(node_id):
            # Building list of labels
            if graph.node[nb]['type'] not in d['nbArray']:
                d['nbArray'].append(graph.node[nb]['type'])

            # Keeping track of neighbor connectedness
            d['nbConnection'] = d['nbConnection'] + len(set(graph.neighbors(nb)).intersection(set(graph.neighbors(node_id))))

        # Double counted...so divide by two..lol
        d['nbConnection'] = d['nbConnection'] / 2
        return d

    def __generate_nh_index(self,query_graph, database_graph):
        # dictionary for query graph NHI
        query_nh_idx = {}
        # dictionary for database graph NHI
        database_nh_idx = {}

        for n in query_graph.nodes:
            query_nh_idx[n] = self.__compute_node_nh_idx(query_graph, n)

        for n in database_graph.nodes:
            database_nh_idx[n] = self.__compute_node_nh_idx(database_graph, n)

        return query_nh_idx, database_nh_idx

if __name__ == "__main__":
    t = Tale()
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
    G.add_edge(0,2)
    G.add_edge(0,3)
    G.add_edge(1,2)
    G.add_edge(2,3)

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
    H.add_edge(4,6)
    H.add_edge(4,7)
    H.add_edge(5,6)
    H.add_edge(6,7)

    fp = nx.read_gpickle('positive_footprint_new.gpickle')
    v = nx.read_gpickle('data_vuln/flic_decode_frame_8BPP_VULN.gpickle')

    print t.match(fp, v)[0]

