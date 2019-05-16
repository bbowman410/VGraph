# vGraph:
#  positive
#  negative
#  context

# constructor should take a vulnerable graph and a patch graph and generate all internal representations
import networkx as nx
class VGraph:
    MIN_NODES=50

    def __init__(self, vuln_graph_file, patch_graph_file):
        self.v = nx.read_gpickle(vuln_graph_file)
        self.p = nx.read_gpickle(patch_graph_file)
        self.v_to_p, self.p_to_v = self.__align_graphs()

        self.positive = self.__gen_positive_vg()
        self.negative = self.__gen_negative_vg()
        self.context = self.__gen_context_vg()

        self.positive_index = self.__gen_index(self.positive)
        self.negative_index = self.__gen_index(self.negative)
        self.context_index = self.__gen_index(self.context)

        self.positive_imp_nodes = self.__gen_imp_nodes(self.positive)
        self.negative_imp_nodes = self.__gen_imp_nodes(self.negative)
        self.context_imp_nodes = self.__gen_imp_nodes(self.context)

        self.positive_bfs_trees = self.__gen_bfs_trees(self.positive_imp_nodes, self.positive)
        self.negative_bfs_trees = self.__gen_bfs_trees(self.negative_imp_nodes, self.negative)
        self.context_bfs_trees = self.__gen_bfs_trees(self.context_imp_nodes, self.context)


    def match(self, q, t, q_prepared, t_prepared):
        raise NotImplementedError

    def prepare_query(self, q):
        raise NotImplementedError

    def prepare_target(self, t):
        raise NotImplementedError

    def __align_graphs(self):
        src_graph = self.v
        dst_graph = self.p

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

    def __gen_positive_vg(self):
        pvg = nx.DiGraph()
        for v_node in set(self.v.nodes).difference(set(self.v_to_p.keys())):
            pvg.add_node(v_node)
            pvg.node[v_node]['type'] = self.v.node[v_node]['type']
            pvg.node[v_node]['code'] = self.v.node[v_node]['code']
            pvg.node[v_node]['style'] = 'o'

        self.__add_edges(pvg, self.v)
        self.__connect_graph(pvg, self.v)
        while len(pvg.nodes) < self.MIN_NODES and len(pvg.nodes) < len(self.v.nodes):
            self.__expand_graph(pvg, self.v)
        
        return pvg

    
    def __gen_negative_vg(self):
        nvg = nx.DiGraph()
        # Add all nodes in P that were missing from V (i.e. added during patch)
        for p_node in set(self.p.nodes).difference(set(self.p_to_v.keys())):
            nvg.add_node(p_node)
            nvg.node[p_node]['type'] = self.p.node[p_node]['type']
            nvg.node[p_node]['code'] = self.p.node[p_node]['code']
            nvg.node[p_node]['style'] = 'o'

        self.__add_edges(nvg, self.p)
        self.__connect_graph(nvg, self.p)
        while len(nvg.nodes) < self.MIN_NODES and len(nvg.nodes) < len(self.p.nodes):
            self.__expand_graph(nvg, self.p)
   
        return nvg

    def __gen_context_vg(self):
        cvg = nx.DiGraph()
        for n in self.v_to_p: # These are all shared nodes
            if n in self.positive.nodes or self.v_to_p[n] in self.negative.nodes:
            # these nodes were added during expand_graph
            # skip them so we dont overlap (or should we overlap??)
                continue

            #context_graph.add_node(n)
            #context_graph.node[n]['type'] = V.node[n]['type']
            #context_graph.node[n]['code'] = V.node[n]['code']

            added=False
            for n2 in list(self.v.predecessors(n)) + list(self.v.successors(n)):
                if n2 in self.positive.nodes:
                    # Found context node because it has edge into positive vGraph
                    cvg.add_node(n)
                    cvg.node[n]['type'] = self.v.node[n]['type']
                    cvg.node[n]['code'] = self.v.node[n]['code']
                    added=True
                    break
            if added:
                continue # already added so just move on
            # otherwise lets check patch nodes

            for n2 in list(self.p.predecessors(self.v_to_p[n])) + list(self.p.successors(self.v_to_p[n])):
                if n2 in self.negative.nodes:
                    # Found context node because it has edge into negative vGraph
                    cvg.add_node(n)
                    cvg.node[n]['type'] = self.v.node[n]['type']
                    cvg.node[n]['code'] = self.v.node[n]['code']
                    break
        
        self.__add_edges(cvg, self.v)
        self.__connect_graph(cvg, self.v)

        # Now we added some nodes, lets keep going until
        while len(cvg.nodes) < self.MIN_NODES:
            self.__expand_graph(cvg, self.v)

        return cvg

    def __gen_index(self, g):
        pass

    def __gen_imp_nodes(self, g):
        pass

    def __gen_bfs_trees(self, g, imp_nodes):
        pass

    # We want our graphs to remain connected, so we do that
    def __connect_graph(self,small_graph, big_graph):
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
    def __expand_graph(self, small_graph, big_graph, num_hops=1):
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

    def __add_edges(self, graph_nodes_only, full_graph):
        # finish graph by adding relevant edges
        for (src, dst) in full_graph.edges():
            if src in graph_nodes_only.nodes and dst in graph_nodes_only.nodes:
                graph_nodes_only.add_edge(src, dst)
                graph_nodes_only[src][dst]['type'] = full_graph[src][dst]['type']

