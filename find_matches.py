import networkx as nx
import tale
import Queue
import multiprocessing
import sys
import os
import pickle as pkl


NUM_PROCS=30

def check_index(ind1, ind2, thresh):
    overlap = ind1.intersection(ind2)
    match_percent = len(overlap)*100/len(ind1)
    if match_percent >= thresh:
        return True
    else:
        return False

def generate_edge_indexing(g):
    # we will look at all edge node-relationship-node in g
    index = set([])
    for (a,b) in g.edges():
        index.add((g.node[a]['type'], g[a][b]['type'], g.node[b]['type']))
        index.add((g.node[b]['type'], g[b][a]['type'], g.node[a]['type']))

    return index


def simple_worker(work_q, done_q):
    while True:
       job = work_q.get()
       job_num = job[0]
       print "Processing job: %d" % job_num
       done_q.put((job_num, (0,0,0,0)))

""" Multi process worker daemon"""
def worker(work_q, done_q):
    while True:
        job = work_q.get() # blocks until there is work
        job_num = job[0]
        cvg = job[1]
        target = job[2]

        query_graph = cvg['pCVG']
        target_graph = target[0]
	query_nhi = cvg['pCVG_nhi']
	target_nhi = target[1]
	important_nodes = cvg['pCVG_important_nodes']
        context_mapping = cvg['context_mapping']
        # perform pCVG matching

        pos_score, pos_mapping, imp_node_score = tale.match(query_graph, target_graph, query_nhi, target_nhi, important_nodes, {})

        # Prematched node determination
        context_nodes = set(pos_mapping.keys()).intersection(set(context_mapping.keys()))
        # now we essentially want to pre-match those nodes in the nCVG
        prematched_nodes = {}
        for n in context_nodes:
            # 2 things we need to do here - convert our pCVG node to a nCVG node with the
            # context mapping, and set the match in the target graph to the same as
            # what was in the pos_node_mapping (if it was mapped)
            if n in pos_mapping and context_mapping[n][0] in cvg['nCVG']:
                prematched_nodes[context_mapping[n][0]] = pos_mapping[n]

        # Evaluating nCVG
        #neg_score, neg_mapping, neg_imp_node_score = tale.match(cvg['nCVG'], target_graph, cvg['nCVG_nhi'], target_nhi, cvg['nCVG_important_nodes'], prematched_nodes)
        neg_score, neg_mapping, neg_imp_node_score = tale.match(cvg['nCVG'], target_graph, cvg['nCVG_nhi'], target_nhi, cvg['nCVG_important_nodes'], {})# Screw prematched nodes...
        # perform nCVG matching

	done_q.put((job_num, (pos_score, imp_node_score, neg_score, neg_imp_node_score)))


""" Build list of target files from provided db location """
def get_target_files(target_db_location):
    # Build lst of target files by walking target_graph_db looking for *.gpickle
    target_files = []
    for root, dirs, files in os.walk(target_db_location):
        for f in files:
            if f.endswith(".gpickle"):
                if f.endswith("_pfg.gpickle") or f.endswith("_nfg.gpickle"):
                    # We dont want our CVGs to be targets.  Skip these.
                    continue
                target_files.append("%s/%s" % (root, f))

    print "Found %d target files." % len(target_files)
    return target_files

""" Build list of query files from provided db location """
def get_query_files(vuln_db_location):
    query_files = {}
    for repo in os.listdir(vuln_db_location):
        print "Found repo %s" % repo
        for cve in os.listdir(vuln_db_location + "/" + repo):
            query_files[cve]= []
            for f in os.listdir(vuln_db_location + "/" + repo + "/" + cve):
                if f.endswith("_pfg.gpickle"):
                    func_name = f[:-len("_pfg.gpickle")]
                    func_location = vuln_db_location + "/" + repo + "/" + cve + "/" + func_name
                    if func_location not in query_files[cve]:
                        query_files[cve].append((func_name, func_location))
            if len(query_files[cve]) == 0:
                # We must have failed to generate the CVG representation for this CVE
                del(query_files[cve])

    print "Found %d CVEs with CVGs." % len(query_files)
    return query_files

""" For each query file in query files list, load the CVG graphs """
def load_query_graphs(query_files_list):
    query_graphs = {}
    for cve, query_tuples in query_files_list.iteritems():
        query_graphs[cve] = []
        for t in query_tuples:
            pCVG = nx.read_gpickle(t[1] + "_pfg.gpickle")
            nCVG = nx.read_gpickle(t[1] + "_nfg.gpickle")
            pCVG_index = generate_edge_indexing(pCVG)
	    pCVG_nhi = tale.generate_nh_index(pCVG)
	    nCVG_nhi = tale.generate_nh_index(nCVG)
            pCVG_important_nodes = pkl.load(open(t[1] + "_pfg.important_nodes", 'rb'))
            nCVG_important_nodes = pkl.load(open(t[1] + "_nfg.important_nodes", 'rb'))
            pCVG_size = pkl.load(open(t[1] + "_size", 'rb'))
            context_mapping = pkl.load(open(t[1] + ".context_mapping", 'rb'))

            query_graphs[cve].append({
                "func_name":t[0],
                "func_loc":t[1],
                "pCVG":pCVG,
                "pCVG_index":pCVG_index,
                "pCVG_important_nodes":pCVG_important_nodes,
		"pCVG_size":pCVG_size,
		"pCVG_nhi":pCVG_nhi,
		"nCVG_nhi":nCVG_nhi,
                "nCVG":nCVG,
                "nCVG_important_nodes":nCVG_important_nodes,
                "context_mapping": context_mapping})
    return query_graphs

""" For each target file in target files list, load the CPG """
def load_target_graphs(target_files_list):
    target_graphs = {}
    for f in target_files_list:
        tg = nx.read_gpickle(f)
	if len(tg.nodes) < 10 or len(tg.nodes) > 2000:
	    print "Skipping target graph with number of nodes: %d" % len(tg.nodes)
	    continue
        else:
	    tg_nhi = tale.generate_nh_index(tg)
            tg_index = generate_edge_indexing(tg)
       	    target_graphs[f] = (tg, tg_nhi, tg_index)
    return target_graphs


def main(args):
    if len(args) != 3:
        print "Usage: python find_matches.py <vuln_graph_db> <target_graph_db>"
        exit()

    threshold = 90 # required edge_index matching
    # Setup our worker daemons prior to loading our data to prevent pollution in
    # worker process memory space
    work_q = multiprocessing.Queue()
    done_q = multiprocessing.Queue()
    processes = []
    for w in range(NUM_PROCS):
        p = multiprocessing.Process(target=worker, args=(work_q,done_q,))
        p.daemon = True
        processes.append(p)
        p.start()

    # Now start loading our data

    vuln_graph_db = args[1]
    target_graph_db = args[2]
    print vuln_graph_db
    print target_graph_db

    print "Parsing target files"
    target_files = get_target_files(target_graph_db)
    print "Parsing query files"
    query_files = get_query_files(vuln_graph_db)
    print "Loading target graphs"
    target_graphs = load_target_graphs(target_files)
    print "Loading query graphs"
    query_graphs = load_query_graphs(query_files)

    # main idea here:
    # for each cve in query_graphs
    #   for each cvg
    #       set important nodes for our tale graph matchers
    #       build a queue of work with cvg against each target graph
    #       start the threads
    #       wait for threads to complete...write results...move onto next cvg/cve

    curr_cve = 0
    idx_to_file = {}
    i = 0
    worker_info = {}
    for cve, array_of_cvgs in query_graphs.iteritems():
        for cvg in array_of_cvgs:
            for target_file, target_graph in target_graphs.iteritems():
                if check_index(cvg['pCVG_index'],target_graph[2], threshold): 
                    work_q.put((i, cvg, target_graph))
   		    worker_info[i] = (cve, cvg, target_file)
                    i += 1
    
    # work q populated...
    # now we wait
    num_completed_jobs = 0
    while num_completed_jobs < i:
        res = done_q.get()
        num_completed_jobs += 1
        print "%s\t%s\t%s\tU\t%d\t%d\t%d\t%d" % (worker_info[res[0]][0], worker_info[res[0]][1]['func_loc'], worker_info[res[0]][2], res[1][0], res[1][1], res[1][2], res[1][3])
  

if __name__ == "__main__":
    main(sys.argv)
