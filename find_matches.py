import networkx as nx
import tale
import Queue
import multiprocessing
import sys
import os
import pickle as pkl


NUM_PROCS=10

""" Multi process worker daemon"""
def worker(work_q, done_q):
    while True:
        job = work_q.get() # blocks until there is work
        job_num = job[0]
        query_graph = job[1]
        target_graph = job[2]
	query_nhi = job[3]
	target_nhi = job[4]
	important_nodes = job[5]
	done_q.put((job_num, tale.match(query_graph, target_graph, query_nhi, target_nhi, important_nodes)))


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
	    pCVG_nhi = tale.generate_nh_index(pCVG)
            pCVG_important_nodes = pkl.load(open(t[1] + "_pfg.important_nodes", 'rb'))
            nCVG_important_nodes = pkl.load(open(t[1] + "_nfg.important_nodes", 'rb'))

            query_graphs[cve].append({
                "func_name":t[0],
                "pCVG":pCVG,
                "pCVG_important_nodes":pCVG_important_nodes,
		"pCVG_nhi":pCVG_nhi,
                "nCVG":nCVG,
                "nCVG_important_nodes":nCVG_important_nodes})
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
       	    target_graphs[f] = (tg, tg_nhi)
    return target_graphs


def main(args):
    if len(args) != 3:
        print "Usage: python find_matches.py <vuln_graph_db> <target_graph_db>"
        exit()

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

    num_cves = len(query_graphs)
    curr_cve = 0
    idx_to_file = {}
    # Each CVE may have multiple CVGs.. although most should have one
    for cve, array_of_cvgs in query_graphs.iteritems():
        for cvg in array_of_cvgs:
            i = 0
	    idx_to_file.clear()
            # build work q
            for target_file, target_graph in target_graphs.iteritems(): # this should be only 10 for testing...
                work_q.put((i,cvg['pCVG'],target_graph[0], cvg['pCVG_nhi'], target_graph[1], cvg['pCVG_important_nodes']))
    	        idx_to_file[i] = target_file
                i = i + 1

	    # wait for work_q to drain
	    while work_q.qsize() > 0:
	        # our little worker bees are working.  flush the done_q while we wait so it doesn't get backed up...
	        if not done_q.empty():
	            res = done_q.get()
            	    print "pCVG\t%s\t%s\t%s\t%d" % (cve, cvg['func_name'], idx_to_file[res[0]], res[1][0])

	    # at this point, work_q is drained
            # still might be some stuff in done q
            while not done_q.empty():
                res = done_q.get()
                print "pCVG\t%s\t%s\t%s\t%d" % (cve, cvg['func_name'], idx_to_file[res[0]], res[1][0])
        # At this point we move onto next CVG
        curr_cve = curr_cve + 1


if __name__ == "__main__":
    main(sys.argv)
