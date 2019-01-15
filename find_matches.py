import networkx as nx
import tale
import time
import Queue
import multiprocessing
import sys
import os
import pickle as pkl


NUM_PROCS=40

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


""" Multi process worker daemon"""
def output_writer(done_q, ofp):
    while True:
        res = done_q.get()
        vg_id = res[0]
        target_id = res[1]
        context_score = res[2]
        pos_score = res[3]
        neg_score = res[4]
        ofp.write("%s\t%s\t%d\t%d\t%d\n" % (vg_id, target_id, context_score, pos_score, neg_score))
        ofp.flush()


""" Multi process worker daemon"""
def worker(work_q, done_q):
    while True:
        job = work_q.get() # blocks until there is work
        vg_id = job[0]
        target_id = job[1]
        vg = job[2]
        target = job[3]
        
        context_score = 0
        pos_score = 0
        neg_score = 0
        target_graph = target['graph']
	target_nhi = target['nhi']
	#important_nodes = cvg['pCVG_important_nodes']
        #context_mapping = vg['context_mapping']
        num_query_nodes = len(vg['context'].nodes)
        num_target_nodes = len(target_graph.nodes)
        if abs(num_query_nodes - num_target_nodes) > (0.2 * num_query_nodes):
            # number of nodes is too diferent.  This is an analogue for context behavior.  so we skip
            done_q.put((vg_id, target_id, 0, 0, 0))
            continue
       
        #match on context
        context_score, context_mapping = tale.match(vg['context'], target_graph, vg['context_nhi'], target_nhi) 

        # perform positive vGraph matching
        pos_score, pos_mapping = tale.match(vg['pvg'], target_graph, vg['pvg_nhi'], target_nhi)

        # perform negative vGraph matching
        neg_score, neg_mapping = tale.match(vg['nvg'], target_graph, vg['nvg_nhi'], target_nhi)
        

	done_q.put((vg_id, target_id, context_score, pos_score, neg_score))


""" Build list of target files from provided db location """
def get_target_files(target_db_location):
    # Build lst of target files by walking target_graph_db looking for *.gpickle
    target_files = []
    for root, dirs, files in os.walk(target_db_location):
        for f in files:
            if f.endswith(".gpickle"):
                if f.endswith("_pvg.gpickle") or f.endswith("_nvg.gpickle"):
                    # We dont want our CVGs to be targets.  Skip these.
                    continue
                target_files.append("%s/%s" % (root, f))

    print "Found %d target files." % len(target_files)
    #return target_files[:100] # 100 target files for testing...
    return target_files

""" Build list of query files from provided db location """
def get_query_files(vuln_db_location):
    query_files = []
    for repo in os.listdir(vuln_db_location):
        for cve in os.listdir(vuln_db_location + "/" + repo):
            for src_file in os.listdir(vuln_db_location + '/' + repo + '/' + cve):
                for f in os.listdir(vuln_db_location + "/" + repo + "/" + cve + '/' + src_file):
                    if f.endswith("_pvg.gpickle"): # Found a vGraph
                        func_name = f[:-len("_pvg.gpickle")]
                        func_location = vuln_db_location + "/" + repo + "/" + cve + "/" + src_file + '/' + func_name
                        query_files.append(func_location)
                        #if func_location not in query_files[cve]:
                        #    query_files[cve].append((func_name, func_location))
            #if len(query_files[cve]) == 0:
                # We must have failed to generate the CVG representation for this CVE
            #    del(query_files[cve])

    print "Found %d query files," % len(query_files)
    return query_files

""" For each query file in query files list, load the CVG graphs """
def load_query_graphs(query_files_list):
    print "Loading %d query graphs..." % len(query_files_list)
    query_graphs = {}
    for vg in query_files_list:
        pvg = nx.read_gpickle(vg + "_pvg.gpickle")
        nvg = nx.read_gpickle(vg + "_nvg.gpickle")
        context = nx.read_gpickle(vg + "_context.gpickle")
        pvg_index = generate_edge_indexing(pvg)
        context_index = generate_edge_indexing(context)
	pvg_nhi = tale.generate_nh_index(pvg)
	nvg_nhi = tale.generate_nh_index(nvg)
	context_nhi = tale.generate_nh_index(context)
        #pvg_important_nodes = pkl.load(open(t[1] + "_pvg.important_nodes", 'rb'))
        #nvg_important_nodes = pkl.load(open(t[1] + "_nfg.important_nodes", 'rb'))
        #pvg_size = pkl.load(open(t[1] + "_size", 'rb'))
        context_mapping = pkl.load(open(vg + ".context_mapping", 'r'))
        query_graphs[vg] = {
            "id":vg,
            "pvg":pvg,
            "pvg_index":pvg_index,
            #"pvg_important_nodes":pCVG_important_nodes,
            #"pvg_size":pCVG_size,
            "pvg_nhi":pvg_nhi,
            "nvg_nhi":nvg_nhi,
            "nvg":nvg,
            "context":context,
            "context_nhi":context_nhi,
            "context_index":context_index,
            #"nCVG_important_nodes":nCVG_important_nodes,
            "context_mapping": context_mapping}
    return query_graphs

""" For each target file in target files list, load the CPG """
def load_target_graphs(target_files_list):
    print "Loading %d target graphs..." % len(target_files_list)
    target_graphs = {}
    for f in target_files_list:
        tg = nx.read_gpickle(f)
	if len(tg.nodes) < 10 or len(tg.nodes) > 2000:
	    print "Skipping target graph with number of nodes: %d" % len(tg.nodes)
	    continue
        else:
	    tg_nhi = tale.generate_nh_index(tg)
            tg_index = generate_edge_indexing(tg)
       	    target_graphs[f] = {
                'graph': tg,
                'nhi': tg_nhi,
                'index':  tg_index
            }
    return target_graphs


def main(args):
    if len(args) != 4:
        print "Usage: python find_matches.py <vuln_graph_db> <target_graph_db> <result_file>"
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


    vuln_graph_db = args[1]
    target_graph_db = args[2]
    result_file = args[3]

    ofp = open(result_file, 'w')
    if not ofp:
        print "Unable to open output file: %s.  Aborting." % result_file
        exit()
    
    writer = multiprocessing.Process(target=output_writer, args=(done_q,ofp,))
    writer.daemon = True
    writer.start() 

    print vuln_graph_db
    print target_graph_db

    print "Locating target files..."
    target_files = get_target_files(target_graph_db)
    print "Locating query files..."
    query_files = get_query_files(vuln_graph_db)
    print "Loading target graphs..."
    target_graphs = load_target_graphs(target_files)
    print "Loading query graphs..."
    query_graphs = load_query_graphs(query_files)

    print "Building work queue..."
    failed_index_check = 0
    items_added = 0
    for vg in query_graphs:
        for target in target_graphs:
            if check_index(query_graphs[vg]['context_index'],target_graphs[target]['index'], threshold): 
                items_added += 1
                work_q.put((vg, target, query_graphs[vg], target_graphs[target]))
            else:
                failed_index_check += 1
                done_q.put((vg, target, 0, 0, 0))
    print "Jobs added: %d" % items_added
    print "Jobs skipped: %d" % failed_index_check 
    print "Processing done queue..."
    num_completed_jobs = 0
    while done_q.qsize() > 0 or work_q.qsize() > 0:
        time.sleep(2)
    ofp.close()    
    print "\nDone!"
  

if __name__ == "__main__":
    main(sys.argv)
