from src.matching.path_matcher import PathMatcher
from src.matching.tale_matcher import TaleMatcher

import networkx as nx
import tale
import time
import Queue
import multiprocessing
import sys
import os
import sys
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

    return index



""" Multi process worker daemon"""
def output_writer(done_q, ofp):
    while True:
        res = done_q.get()
        vg_id = res[0]
        target_id = res[1]
        context_score = res[2] * 100
        pos_score = res[3] * 100
        neg_score = res[4] * 100
        ofp.write("%s\t%s\t%d\t%d\t%d\n" % (vg_id, target_id, context_score, pos_score, neg_score))
        ofp.flush()


""" Multi process worker daemon"""
def worker(work_q, done_q, matching_alg):
    if matching_alg == 'path':
        matcher = PathMatcher()
    elif matching_alg == 'tale':
        matcher = TaleMatcher()
    else:
        print "Unknown matching algorithm: %s" % matching_alg
        exit()
    
    while True:
        job = work_q.get() # blocks until there is work
    
        
        vg_id = job[0]
        target_id = job[1]
        vg = job[2]
        target = job[3]
        
        context_score = 0
        pos_score = 0
        neg_score = 0

        # step 1: match on context graph
        context_mapping, context_score = matcher.match(vg['context'], target['graph'], vg['context_prepared'], target['prepared'])

        # step 2: Match on positive vGraph 
        pos_mapping, pos_score = matcher.match(vg['pvg'], target['graph'], vg['pvg_prepared'], target['prepared'])

        # step 3: Match on negative vGraph
        neg_mapping, neg_score = matcher.match(vg['nvg'], target['graph'], vg['nvg_prepared'], target['prepared'])
        
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
            for h in os.listdir(vuln_db_location + "/" + repo + '/' + cve):
                for src_file in os.listdir(vuln_db_location + '/' + repo + '/' + cve + '/' + h):
                    for f in os.listdir(vuln_db_location + "/" + repo + "/" + cve + '/'+ h + '/' + src_file):
                        if f.endswith("_pvg.gpickle"): # Found a vGraph
                            func_name = f[:-len("_pvg.gpickle")]
                            func_location = vuln_db_location + "/" + repo + "/" + cve + "/" + h + "/" + src_file + '/' + func_name
                            query_files.append(func_location)
                        #if func_location not in query_files[cve]:
                        #    query_files[cve].append((func_name, func_location))
            #if len(query_files[cve]) == 0:
                # We must have failed to generate the CVG representation for this CVE
            #    del(query_files[cve])

    print "Found %d query files," % len(query_files)
    return query_files

""" For each query file in query files list, load the CVG graphs """
def load_query_graphs(query_files_list, matcher):
    print "Loading %d query graphs..." % len(query_files_list)
    query_graphs = {}
    for vg in query_files_list:
        sys.stdout.write('%s\r' % (vg.rstrip()))
        sys.stdout.flush()
        pvg = nx.read_gpickle(vg + "_pvg.gpickle")
        nvg = nx.read_gpickle(vg + "_nvg.gpickle")
        context = nx.read_gpickle(vg + "_context.gpickle")
        pvg_index = generate_edge_indexing(pvg)
        context_index = generate_edge_indexing(context)
        size_idx = len(context.nodes()) + len(pvg.nodes())
	pvg_prepared = matcher.prepare_query(pvg)
	nvg_prepared = matcher.prepare_query(nvg)
	context_prepared = matcher.prepare_query(context)
        #context_mapping = pkl.load(open(vg + ".context_mapping", 'r'))
        query_graphs[vg] = {
            "id":vg,
            "pvg":pvg,
            "pvg_index":pvg_index,
            #"pvg_important_nodes":pCVG_important_nodes,
            #"pvg_size":pCVG_size,
            "pvg_prepared":pvg_prepared,
            "nvg_prepared":nvg_prepared,
            "nvg":nvg,
            "context":context,
            "context_prepared":context_prepared,
            "context_index":context_index,
            "size_idx": size_idx
         }
            #"nCVG_important_nodes":nCVG_important_nodes,
            #"context_mapping": context_mapping}
    return query_graphs

""" For each target file in target files list, load the CPG """
def load_target_graphs(target_files_list, matcher):
    print "Loading %d target graphs..." % len(target_files_list)
    target_graphs = {}
    for f in target_files_list:
        sys.stdout.write('%s\r' % (f.rstrip()))
        sys.stdout.flush()
        tg = nx.read_gpickle(f)
	if len(tg.nodes) < 10 or len(tg.nodes) > 20000:
	    print "Skipping target graph with number of nodes: %d" % len(tg.nodes)
	    continue
        else:
	    tg_prepared = matcher.prepare_target(tg)
            tg_index = generate_edge_indexing(tg)
       	    target_graphs[f] = {
                'graph': tg,
                'prepared': tg_prepared,
                'index':  tg_index,
                'size_idx':len(tg.nodes())
            }
    return target_graphs


def main(args):
    if len(args) != 5:
        print "Usage: python find_matches.py <vuln_graph_db> <target_graph_db> <result_file> <matching_alg>"
        exit()
    # parse args.  TODO use argparser
    vuln_graph_db = args[1]
    target_graph_db = args[2]
    result_file = args[3]
    matching_alg = str(args[4]).rstrip()

    # Verify args TODO use argparser
    if matching_alg == 'tale':
        print "Using TALE matching algorithm..."
        matcher = TaleMatcher()
    elif matching_alg == 'path':
        print "Using path matching algorithm..."
        matcher = PathMatcher()
    else:
        print "Unknown matching algorithm: %s" % matching_alg
        exit()

    # Set edge index threshold #TODO add as argument with default value
    # Also used for size.  
    edge_threshold = 90 
    size_threshold = .25
    work_q = multiprocessing.Queue()
    done_q = multiprocessing.Queue()
    processes = []
    for w in range(NUM_PROCS):
        p = multiprocessing.Process(target=worker, args=(work_q,done_q,matching_alg,))
        p.daemon = True
        processes.append(p)
        p.start()


    # Open output file
    ofp = open(result_file, 'w')
    if not ofp:
        print "Unable to open output file: %s.  Aborting." % result_file
        exit()
    
    # Start writer process
    writer = multiprocessing.Process(target=output_writer, args=(done_q,ofp,))
    writer.daemon = True
    writer.start() 

    print "Locating target files in %s" % target_graph_db
    target_files = get_target_files(target_graph_db)
    print "Locating query files in %s" % vuln_graph_db
    query_files = get_query_files(vuln_graph_db)
    print "Loading target graphs..."
    target_graphs = load_target_graphs(target_files, matcher)
    print "Loading query graphs..."
    query_graphs = load_query_graphs(query_files, matcher)

    print "Starting timer..."
    start_time = time.time()
    print "Building work queue..."
    failed_index_check = 0
    items_added = 0
    for vg in query_graphs:
        for target in target_graphs:
            if check_index(query_graphs[vg]['context_index'],target_graphs[target]['index'], edge_threshold): # and abs(target_graphs[target]['size_idx'] - query_graphs[vg]['size_idx']) < size_threshold*query_graphs[vg]['size_idx']: 
                items_added += 1
                work_q.put((vg, target, query_graphs[vg], target_graphs[target]))
            else:
                failed_index_check += 1
                done_q.put((vg, target, 0, 0, 0))
    print "Jobs added: %d" % items_added
    print "Jobs skipped: %d" % failed_index_check 
    print "Processing done queue..."
    while done_q.qsize() > 0 or work_q.qsize() > 0:
        sys.stdout.write('%d %%\r' % (((items_added - work_q.qsize()) * 100) / items_added))
        sys.stdout.flush()
        time.sleep(2)
    ofp.close()    
    print "Done!"
    elapsed_time = time.time() - start_time
    print "Elapsed time: "
    print elapsed_time
  

if __name__ == "__main__":
    main(sys.argv)
