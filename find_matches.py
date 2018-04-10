import networkx as nx
from tale import Tale
import sys
import os
import pickle as pkl

if len(sys.argv) != 3:
    print "Usage: python subgraph_test.py <vuln_graph_db> <target_graph_db>"
    exit()

vuln_graph_db = sys.argv[1]
target_graph_db = sys.argv[2]

# Build lst of target files by walking target_graph_db looking for *.gpickle
target_files = []
for root, dirs, files in os.walk(target_graph_db):
    for f in files:
        if f.endswith(".gpickle"):
            if f.endswith("_pfg.gpickle") or f.endswith("_nfg.gpickle"):
                # We dont want our CVGs to be targets.  Skip these.
                continue
            print "Target File: %s" % (f)
            target_files.append("%s/%s" % (root, f))

print "Found %d target graphs." % len(target_files)

# Build list of +CGs
query_files = {}
for repo in os.listdir(vuln_graph_db):
    print "Found repo %s" % repo
    for cve in os.listdir(vuln_graph_db + "/" + repo):
        query_files[cve]= []
        for f in os.listdir(vuln_graph_db + "/" + repo + "/" + cve):
            if f.endswith("_pfg.gpickle"):
                func_name = f[:-len("_pfg.gpickle")]
                func_location = vuln_graph_db + "/" + repo + "/" + cve + "/" + func_name
                if func_location not in query_files[cve]:
                    query_files[cve].append((func_name, func_location))
        if len(query_files[cve]) == 0:
            # We must have failed to generate the CVG representation for this CVE
            del(query_files[cve])

print "Found %d CVEs with CVGs." % len(query_files)
print "Loading CVGs"
query_graphs = {}
num_query_graphs = 0
for cve, query_tuples in query_files.iteritems():
    query_graphs[cve] = []
    for t in query_tuples:
        pCVG = nx.read_gpickle(t[1] + "_pfg.gpickle")
        nCVG = nx.read_gpickle(t[1] + "_nfg.gpickle")
        pCVG_important_nodes = pkl.load(open(t[1] + "_pfg.important_nodes", 'rb'))
        nCVG_important_nodes = pkl.load(open(t[1] + "_nfg.important_nodes", 'rb'))

        query_graphs[cve].append({
            "func_name":t[0],
            "pCVG":pCVG,
            "pCVG_important_nodes":pCVG_important_nodes,
            "nCVG":nCVG,
            "nCVG_important_nodes":nCVG_important_nodes})
        num_query_graphs = num_query_graphs + 1

# Now we will process each target graph by:
# 1. load target graph
# 2. check target graph against all pCVG, nCVG
# 3. print results

print "Loading target graphs."
target_graphs = {}

for f in target_files:
    target_graphs[f] = nx.read_gpickle(f)

positive_tale = Tale(0,1)
negative_tale = Tale(0,1)

num_comparisons = len(target_files) * num_query_graphs
curr_comparison = 0
for cve, array_of_cvgs in query_graphs.iteritems():
    for cvg in array_of_cvgs:
        positive_tale.set_important_nodes(cvg['pCVG_important_nodes'])
        negative_tale.set_important_nodes(cvg['nCVG_important_nodes'])
        for target_file, target_graph in target_graphs.iteritems():
            print "Evaluating: %s %s %s. %d %% complete. (%d / %d)" % (cve, cvg['func_name'], target_file, curr_comparison*100/num_comparisons, curr_comparison, num_comparisons)
            pos_match_score, pos_node_mapping = positive_tale.match(cvg['pCVG'], target_graph)
            print "pCVG\t%s\t%s\t%s\t%d" % (cve, cvg['func_name'], target_file, pos_match_score)
            neg_match_score, neg_node_mapping = negative_tale.match(cvg['nCVG'], target_graph)
            print "nCVG\t%s\t%s\t%s\t%d" % (cve, cvg['func_name'], target_file, neg_match_score)
            curr_comparison = curr_comparison + 1




exit()


#    print "================RESULTS================"
#    top_num = 10
#    for f_name,s in reversed(sorted(pfg_result_list.iteritems(), key=lambda (k,v):(v,k))):
#        print "%s\t%s\ttotal match\t%d\tnfg_match\t%d" % (f, f_name, s, nfg_result_list[f_name])
#        top_num = top_num - 1
#        if top_num <= 0:
#            break



