import networkx as nx
import tale
import sys
import os
import pickle as pkl
import random


if __name__ == "__main__":
    cve_dir=sys.argv[1]
    target_file=sys.argv[2]

    print cve_dir
    print target_file

    # Load our CVGs for this CVE
    cvg_funcs = []
    cvgs = {}
    for f in os.listdir(cve_dir):
        if f.endswith("_pfg.gpickle"):
            func_name = f[:-len("_pfg.gpickle")]
            if func_name not in cvgs.keys():
                cvgs[func_name] = {}

    for f in cvgs.keys():
        cvgs[f]['pCVG'] = nx.read_gpickle("%s/%s_pfg.gpickle" % (cve_dir,f))
        cvgs[f]['pCVG_nhi'] = tale.generate_nh_index(cvgs[f]['pCVG'])
        cvgs[f]['pCVG_important_nodes'] = pkl.load(open("%s/%s_pfg.important_nodes" % (cve_dir,f), 'rb'))
        cvgs[f]['pCVG_size'] = pkl.load(open("%s/%s_size" % (cve_dir,f), 'rb'))
        cvgs[f]['nCVG'] = nx.read_gpickle("%s/%s_nfg.gpickle" % (cve_dir,f))
        cvgs[f]['nCVG_nhi'] = tale.generate_nh_index(cvgs[f]['nCVG'])
        cvgs[f]['nCVG_important_nodes'] = pkl.load(open("%s/%s_nfg.important_nodes" % (cve_dir,f), 'rb'))

    # Load the target graph
    target = nx.read_gpickle(target_file)
    target_nhi = tale.generate_nh_index(target)
    for f in cvgs.keys():
        if abs(len(target.nodes) - cvgs[f]['pCVG_size']) > 3*cvgs[f]['pCVG_size']:
            print "Size difference too big"
            print "%s %s %d %d %d" % (f, target_file, 0, 0, 0)
        else:
            pos_match_score, pos_node_mapping, pos_imp_match_score = tale.match(cvgs[f]['pCVG'], target, cvgs[f]['pCVG_nhi'], target_nhi, cvgs[f]['pCVG_important_nodes'])

            neg_match_score, neg_node_mapping, neg_imp_match_score = tale.match(cvgs[f]['nCVG'], target, cvgs[f]['nCVG_nhi'], target_nhi, cvgs[f]['nCVG_important_nodes'])

            print "%s %s %d (%d) %d (%d)" % (f, target_file, pos_match_score, pos_imp_match_score, neg_match_score, neg_imp_match_score)




