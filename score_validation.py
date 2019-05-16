import sys

input_file = sys.argv[1]
ctx_thresh = sys.argv[2]
pos_thresh = sys.argv[3]
neg_delta = sys.argv[4]


# vgraph_db//xen/CVE-2017-12137/ce442926c2530da9376199dcc769436376ad2386/mm.c/destroy_grant_pte_mapping   evaluation_db/linux/CVE-2013-0231/after/imm/bdc5c1812cea6efe1aaefb3131fcba28cd0b2b68/pciback_ops.c/xen_pcibk_enable_msix.gpickle 00       0

TP = 0
FP = 0
TN = 0
FN = 0
with open(input_file, 'r') as f:
    for l in f.readlines():
        # Parse line sections
        vg, tg, context_score, pos_score, neg_score = l.split('\t')

        # Parse vGraph data 
        vg_repo, vg_cve, commit_hash, vg_file, vg_func = vg.split('/')[-5:]  

        vg_cve_year = int(vg_cve.split('-')[1])
        vg_cve_num = int(vg_cve.split('-')[2])

        # Parse target data
        tg_repo, tg_cve, b_or_a, time_delta, target_commit_hash, tg_file, tg_func = tg.split('/')[-7:]
        tg_cve_year = int(tg_cve.split('-')[1])
        tg_cve_num = int(tg_cve.split('-')[2])
        
        # Remove '.gpickle' from func
        tg_func = tg_func[:-len(".gpickle")]

        flagged = False
 
        if int(context_score) > int(ctx_thresh):
            # Passed context threshold
            if int(pos_score) > int(pos_thresh):
                # Passed positive threshold
                if int(pos_score) > int(neg_score) + int(neg_delta):
                    # Passed negative check
                    flagged = True

        # we call it a TP if:
        #  CVEs match, same file, and target commit is from before patch
        #   OR same file and vg year is newer than target
        #   OR same file, same year, and vg is newer than tg
        if flagged:
            if vg_cve == tg_cve and vg_file == tg_file and b_or_a in [ 'vuln', 'before' ]: 
                TP +=1
            elif vg_file == tg_file and vg_cve != tg_cve and  vg_cve_year >= tg_cve_year: # vGraph is NEWWER than target, which means target is likely still vulnerable
                TP += 1
            else:
                if vg_cve == tg_cve and b_or_a in ['after']: # same CVE, so we KNOW this is FP.. if we don't KNOW, we just ignore it.
                    FP += 1 
                    print "FP " + l
        else: # not flagged
            if vg_cve == tg_cve and vg_func == tg_func and vg_repo == tg_repo and b_or_a in [ 'vuln', 'before' ]:
                # should have been flagged
                FN += 1
                print "FN " + l
            else:
                TN +=1
                
            

print "TP: %d" % TP
print "FP: %d" % FP
print "TN: %d" % TN
print "FN: %d" % FN
P = float(TP)/float(TP+FP)
R = float(TP)/float(TP+FN)
F1 = 2*(P*R)/(P+R)

print "P: %.2f" % P
print "R: %.2f" % R
print "F1: %.2f" % F1

        
