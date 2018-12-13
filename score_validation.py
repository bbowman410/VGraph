import sys

input_file = sys.argv[1]
match_thresh = sys.argv[2]

print input_file
print match_thresh

TP = 0
FP = 0
TN = 0
FN = 0
with open(input_file, 'r') as f:
    for l in f.readlines():
        vg, tg, pos_score, neg_score = l.split('\t')
        print "%s %s" % (pos_score, neg_score)
        vg_repo, vg_cve,vg_file,vg_func = vg.split('/')[-4:]  
        tg_repo, tg_cve, tg_v_or_p, tg_file, _, tg_func = tg.split('/')[-6:]
        tg_func = tg_func[:-len(".gpickle")]
        
        if vg_cve == tg_cve and \
               vg_file == tg_file and \
               vg_func == tg_func and \
               vg_repo == tg_repo and \
               tg_v_or_p == 'vuln':
            # This should have been flagged
            if int(pos_score) > int(match_thresh) and int(pos_score) > int(neg_score):
                TP += 1
            else:
                FN += 1
                print "FN " + l
        else:
            if int(pos_score) > int(match_thresh) and int(pos_score) > int(neg_score):
                FP += 1
                print "FP " + l
            else:
                TN += 1 
            

print "TP: %d" % TP
print "FP: %d" % FP
print "TN: %d" % TN
print "FN: %d" % FN

print "P: %.2f" % (float(TP)/float(TP+FP))
print "R: %.2f" % (float(TP)/float(TP+FN))
        
