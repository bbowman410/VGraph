import os
import subprocess
import filecmp
from tqdm import tqdm
import numpy as np
import pickle as pkl
from src.graph.utils import load_vgraph_db, load_target_db
from src.matching.triplet_match import *
from multiprocessing import Pool,Process, Queue, SimpleQueue
import time

def decision_function(cvg_score, pvg_score, nvg_score):
    return cvg_score >= CVG_THRESH and pvg_score >= PVG_THRESH and pvg_score > nvg_score

def consume(work):
    (target_id, vg, t_trips) = work
    cvg_score, pvg_score, nvg_score = triplet_match_exact(vg, t_trips)
    return (target_id, vg, cvg_score, pvg_score, nvg_score)

def generate_ground_truth(target_graphs):
    NUM_VULN=0
    NUM_PATCH=0
    NUM_BEFORE=0
    NUM_AFTER=0
   
    for g in target_graphs:
        repo,cve,t,hash,f,_,_=g['path'].split('/')[-7:]
        func=g['base_name'] 
        
        
        if t == 'vuln':
            NUM_VULN += 1
        elif t == 'patch':
            NUM_PATCH += 1
        elif t == 'before':
            NUM_BEFORE += 1
        elif t == 'after':
            NUM_AFTER += 1


    print("Ground truth stats:")
    print("NUM_VULN: %d" % NUM_VULN)
    print("NUM_PATCH: %d" % NUM_PATCH)
    print("NUM_BEFORE: %d" % NUM_BEFORE)
    print("NUM_AFTER: %d" % NUM_AFTER)
    print("TOT_VULN: %d" % (NUM_VULN + NUM_BEFORE))
    print("TOT_NOT_VULN: %d" % (NUM_PATCH + NUM_AFTER))
    return NUM_VULN, NUM_PATCH, NUM_BEFORE, NUM_AFTER

def get_hits_multi(vgraph_db, target_db):
    work=[]
    scores = []
    for i, tg in enumerate(target_db):
        t_trips = tg['triples']
        tg['hits'] = [] # place to put hits
        for vg in vgraph_db:
            work.append((i,vg, t_trips)) 
    print("Work size: %d" % len(work))
    print("Applying pool...")
    p = Pool(NUM_PROCS)
    res = p.map(consume, work)
    print("done..")

    for (target_id, vg, cvg_score, pvg_score, nvg_score) in res:
        scores.append((vg['cve'],vg['repo'],vg['func'],target_db[target_id]['path'],cvg_score, pvg_score, nvg_score))
        if decision_function(cvg_score, pvg_score, nvg_score):
            target_db[target_id]['hits'].append(vg)


def get_hits(vgraph_db, target_db):
    skipped=0
    scores = []
    for i, tg in tqdm(enumerate(target_db)):
        tg['hits'] = [] # place to store our hits
        t_trips = tg['triples']
        t_vec = np.array(tg['vec'])
        for vg in vgraph_db:
            cvg_score, pvg_score, nvg_score = triplet_match_exact(vg, t_trips)
            scores.append((vg['cve'],vg['repo'],vg['func'],tg['path'],cvg_score, pvg_score, nvg_score))
            if decision_function(cvg_score, pvg_score, nvg_score):
                # we have a hit
                tg['hits'].append(vg)
    return scores


def eval_vgraph(vgraph_db, target_db, gt, manual_labels):
    # Loop through target graphs.  Get any vGraph hits and evaluate for truthiness
    # Now we score
    print("Scoring results...")

    # Score all:
    TP=0.
    FP=0.
    TN=0.
    FN=0.
    UNK=0
    for tg in target_db:
        if len(tg['hits']) == 0: # nothing hit on this target
            if '/patch/' in tg['path'] or '/after/' in tg['path']:
                TN +=1
            else: # something should have hit
                FN += 1
                if(PRINT_FN):
                    print("FN: %s" % (tg['path']))
        else:
            # something hit
            #accounted_for = False
            for vg in tg['hits']:
                if vg['cve'] in tg['path'] and ('/vuln/' in tg['path'] or '/before/' in tg['path']):
                    TP += 1
                    #accounted_for = True
                    #break
                elif vg['cve'] in tg['path'] and ('/patch/' in tg['path'] or '/after/' in tg['path']):
                    FP += 1
                    if PRINT_FP:
                        print("FP: %s %s" % (vg['cve'], tg['path']))
                    #accounted_for = True
                    #break
                else:
                    #continue # until we find either TP or FP
                    # Need to check
                    tg_name = tg['path'].split('/')[-1][:-len('.gpickle')]
                    vg_name = vg['func']
                    tg_time = int(tg['path'].split('/')[-4].split('_')[1])
                    vg_time = int(vg['hsh'].split('_')[1])
                    if tg_name == vg_name and tg_time < vg_time:
                        TP += 1
                    else:
                        # check in manual labels
                        found=False
                        for label in manual_labels:
                            label_split = label.rstrip().split(' ')
                            if label_split[1] == vg['cve'] and label_split[2] in tg['path']:
                                if label_split[0] == 'TP':
                                    TP += 1
                                else:
                                    FP += 1
                                    if PRINT_FP:
                                        print("FP: %s %s" % (vg['cve'], tg['path']))
                                found=True
                                break
                        if not found:
                            UNK += 1
                            if(PRINT_UNK):
                                print("UNK: %s %s/%s/%s/%s/%s)" % (tg['path'], vg['repo'], vg['cve'], vg['hsh'],vg['file'], vg['func']))

            #if not accounted_for:
            #    if '/patch/' in tg['path'] or '/after/' in tg['path']:
            #        TN +=1
            #    else: # something should have hit
            #        FN += 1

             
    P = TP/(TP+FP)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("All Score:")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tF1")   
    print("%d\t%d\t%d\t%d\t%d\t%02f\t%02f\t%02f"%(TP,FP,TN,FN,UNK,P,R,F1))

    print("Worst Case:")
    P = TP/(TP+FP + UNK)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))
    print("Best Case:")
    P = (TP+UNK)/(TP+FP+UNK)
    R = (TP+UNK)/(TP+UNK+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))


    # Score train data:
    TP=0.
    FP=0.
    TN=0.
    FN=0.
    UNK=0
    for tg in target_db:
        if not ('/vuln/' in tg['path'] or '/patch/' in tg['path']):
            continue # only vuln/patch
        if len(tg['hits']) == 0: # nothing hit on this target
            if '/patch/' in tg['path'] or '/after/' in tg['path']:
                TN +=1
            else: # something should have hit
                if(PRINT_FN):
                    print("FN: %s" % (tg['path']))
                FN += 1
        else:
            # something hit
            accounted_for = False  
            for vg in tg['hits']:
                if vg['cve'] in tg['path'] and ('/vuln/' in tg['path'] or '/before/' in tg['path']):
                    TP += 1
                    #accounted_for = True
                    #break
                elif vg['cve'] in tg['path'] and ('/patch/' in tg['path'] or '/after/' in tg['path']):
                    FP += 1
                    if PRINT_FP:
                        print("FP: %s %s" % (vg['cve'], tg['path']))
                    #accounted_for = True
                    #break
                else:
                    #continue
                    # Need to check
                    tg_name = tg['path'].split('/')[-1][:-len('.gpickle')]
                    vg_name = vg['func']
                    tg_time = int(tg['path'].split('/')[-4].split('_')[1])
                    vg_time = int(vg['hsh'].split('_')[1])
                    if tg_name == vg_name and tg_time < vg_time:
                        TP += 1
                    else:
                        # check in manual labels
                        found=False
                        for label in manual_labels:
                            label_split = label.rstrip().split(' ')
                            if label_split[1] == vg['cve'] and label_split[2] in tg['path']:
                                if label_split[0] == 'TP':
                                    TP += 1
                                else:
                                    FP += 1
                                    if PRINT_FP:
                                        print("FP: %s %s" % (vg['cve'], tg['path']))
                                found=True
                                break
                        if not found:
                            UNK += 1
                            if(PRINT_UNK):
                                print("UNK: %s %s/%s/%s/%s/%s)" % (tg['path'], vg['repo'], vg['cve'], vg['hsh'],vg['file'], vg['func']))

            #if not accounted_for:
            #    if '/patch/' in tg['path'] or '/after/' in tg['path']:
            #        TN +=1
            #    else: # something should have hit
            #        FN += 1

    P = TP/(TP+FP)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("Train Score:")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tF1")   
    print("%d\t%d\t%d\t%d\t%d\t%02f\t%02f\t%02f"%(TP,FP,TN,FN,UNK,P,R,F1))
    print("Worst Case:")
    P = TP/(TP+FP + UNK)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))
    print("Best Case:")
    P = (TP+UNK)/(TP+FP+UNK)
    R = (TP+UNK)/(TP+UNK+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))

    # score test data:
    TP=0.
    FP=0.
    TN=0.
    FN=0.
    UNK=0
    for tg in target_db:
        if not ('/before/' in tg['path'] or '/after/' in tg['path']):
            continue # only before/after
        if len(tg['hits']) == 0: # nothing hit on this target
            if '/patch/' in tg['path'] or '/after/' in tg['path']:
                TN +=1
            else: # something should have hit
                if(PRINT_FN):
                    print("FN: %s" % (tg['path']))
                FN += 1
        else:
            # something hit
            accounted_for = False
            for vg in tg['hits']:
                if vg['cve'] in tg['path'] and ('/vuln/' in tg['path'] or '/before/' in tg['path']):
                    TP += 1
                    #accounted_for = True
                    #break
                elif vg['cve'] in tg['path'] and ('/patch/' in tg['path'] or '/after/' in tg['path']):
                    FP += 1
                    if PRINT_FP:
                        print("FP: %s %s" % (vg['cve'], tg['path']))
                    #accounted_for = True
                    #break
                else:
                    #continue
                    # Need to check
                    tg_name = tg['path'].split('/')[-1][:-len('.gpickle')]
                    vg_name = vg['func']
                    tg_time = int(tg['path'].split('/')[-4].split('_')[1])
                    vg_time = int(vg['hsh'].split('_')[1])
                    if tg_name == vg_name and tg_time < vg_time:
                        TP += 1
                    else:
                        # check in manual labels
                        found=False
                        for label in manual_labels:
                            label_split = label.rstrip().split(' ')
                            if label_split[1] == vg['cve'] and label_split[2] in tg['path']:
                                if label_split[0] == 'TP':
                                    TP += 1
                                else:
                                    FP += 1
                                    if PRINT_FP:
                                        print("FP: %s %s" % (vg['cve'], tg['path']))
                                found=True
                                break
                        if not found:
                            UNK += 1
                            if(PRINT_UNK):
                                print("UNK: %s %s/%s/%s/%s/%s)" % (tg['path'], vg['repo'], vg['cve'], vg['hsh'],vg['file'], vg['func']))

            #if not accounted_for:
            #    if '/patch/' in tg['path'] or '/after/' in tg['path']:
            #        TN +=1
            #    else: # something should have hit
            #        FN += 1


    P = TP/(TP+FP)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("Test Score:")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tF1")   
    print("%d\t%d\t%d\t%d\t%d\t%02f\t%02f\t%02f"%(TP,FP,TN,FN,UNK,P,R,F1))
    print("Worst Case:")
    P = TP/(TP+FP + UNK)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))
    print("Best Case:")
    P = (TP+UNK)/(TP+FP+UNK)
    R = (TP+UNK)/(TP+UNK+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))
  
    # score test modified only:
    test_mod_tps = []
    score_by_line_mods = [] 
    TP=0.
    FP=0.
    TN=0.
    FN=0.
    UNK=0
    for tg in target_db:
        if not ('/before/' in tg['path'] or '/after/' in tg['path']):
            continue # only before/after

        d = '/'.join(tg['path'].split('/')[0:4]) # root/repo/CVE
        func = tg['path'].split('/')[-1] # function.gpickle

        if '/before/' in tg['path']: # should be vuln
            is_same = False
            for (root,dirs,files) in os.walk(d):
                if func in files and '/vuln/' in root:
                   # This is orig vuln file.  lets check for differences
                   before_src = tg['path'].replace('/graph/', '/code/')
                   before_src = before_src.replace('.gpickle','.c')
                   vuln_src = (root + '/' + func).replace('/graph/','/code/')
                   vuln_src = vuln_src.replace('.gpickle','.c')
                   if filecmp.cmp(before_src, vuln_src):
                       # found match
                       is_same = True
                       break
            if is_same:
                continue # skip this one

            # Count line diffs of files
            res = subprocess.check_output('diff %s %s | grep "^>" | wc -l' % (vuln_src, before_src), shell=True)
            num_right_mods = int(res.decode('utf-8').rstrip())
            res = subprocess.check_output('diff %s %s | grep "^<" | wc -l' % (vuln_src, before_src), shell=True)
            num_left_mods = int(res.decode('utf-8').rstrip())
            res = subprocess.check_output("wc -l %s | awk '{print $1}'" % (vuln_src), shell=True)
            num_lines_orig = int(res.decode('utf-8').rstrip())
            #os.system('diff %s %s | grep "^>" | wc -l > scratch' % (vuln_src, before_src))

        else: # after patch so should be patched
            is_same = False
            for (root,dirs,files) in os.walk(d):
                if func in files and '/patch/' in root:
                   # This is orig vuln file.  lets check for differences
                   after_src = tg['path'].replace('/graph/', '/code/')
                   after_src = after_src.replace('.gpickle','.c')
                   patch_src = (root + '/' + func).replace('/graph/','/code/')
                   patch_src = patch_src.replace('.gpickle','.c')
                   if filecmp.cmp(after_src, patch_src):
                       is_same = True
                       break
            if is_same:
                continue # skip this
         
            # Count line diffs of files
            res = subprocess.check_output('diff %s %s | grep "^>" | wc -l' % (patch_src, after_src), shell=True)
            num_right_mods = int(res.decode('utf-8').rstrip())
            res = subprocess.check_output('diff %s %s | grep "^<" | wc -l' % (patch_src, after_src), shell=True)
            num_left_mods = int(res.decode('utf-8').rstrip())
            res = subprocess.check_output("wc -l %s | awk '{print $1}'" % (patch_src), shell=True)
            num_lines_orig = int(res.decode('utf-8').rstrip())
            #os.system('diff %s %s | grep "^>" | wc -l > scratch' % (patch_src, after_src))

        # If we make it here, this is either a before/after target graph which has
        # source code thats modified from the vuln/patch file used to generate vGraph

        # count num lines
        #with open('scratch', 'r') as fp:
        #    num_mods = fp.readlines()[0]
        if num_right_mods == num_left_mods:
            print("Type-2")
            clone_type=2
        elif num_right_mods+num_left_mods > int(0.5*num_lines_orig):
            print("Type-4")
            clone_type=4
        else:
            print("Type-3")
            clone_type=3
        num_mods = num_right_mods
        #print("Num mods: %s" % num_mods)

        # score it
        if len(tg['hits']) == 0: # nothing hit on this target
            if '/patch/' in tg['path'] or '/after/' in tg['path']:
                TN +=1
                score_by_line_mods.append([tg['path'],num_mods,clone_type,'TN'])
            else: # something should have hit
                FN += 1
                score_by_line_mods.append([tg['path'],num_mods,clone_type,'FN'])
        else:
            # something hit
            accounted_for = False
            for vg in tg['hits']:
                if vg['cve'] in tg['path'] and ('/vuln/' in tg['path'] or '/before/' in tg['path']):
                    TP += 1
                    score_by_line_mods.append([tg['path'],num_mods,clone_type,'TP'])
                    accounted_for = True
                    break
                    #test_mod_tps.append((tg['path'],vg['cve'],vg['file'],vg['func']))
                elif vg['cve'] in tg['path'] and ('/patch/' in tg['path'] or '/after/' in tg['path']):
                    FP += 1
                    score_by_line_mods.append([tg['path'],num_mods,clone_type,'FP'])
                    accounted_for = True
                    break
                else:
                    continue # Not considering cross-cve clones for per-line mode experiment
                    # Need to check
                    tg_name = tg['path'].split('/')[-1][:-len('.gpickle')]
                    vg_name = vg['func']
                    tg_time = int(tg['path'].split('/')[-4].split('_')[1])
                    vg_time = int(vg['hsh'].split('_')[1])
                    if tg_name == vg_name and tg_time < vg_time:
                        test_mod_tps.append((tg['path'],vg['cve'],vg['file'],vg['func']))
                        TP += 1
                    else:
                         # check in manual labels
                        found=False
                        for label in manual_labels:
                            label_split = label.rstrip().split(' ')
                            if label_split[1] == vg['cve'] and label_split[2] in tg['path']:
                                if label_split[0] == 'TP':
                                    TP += 1
                                else:
                                    FP += 1
                                found=True
                                break
                        if not found:
                            UNK += 1
                            if(PRINT_UNK):
                                print("UNK: %s %s/%s/%s/%s/%s)" % (tg['path'], vg['repo'], vg['cve'], vg['hsh'],vg['file'], vg['func']))

            if not accounted_for:
                if '/patch/' in tg['path'] or '/after/' in tg['path']:
                    TN +=1
                    score_by_line_mods.append([tg['path'],num_mods,clone_type,'TN'])
                else: # something should have hit
                    FN += 1
                    score_by_line_mods.append([tg['path'],num_mods,clone_type,'FN'])

    
    with open('vgraph_score_by_line_mods.txt','w') as fp:
        for s in score_by_line_mods:
            fp.write("%s %s %s %s\n" % (s[0], s[1], s[2], s[3]))




    P = TP/(TP+FP)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("Test Modified")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tF1")
    print("%d\t%d\t%d\t%d\t%d\t%02f\t%02f\t%02f"%(TP,FP,TN,FN,UNK,P,R,F1))
    print("Worst Case:")
    P = TP/(TP+FP + UNK)
    R = TP/(TP+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))
    print("Best Case:")
    P = (TP+UNK)/(TP+FP+UNK)
    R = (TP+UNK)/(TP+UNK+FN)
    F1 = 2*(P*R)/(P+R)
    print("%02f\t%02f\t%02f"%(P,R,F1))


def eval_vgraph_mods_only(vgraph_db, target_db, gt, manual_labels):
    # score test modified
    test_mod_tps = []
    score_by_line_mods = []
    TP=0.
    FP=0.
    TN=0.
    FN=0.
    UNK=0
    for tg in target_db:
        if not ('/before/' in tg['path'] or '/after/' in tg['path']):
            continue # only before/after

        d = '/'.join(tg['path'].split('/')[0:4]) # root/repo/CVE
        func = tg['path'].split('/')[-1] # function.gpickle

        if '/before/' in tg['path']: # should be vuln
            is_same = False
            for (root,dirs,files) in os.walk(d):
                if func in files and '/vuln/' in root:
                   # This is orig vuln file.  lets check for differences
                   before_src = tg['path'].replace('/graph/', '/code/')
                   before_src = before_src.replace('.gpickle','.c')
                   vuln_src = (root + '/' + func).replace('/graph/','/code/')
                   vuln_src = vuln_src.replace('.gpickle','.c')
                   if filecmp.cmp(before_src, vuln_src):
                       # found match
                       is_same = True
                       break
            if is_same:
                continue # skip this one
            print('diff %s %s | grep "^>" | wc -l > scratch' % (vuln_src, before_src))
            #os.system('diff %s %s | grep "^>" | wc -l > scratch' % (vuln_src, before_src))
        else: # after patch so should be patched
            is_same = False
            for (root,dirs,files) in os.walk(d):
                if func in files and '/patch/' in root:
                   # This is orig vuln file.  lets check for differences
                   after_src = tg['path'].replace('/graph/', '/code/')
                   after_src = after_src.replace('.gpickle','.c')
                   patch_src = (root + '/' + func).replace('/graph/','/code/')
                   patch_src = patch_src.replace('.gpickle','.c')
                   if filecmp.cmp(after_src, patch_src):
                       is_same = True
                       break
            if is_same:
                continue # skip this
            #os.system('diff %s %s | grep "^>" | wc -l > scratch' % (patch_src, after_src))
        # If we make it here, this is either a before/after target graph which has
        # source code thats modified from the vuln/patch file used to generate vGraph

        # count num lines
        #with open('scratch', 'r') as fp:
        #    num_mods = fp.readlines()[0]
        #print("Num mods: %s" % num_mods)

        # score it
        if len(tg['hits']) == 0: # nothing hit on this target
            if '/patch/' in tg['path'] or '/after/' in tg['path']:
                TN +=1
                #score_by_line_mods.append([tg['path'],num_mods,'TN'])
            else: # something should have hit
                FN += 1
                #score_by_line_mods.append([tg['path'],num_mods,'FN'])
        else:
            # something hit
            accounted_for = False
            for vg in tg['hits']:
                if vg['cve'] in tg['path'] and ('/vuln/' in tg['path'] or '/before/' in tg['path']):
                    TP += 1
                    #score_by_line_mods.append([tg['path'],num_mods,'TP'])
                    accounted_for = True
                    break
                    #test_mod_tps.append((tg['path'],vg['cve'],vg['file'],vg['func']))
                elif vg['cve'] in tg['path'] and ('/patch/' in tg['path'] or '/after/' in tg['path']):
                    FP += 1
                    #score_by_line_mods.append([tg['path'],num_mods,'FP'])
                    accounted_for = True
                    break
                else:
                    continue
                    # Need to check
                    tg_name = tg['path'].split('/')[-1][:-len('.gpickle')]
                    vg_name = vg['func']
                    tg_time = int(tg['path'].split('/')[-4].split('_')[1])
                    vg_time = int(vg['hsh'].split('_')[1])
                    if tg_name == vg_name and tg_time < vg_time:
                    #    test_mod_tps.append((tg['path'],vg['cve'],vg['file'],vg['func']))
                        TP += 1
                    else:
                         # check in manual labels
                        found=False
                        for label in manual_labels:
                            label_split = label.rstrip().split(' ')
                            if label_split[1] == vg['cve'] and label_split[2] in tg['path']:
                                if label_split[0] == 'TP':
                                    TP += 1
                                else:
                                    FP += 1
                                found=True
                                break
                        if not found:
                            UNK += 1
                            if(PRINT_UNK):
                                print("UNK: %s %s/%s/%s/%s/%s)" % (tg['path'], vg['repo'], vg['cve'], vg['hsh'],vg['file'], vg['func']))

            if not accounted_for:
                if '/patch/' in tg['path'] or '/after/' in tg['path']:
                    TN +=1
                    #score_by_line_mods.append([tg['path'],num_mods,'TN'])
                else: # something should have hit
                    FN += 1
                    #score_by_line_mods.append([tg['path'],num_mods,'FN'])
    #with open('vgraph_score_by_line_mods.txt','w') as fp:
    #    for s in score_by_line_mods:
    #        fp.write("%s %s %s\n" % (s[0], s[1], s[2]))



    try:
        P = TP/(TP+FP)
    except:
        P=0.
    try:
        R = TP/(TP+FN)
    except:
        R = 0.
    try:
        F1 = 2*(P*R)/(P+R)
    except:
        F1 = 0.
    print("Test Modified")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tF1")
    print("%d\t%d\t%d\t%d\t%d\t%02f\t%02f\t%02f"%(TP,FP,TN,FN,UNK,P,R,F1))

##############################################################################################
# main
#############################################################################################
PRINT_FN=True
PRINT_FP=True
PRINT_UNK=False
CVG_THRESH=25
PVG_THRESH=60
NUM_PROCS=20

print("Loading VGraph DB...")
vgraph_db = load_vgraph_db('data/vgraph_db')
func_list = []
for vg in vgraph_db:
    if vg['func'] not in func_list:
        func_list.append(vg['func'])

# load manual labels
with open('./manual_labels.txt', 'r') as fp:
    manual_labels = fp.readlines()

print("Loading target graphs..")
target_db = load_target_db('data/vuln_patch_graph_db', func_list)
target_db_clean = []
for tg in target_db:
    cve = tg['path'].split('/')[3]
    func = tg['base_name']
    for vg in vgraph_db:
        if vg['cve'] == cve and vg['func'] == func:
            # function has a vgraph, so we will compare
            target_db_clean.append(tg)
            break

print("Calculating ground truth...")
gt = generate_ground_truth(target_db_clean)
#start_time = time.time()
#for thresh_c in [ 0, 20, 40, 60, 80, 100 ]:
#    for thresh_p in [ 0, 20, 40, 60, 80, 100]: 
#        print("thresh_c: %d" % thresh_c)
#        print("thresh_p: %d" % thresh_p)
#        PVG_THRESH = thresh_p
#        CVG_THRESH = thresh_c
#        scores = get_hits(vgraph_db, target_db_clean)
#        eval_vgraph_mods_only(vgraph_db, target_db_clean, gt, manual_labels)

if os.path.exists('evaluate_vgraph_scores.pkl'):
    print("Loading saved results...")
    scores = pkl.load(open('evaluate_vgraph_scores.pkl', 'rb'))
    target_db_clean = pkl.load(open('evaluate_vgraph_target_db.pkl', 'rb'))
else:
    start_time = time.time()
    scores = get_hits(vgraph_db, target_db_clean)
    pkl.dump(scores, open('evaluate_vgraph_scores.pkl', 'wb'))
    pkl.dump(target_db_clean, open('evaluate_vgraph_target_db.pkl', 'wb'))
    end_time = time.time()
    print("Time to generate results: %d" % (end_time - start_time))
#eval_vgraph_mods_only(vgraph_db, target_db_clean, gt, manual_labels)
eval_vgraph(vgraph_db, target_db_clean, gt, manual_labels)


#with open('eval_all_scores.txt','w') as fp:
#    for score in scores:
#        fp.write("%s/%s/%s %s %d %d %d\n" % (score[0], score[1], score[2], score[3], score[4], score[5], score[6]))
