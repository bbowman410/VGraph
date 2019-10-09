from difflib import SequenceMatcher
import sys,os
import pickle as pkl

def triplet_match_exact(vg, target_trips):
    
    cvg_overlap = vg['cvg'].intersection(target_trips)
    pvg_overlap = vg['pvg'].intersection(target_trips)
    nvg_overlap = vg['nvg'].intersection(target_trips)

    cvg_score = (len(cvg_overlap)*100)/len(vg['cvg'])
    pvg_score=(len(pvg_overlap)*100/len(vg['pvg']))
    nvg_score=(len(nvg_overlap)*100/len(vg['nvg']))
 
    return cvg_score, pvg_score, nvg_score


def approx_overlap(src_trips, target_trips):
    APPROX_THRESH = .7
    match_score = 0.
    already_matched = []
    completed=0
    for (first, rela, second) in src_trips:
        local_max = 0
        local_match = None
        for (tg_first, tg_rela, tg_second) in target_trips:

            #if (tg_first, tg_rela, tg_second) in already_matched:
            #    continue # bring down to nlogn complexity

            if rela == tg_rela: # same edge type required
                if first == tg_first: # if equal don't do expensive sequence matching
                    score_first = 1.
                else:
                    #score_first = SequenceMatcher(first, tg_first).ratio()
                    score_first=set(first).intersection(set(tg_first))
                    score_first = float(len(score_first))/float((len(set(first).union(set(tg_first)))))
                if second == tg_second:
                    score_second = 1.
                else:
                    #score_second = SequenceMatcher(second, tg_second).ratio()
                    score_second=set(second).intersection(set(tg_second))
                    score_second=float(len(score_second))/float((len(set(second).union(set(tg_second)))))

                # check if they are both over match threshold
                #if score_first > APPROX_THRESH and score_second > APPROX_THRESH:
                score_avg = (score_first + score_second) / 2.
                if score_avg > APPROX_THRESH and score_avg > local_max:
                    local_max = score_avg
                    local_match = (tg_first, tg_rela, tg_second)
  
        if local_match: # Found a match for this src node
            match_score += local_max
            already_matched.append(local_match)
        completed += 1
        if (1.*(len(src_trips)-completed) + match_score)/len(src_trips) < .50:
            # Even if rest of triples found a perfect match, no way to get abouve 50%
            # so we break
            break 

    # at most match_score would be +1 for each trip in src_trips
    return match_score


def triplet_match_approx(vg, target_trips):
    ''' Approximate overlap function using string matching on code '''
    #TODO lets filter on edges first since we require edge types to be same
    # Why is this so slow???
    #cvg_overlap = approx_overlap(vg['cvg'],target_trips)
    #cvg_score = (cvg_overlap*100)/len(vg['cvg'])
    #if(cvg_score > 50):
    cvg_score=0
    pvg_overlap = approx_overlap(vg['pvg'],target_trips)
    pvg_score = (pvg_overlap*100)/len(vg['pvg'])
    nvg_overlap = approx_overlap(vg['nvg'],target_trips)
    nvg_score = (nvg_overlap*100)/len(vg['nvg'])
    #else: # no need to do pvg, nvg
    #    pvg_score = 0
    #    nvg_score = 0

    return cvg_score, pvg_score, nvg_score

if __name__ == "__main__":
    src_dir=sys.argv[1]
    target_dir=sys.argv[2]
    for f in os.listdir(src_dir):
        if f.endswith("_cvg.pkl"):
            print("Loading cvg: ", f)
            cvg=pkl.load(open(src_dir + '/' + f, 'rb'))
        elif f.endswith("_pvg.pkl"):
            print("Loading pvg: ", f)
            pvg=pkl.load(open(src_dir + '/' + f,'rb'))
        elif f.endswith("_nvg.pkl"):
            print("Loading nvg: ", f)
            nvg=pkl.load(open(src_dir + '/' + f,'rb'))

    for f in os.listdir(target_dir):
        if f.endswith("triples"):
            print("Loading target triples: ", f)
            target_trips = pkl.load(open(target_dir + '/' + f,'rb'))
  
    vg={'cvg':cvg,'pvg':pvg,'nvg':nvg} 
    
    print("Performing exact matching...")
    res = triplet_match_exact(vg, target_trips)
    print(res)
    print("Performing approximate matching...")
    res = triplet_match_approx(vg, target_trips)
    print(res)

     
