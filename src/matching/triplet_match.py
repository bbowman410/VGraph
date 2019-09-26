from difflib import SequenceMatcher

def triplet_match_exact(vg, target_trips):
    
    cvg_overlap = vg['cvg'].intersection(target_trips)
    pvg_overlap = vg['pvg'].intersection(target_trips)
    nvg_overlap = vg['nvg'].intersection(target_trips)

    cvg_score = (len(cvg_overlap)*100)/len(vg['cvg'])
    pvg_score=(len(pvg_overlap)*100/len(vg['pvg']))
    nvg_score=(len(nvg_overlap)*100/len(vg['nvg']))
 
    return cvg_score, pvg_score, nvg_score


def approx_overlap(src_trips, target_trips):
    APPROX_THRESH = .5
    match_score = 0.
    already_matched = []
    for (first, rela, second) in src_trips:
        local_max = 0.
        local_match = None
        for (tg_first, tg_rela, tg_second) in target_trips:

            if (tg_first, tg_rela, tg_second) in already_matched:
                continue # bring down to nlogn complexity

            if rela == tg_rela: # same edge type required
                if first == tg_first: # if equal don't do expensive sequence matching
                    score_first = 1.
                else:
                    score_first = SequenceMatcher(first, tg_first).ratio()
                if second == tg_second:
                    score_second = 1.
                else:
                    score_second = SequenceMatcher(second, tg_second).ratio()

                # check if they are both over match threshold
                if score_first > APPROX_THRESH and score_second > APPROX_THRESH:
                    score_avg = (score_first + score_second) / 2.
                    if score_avg > local_max:
                        local_max = score_avg
                        local_match = (tg_first, tg_rela, tg_second)

        match_score += local_max
        if local_match:
            already_matched.append(local_match)

    return match_score


def triplet_match_approx(vg, target_trips):
    ''' Approximate overlap function using string matching on code '''
    cvg_overlap = approx_overlap(vg['cvg'],target_trips)
    pvg_overlap = approx_overlap(vg['pvg'],target_trips)
    nvg_overlap = approx_overlap(vg['nvg'],target_trips)

    cvg_score = (cvg_overlap*100)/len(vg['cvg'])
    pvg_score = (pvg_overlap*100)/len(vg['pvg'])
    nvg_score = (nvg_overlap*100)/len(vg['nvg'])

    return cvg_score, pvg_score, nvg_score

