# Script for running expermints

import os
import sys
import filecmp
import pickle as pkl
import networkx as nx
import numpy as np
import pickle as pkl
from tqdm import tqdm

from src.graph.utils import tripleize, load_vgraph_db, load_target_db
from src.matching.triplet_match import *

# Thresholds for when a function is flagged
CVG_THRESH=50
PVG_THRESH=50
NVG_THRESH=50

def decision_function(cvg_score, pvg_score, nvg_score):
    return cvg_score > CVG_THRESH and pvg_score > PVG_THRESH and nvg_score < NVG_THRESH

def log(log_p, line):
    log_p.write(line)

def print_usage():
    print("Usage: python find_vulns.py <target_path> <score_file> <hit_file> <config>")
    print("\ttarget_path : Location of target code property graphs")
    print("\tscore_file : file to write all scores for each vGraph and target graph.  Used for Evaluations")
    print("\thit_file : file to write all hits to (funcs that pass threshold)")
    print("\tconfig : [e]xact mathing or [a]pproximate matching")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print_usage()
        exit()

    # Process args
    target_path = sys.argv[1]
    stats_file = sys.argv[2]
    hit_file = sys.argv[3]
    config = sys.argv[4]

    print("Target Path: ", target_path)
    print("Stats File: ", stats_file)
    print("Hit File: ", hit_file)
    print("Config: ", config)

    stats_fp = open(stats_file, 'w')
    hit_fp = open(hit_file, 'w')
   
    print("Loading target db...")
    target_db = load_target_db(target_path)
    print("Found %d target graphs" % len(target_db))

    print("Loading vgraph db...")
    vgraph_db = load_vgraph_db('./data/vgraph_db')
    print("Found %d vgraphs" % len(vgraph_db))

    print("Finding vulns...")
    num_hits = 0
    pbar = tqdm(total=len(target_db)*len(vgraph_db))
    for vg in vgraph_db:
        for tg in target_db:
            t_trips = tg['triples']

            if config == "e": # exact matching  
                cvg_score, pvg_score, nvg_score = triplet_match_exact(vg, t_trips)
            elif config == "a": # approximate matching
                cvg_score, pvg_score, nvg_score = triplet_match_approx(vg, t_trips)

            pbar.update(1)

            # Log all results to stats file
            log(stats_fp, "%s/%s/%s/%s/%s %s %d %d %d\n" % (vg['repo'],vg['cve'],vg['hsh'],vg['file'],vg['func'],tg['path'], cvg_score, pvg_score, nvg_score))

            if decision_function(cvg_score,pvg_score,nvg_score):
                # only log hits to the hits file
                log(hit_fp, "%s/%s/%s/%s/%s %s\n" % (vg['repo'],vg['cve'],vg['hsh'],vg['file'],vg['func'],tg['path']))
                num_hits += 1
    pbar.close()
    print("Done!  Found %d hits!" % num_hits)
