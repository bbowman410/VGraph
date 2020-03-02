import os
import sys
import networkx as nx
import pickle as pkl

from src.graph.utils import tripleize, vectorize


def gen_triplets(V,P):
    '''
    Gen a set of triplets from V,P in form of CODE,RELATIONSHIP,CODE or TYPE,RELA,TYPE if no code
    CVG= { set shared by both }
    PVG = { set contained by V but not P }
    NVG = { set contained by P but not V }
    '''
    V_trips = tripleize(V)
    P_trips = tripleize(P)

    print("Num V triplets: %d" % len(V_trips))
    print("Num P triplets: %d" % len(P_trips))

    cvg=V_trips.intersection(P_trips)
    pvg=V_trips.difference(P_trips)
    nvg=P_trips.difference(V_trips)
  
    return cvg, pvg, nvg, V_trips, P_trips



def print_statistics(file_path, v_size, p_size, cvg_size, pvg_size, nvg_size):
    print("%s\t%d\t%d\t%d\t%d\t%d" % (file_path, v_size, p_size,cvg_size, pvg_size, nvg_size))






if __name__ == "__main__":

    if len(sys.argv) != 5:
        print("Usage: python gen_vgraph.py <vuln_graph> <patch_graph> <output_path> <output_name>")
        exit()

    # Read inputs
    vuln_graph = sys.argv[1]
    patch_graph = sys.argv[2]
    output_path = sys.argv[3]
    output_name= sys.argv[4]

    # vgraph ID
    vuln_function = output_path + '/' + output_name

    # Graph Outputs
    pvg_output_file = output_path + '/' + output_name  + "_pvg.pkl"
    nvg_output_file = output_path + '/' + output_name + "_nvg.pkl"
    cvg_output_file = output_path + '/' + output_name + "_cvg.pkl"
    v_output_file = output_path + '/' + output_name + "_v.pkl"
    p_output_file = output_path + '/' + output_name + "_p.pkl"
    # Vector Output
    vec_output_file = output_path + '/' + output_name + "_vec.pkl"

    # Read in the vulnerable and patched graphs
    V = nx.read_gpickle(vuln_graph)
    P = nx.read_gpickle(patch_graph)
    print("V size: %d" % len(V.nodes))
    print("P size: %d" % len(P.nodes))

    cvg, pvg, nvg, V_trips, P_trips = gen_triplets(V,P)
    vec = vectorize(V)
    # Check here to make sure we generated some meanigful information
    if len(cvg) == 0 or len(pvg) == 0 or len(nvg) == 0:
        print("Error: vGraph critical component empty.  Skipping")
        print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(cvg), len(pvg), len(nvg))
        exit()

    # if we get here were good
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    pkl.dump(cvg, open(cvg_output_file, 'wb'))
    pkl.dump(pvg, open(pvg_output_file, 'wb'))
    pkl.dump(nvg, open(nvg_output_file, 'wb'))
    pkl.dump(V_trips, open(v_output_file, 'wb'))
    pkl.dump(P_trips, open(p_output_file, 'wb'))
    pkl.dump(vec, open(vec_output_file, 'wb'))

    # Print final statistics
    print_statistics(vuln_function, len(V.nodes), len(P.nodes), len(cvg), len(pvg), len(nvg))
