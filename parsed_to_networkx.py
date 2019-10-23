import os
import sys
import csv
import networkx as nx
import pickle as pkl
from src.graph.utils import *


def write_graph(graph, output_dir, func_name):
    graph_path = output_dir + '/' + func_name + '.gpickle'
    triple_path = output_dir + '/' + func_name + '.triples'
    vector_path = output_dir + '/' + func_name + '.vec'

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("Writing graph: %s" % graph_path)
    nx.write_gpickle(graph, graph_path)
    
    trips = tripleize(graph)
    print("Writing triples: %s" % triple_path)
    pkl.dump(trips, open(triple_path, 'wb'))

    vec = vectorize(graph)
    print("Writing vector: %s" % vector_path)
    pkl.dump(vec, open(vector_path, 'wb'))
    
    
def print_usage():
    print("Usage: python parsed_to_networkx.py <directory> <output_dir>")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print_usage()
        exit()
    parsed_nodes_file = sys.argv[1]
    output_dir = sys.argv[2]

    base_dir = parsed_nodes_file[:-len('nodes.csv')]

    parsed_edges_file = base_dir + 'edges.csv'

    print("Nodes: %s" % parsed_nodes_file)
    print("Edges: %s" % parsed_edges_file)
    print("Output: %s" % output_dir)

    graphs = joern_to_networkx(parsed_nodes_file, parsed_edges_file)
    for g in graphs:
        write_graph(g['graph'], output_dir + '/' + base_dir, g['name'])
