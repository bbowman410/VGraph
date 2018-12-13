# In this script we will:
#   Go through every repo in src_files
#     Go through every cve
#       for every funcname
#         Find the parsed function from parsed files
#             1) note the location from original source code
#             2) Generate graph in NetworkX format
#             3) Extract those functions from source code and put into c file based on functin name
#
# So the final layout of db will be:
# <repo>/<cve>/<vuln/patch>/<src_file>/<graph/code>/<function_name>.<gpickle/c>

import os
import sys
import csv
import networkx as nx

def get_edge_list(edge_file):
    edge_list = {}
    with open(edge_file, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        first_line = True
        for row in csv_reader:
            # Skip first line
            if first_line:
                first_line = False
                continue
            if row[0] not in edge_list:
                edge_list[row[0]] = [ (row[1], row[2]) ]
            else:
                edge_list[row[0]].append((row[1], row[2]))

    return edge_list

        

def get_all_graphs(nodes_file, edge_list): 
    graphs = []
    with open(nodes_file, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        first_line = True
        processing_func = False
        curr_meta = {}
        for row in csv_reader:
            # Skip first line
            if first_line:
                first_line = False
                continue
            if row[2] == "Function":
                if processing_func: # New function so stop previous function processing
                    # add edges
                    for src_n in curr_meta['graph'].nodes():
                        if src_n in edge_list:
                           for (dst_n, e_type) in edge_list[src_n]:
                               curr_meta['graph'].add_edge(src_n,dst_n)
                               curr_meta['graph'][src_n][dst_n]['type'] = e_type
                    graphs.append(curr_meta)
                    processing_func = False
                    curr_meta = {}

                # Found a new function
                # row[4] is function name
                # row[5] is function location in line_num:x:x:x
                # This function is in our funcnames list.  So we want it!
                curr_meta['location'] = row[4]
                curr_meta['graph'] = nx.Graph()
                curr_meta['name'] = row[3]
                processing_func = True
            else:
                # not a function start.  so just see if we processing or not
                if processing_func:
                    curr_meta['graph'].add_node(row[1]) # add node to graph
                    curr_meta['graph'].node[row[1]]['type'] = row[2]
                    curr_meta['graph'].node[row[1]]['code'] = row[3]
                    curr_meta['graph'].node[row[1]]['functionId'] = row[5]
        # end of csv file
        # lets check to make sure we didnt end on a function we were processing
        if processing_func:
            # need to finish off this function
            # add edges
            for src_n in curr_meta['graph'].nodes():
                if src_n in edge_list:
                    for (dst_n, e_type) in edge_list[src_n]:
                        curr_meta['graph'].add_edge(src_n,dst_n)
                        curr_meta['graph'][src_n][dst_n]['type'] = e_type
            graphs.append(curr_meta)
            processing_func = False
    # now we have processed both the nodes.csv and edges.csv for this source code file
    return graphs
                    



def write_graph(graph, output_dir, func_name):
    name = "%s.gpickle" % func_name
    print "Writing graph: %s" % output_dir + '/' + name
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    nx.write_gpickle(graph, output_dir + '/' + name)
    

parsed_nodes_file = sys.argv[1]
output_dir = sys.argv[2]

base_dir = parsed_nodes_file[:-len('nodes.csv')]

parsed_edges_file = base_dir + 'edges.csv'

print "Nodes: %s" % parsed_nodes_file
print "Edges: %s" % parsed_edges_file
print "Output: %s" % output_dir

edge_list = get_edge_list(parsed_edges_file)
graphs = get_all_graphs(parsed_nodes_file, edge_list)
for g in graphs:
    write_graph(g['graph'], output_dir + '/' + base_dir, g['name'])
