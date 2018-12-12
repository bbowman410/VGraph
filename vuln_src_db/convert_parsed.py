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

        

def get_graphs(nodes_file, function_names): 
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
                    #write_graph(curr_meta['graph'], repo, cve, f, curr_meta['name'])
                    graphs.append(curr_meta)
                    processing_func = False
                    curr_meta = {}

                # Found a new function
                # row[4] is function name
                # row[5] is function location in line_num:x:x:x
                if row[3] in function_names:
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
            #write_graph(curr_meta['graph'], repo, cve, f, curr_meta['name'])
            graphs.append(curr_meta)
            processing_func = False
    # now we have processed both the nodes.csv and edges.csv for this source code file
    return graphs
                    



def write_graph(graph, base_dir, repo, cve, v_or_p, file_name, func_name):
    path = "%s/%s/%s/%s/%s/graph" % (base_dir, repo, cve, v_or_p, file_name)
    name = "%s.gpickle" % func_name
    print "Writing graph: %s" % path
    if not os.path.exists(path):
        os.makedirs(path)
    nx.write_gpickle(graph, path + '/' + name)
    

def write_code(char_buf, base_dir, repo, cve, v_or_p, file_name, func_name):
    path = "%s/%s/%s/%s/%s/code" % (base_dir, repo, cve, v_or_p, file_name)
    name = "%s.%s" % (func_name, file_name.split('.')[-1]) # same extension as original file
    print "Writing code: %s" % path
    if not os.path.exists(path):
        os.makedirs(path)
    with open(path + '/' + name, 'w') as f:
        for c in char_buf:
            f.write(c)

def extract_func(from_file, to_file, location):
    print "extrating function from %s to %s at location %s" % (from_file, to_file, location)
    buf_start = int(location.split(':')[2])
    buf_end = int(location.split(':')[3])
    with open(from_file, 'r') as f:
        char_list = list(f.read())
        return char_list[buf_start:buf_end+1]
        #for c in char_list[buf_start:buf_end+1]:
        #    sys.stdout.write(c)
        #sys.stdout.flush()
        #print char_list[buf_start:buf_end + 1]
        #exit()
        

vuln_code_dir = 'src_files'
parsed_dir = 'parsed'
output_dir = 'vuln_patch_graph_db'
parsed_base_dir = 'parsed'


# Determine the base dir for our parsed directory strucure
while True:
    d = os.listdir(parsed_base_dir)[0]
    if d != 'src_files':
        parsed_base_dir += '/' + d
    else:
        parsed_base_dir += '/src_files'
        break


# For every code repository...
for repo in os.listdir(vuln_code_dir):

    # For every CVE...
    for cve in os.listdir(vuln_code_dir + '/' + repo):
        # Inside here we have funcname, vuln, patch

        # Get names of vulnerable / patched functions
        function_names = []
        for f_name in open(vuln_code_dir + '/' + repo + '/' + cve + '/funcnames').readlines():
            f_name = f_name.rstrip()
            if f_name:
                function_names.append(f_name) 

        
        # Get the names of the source code files we will be processing
        file_names = []
        for f in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/vuln/'): # there will be same files in both vuln and patch
            file_names.append(f)

        # OK. so we have the C files.  The functions in those C files that we care about
        # Now need to find those functions in parsed directory, build Networkx graph, and extract source code from orig code


         
        for f in file_names:
            # Vuln file parsing:
            parsed_file_nodes = parsed_base_dir + '/' + repo + '/' + cve + '/vuln/' + f + '/nodes.csv'
            parsed_file_edges = parsed_base_dir + '/' + repo + '/' + cve + '/vuln/' + f + '/edges.csv'
            edge_list = get_edge_list(parsed_file_edges)
            graphs = get_graphs(parsed_file_nodes, function_names)

            # Now we have a list of graphs, as well as their names and locations for this file_name
            # We need to write out these graphs and,
            # We need to extract the function from the original source code (oooo)

            for g in graphs:
                write_graph(g['graph'], output_dir, repo, cve, 'vuln', f, g['name'])
                just_the_func = extract_func(vuln_code_dir + '/' + repo + '/' + cve + '/vuln/' + f, 'to_file', g['location'])
                write_code(just_the_func, output_dir, repo, cve, 'vuln', f, g['name'])

            # Patch file parsing
            parsed_file_nodes = parsed_base_dir + '/' + repo + '/' + cve + '/patch/' + f + '/nodes.csv'
            parsed_file_edges = parsed_base_dir + '/' + repo + '/' + cve + '/patch/' + f + '/edges.csv'
            edge_list = get_edge_list(parsed_file_edges)
            graphs = get_graphs(parsed_file_nodes, function_names)
            for g in graphs:
                write_graph(g['graph'], output_dir, repo, cve, 'patch', f, g['name'])
                just_the_func = extract_func(vuln_code_dir + '/' + repo + '/' + cve + '/patch/' + f, 'to_file', g['location'])
                write_code(just_the_func, output_dir, repo, cve, 'patch', f, g['name'])

