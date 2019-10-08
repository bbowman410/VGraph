import os
import sys
import csv
import networkx as nx
import pickle as pkl

from src.graph.utils import joern_to_networkx, tripleize, vectorize


def write_graph(graph, base_dir, repo, cve, v_or_p, file_name, func_name):
    path = "%s/%s/%s/%s/%s/graph" % (base_dir, repo, cve, v_or_p, file_name)
    name = "%s.gpickle" % func_name
    if not os.path.exists(path):
        os.makedirs(path)
    nx.write_gpickle(graph, path + '/' + name)

    trips = tripleize(graph)
    pkl.dump(trips, open(path + '/' + func_name + '.triples', 'wb'))

    vec = vectorize(graph)
    pkl.dump(vec, open(path + '/' + func_name + '.vec', 'wb'))

def write_code(char_buf, base_dir, repo, cve, v_or_p, file_name, func_name):
    path = "%s/%s/%s/%s/%s/code" % (base_dir, repo, cve, v_or_p, file_name)
    name = "%s.%s" % (func_name, file_name.split('.')[-1]) # same extension as original file
    if not os.path.exists(path):
        os.makedirs(path)
    with open(path + '/' + name, 'w') as f:
        for c in char_buf:
            f.write(c)

def extract_func(from_file, to_file, location):
    buf_start = int(location.split(':')[2])
    buf_end = int(location.split(':')[3])
    with open(from_file, 'r') as f:
        char_list = list(f.read())
        return char_list[buf_start:buf_end+1]
        

vuln_code_dir=sys.argv[1] # location of source code files
parsed_dir=sys.argv[2] # Location of Joern parsed data
output_dir=sys.argv[3] # Location to write our final database containing code, graphs

# For every code repository...
for repo in os.listdir(vuln_code_dir):
    # For every CVE...
    for cve in os.listdir(vuln_code_dir + '/' + repo):
        # Inside here we have funcname, vuln, patch, before, after

        # Get names of functions of interest
        function_names = []
        try:
            with open(vuln_code_dir + '/' + repo + '/' + cve + '/funcnames') as fp:
                for f_name in fp.readlines():
                    f_name = f_name.rstrip()
                    if f_name:
                        function_names.append(f_name) 
        except:
            # Error opening function names file.  Skip
            print("Error opening funcnames file for %s/%s...Skipping" % (repo, cve))
            continue

        # Get list of vuln files 
        vuln_file_names = []
        for h in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/vuln/'):
            for f in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/vuln/' + h): 
                vuln_file_names.append('%s/%s' % (h,f))
      
        # Get list of patch files
        patch_file_names = []
        for h in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/patch/'): 
            for f in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/patch/' + h): 
                patch_file_names.append('%s/%s' % (h,f))

        # Must have been an error generating these files.  Skip.
        if len(vuln_file_names) == 0 or len(patch_file_names) == 0:
            print("Missing vulnerable or patched files for %s/%s...Skipping" % (repo, cve))
            continue

        # Get list of before patch files (also vuln)
        before_file_names = []
        for h in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/before/'):
            for f in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/before/'+h+'/'): 
                before_file_names.append('%s/%s' % (h,f))
        
        # Get list of after patch files (also patched)
        after_file_names = []
        for h in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/after/'):
            for f in os.listdir(vuln_code_dir + '/' + repo + '/' + cve + '/after/'+h+'/'): 
                after_file_names.append('%s/%s' % (h,f))

        # Now need to:
        #  1)  Find those functions in parsed directory
        #  2)  Build Networkx graph from .csv files
        #  3)  Extract source code of specific functions from orig source code
   
        for (f_names, d) in [(vuln_file_names, 'vuln'),
                (patch_file_names, 'patch'),
                (before_file_names, 'before'),
                (after_file_names, 'after')]:
            for f in f_names:
                parsed_file_nodes = "%s/%s/%s/%s/%s/%s/nodes.csv" % (parsed_dir,vuln_code_dir,repo,cve,d,f)
                parsed_file_edges = "%s/%s/%s/%s/%s/%s/edges.csv" % (parsed_dir,vuln_code_dir,repo,cve,d,f)
                graphs = joern_to_networkx(parsed_file_nodes, parsed_file_edges, func_names=function_names)
                # Now need to write out data
                for g in graphs:
                    write_graph(g['graph'], output_dir, repo, cve, d, f, g['name'])
                    just_the_func = extract_func("%s/%s/%s/%s/%s" % (vuln_code_dir,repo,cve,d,f), 'to_file', g['location'])
                    write_code(just_the_func, output_dir, repo, cve, d, f, g['name'])

            

