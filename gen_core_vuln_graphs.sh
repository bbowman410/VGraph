# This function will find a CPG of patch and vuln function and generate the core graphs and nodes

for repo in `ls vuln_graph_db`; do
    for cve in `ls vuln_graph_db/$repo`; do
        for func in `ls vuln_graph_db/$repo/$cve/vuln | sed 's/.gpickle//'`; do
            python gen_core_vuln_graphs.py $func vuln_graph_db/$repo/$cve/
        done
    done
done
