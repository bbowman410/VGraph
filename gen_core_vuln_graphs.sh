# This function will find a CPG of patch and vuln function and generate the core graphs and nodes
MAX_NUM_PROCS=10

for repo in `ls vuln_src_db/vuln_patch_graph_db`; do
    for cve in `ls vuln_src_db/vuln_patch_graph_db/$repo`; do
        for src_file in `ls vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln`; do
            for func in `ls vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln/$src_file/graph | sed 's/.gpickle//'`; do
                if [ -f vgraph_db/$repo/$cve/$src_file/${func}_pvg.gpickle ]; then
                    echo "CVG already generated for $func...Skipping"
                else
                    python gen_core_vuln_graphs.py vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln/$src_file/graph/${func}.gpickle vuln_src_db/vuln_patch_graph_db/$repo/$cve/patch/$src_file/graph/${func}.gpickle vgraph_db/$repo/$cve/$src_file $func &

                while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
                    echo "Waiting for jobs to finish..."
                    sleep 0.5
                done
                fi
            done
        done
    done
done
