# This function will find a CPG of patch and vuln function and generate the core graphs and nodes
MAX_NUM_PROCS=20
LOG_FILE='gen_core_vuln_graphs.log'

for repo in `ls vuln_src_db/vuln_patch_graph_db`; do
    for cve in `ls vuln_src_db/vuln_patch_graph_db/$repo`; do
        for h in `ls vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln`; do
            for src_file in `ls vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln/$h`; do
                for func in `ls vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln/$h/$src_file/graph | sed 's/.gpickle//'`; do
                    if [ -f vgraph_db/$repo/$cve/$h/$src_file/${func}_pvg.gpickle ]; then
                        echo "CVG already generated for $func...Skipping"
                    else
                        python gen_core_vuln_graphs.py vuln_src_db/vuln_patch_graph_db/$repo/$cve/vuln/$h/$src_file/graph/${func}.gpickle vuln_src_db/vuln_patch_graph_db/$repo/$cve/patch/$h/$src_file/graph/${func}.gpickle vgraph_db/$repo/$cve/$h/$src_file $func >> $LOG_FILE &

                    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
                        sleep 0.5
                    done
                    fi
                done
            done
        done
    done
done
