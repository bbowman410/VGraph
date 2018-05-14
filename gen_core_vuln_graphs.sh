# This function will find a CPG of patch and vuln function and generate the core graphs and nodes
MAX_NUM_PROCS=10

for repo in `ls vuln_graph_db`; do
    for cve in `ls vuln_graph_db/$repo`; do
        for func in `ls vuln_graph_db/$repo/$cve/vuln | sed 's/.gpickle//'`; do
            if [ -f vuln_graph_db/$repo/$cve/${func}_pfg.gpickle ]; then
                echo "CVG already generated for $func...Skipping"
            else
                python gen_core_vuln_graphs.py $func vuln_graph_db/$repo/$cve/ &
                while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
                    echo "Waiting for jobs to finish..."
                    sleep 0.5
                done
            fi

        done
    done
done
