# This function will find a CPG of patch and vuln function and generate the core graphs and nodes
MAX_NUM_PROCS=20
LOG_FILE='gen_vgraph_db.log'
VULN_PATCH_DB='data/vuln_patch_graph_db'
VGRAPH_DB='data/vgraph_db'

echo "Logging to $LOG_FILE..."

for repo in `ls $VULN_PATCH_DB`; do
    for cve in `ls $VULN_PATCH_DB/$repo`; do
        for hsh in `ls $VULN_PATCH_DB/$repo/$cve/vuln/`; do
            for src_file in `ls $VULN_PATCH_DB/$repo/$cve/vuln/$hsh`; do
                for g in `ls $VULN_PATCH_DB/$repo/$cve/vuln/$hsh/$src_file/graph | grep 'gpickle'`; do
                    func=`echo $g | sed 's/.gpickle//'`
                    if [ ! -f $VULN_PATCH_DB/$repo/$cve/vuln/$hsh/$src_file/graph/${func}.gpickle ]; then
                        echo "Missing vulnerable graph for ${repo} ${cve} ${func}...Skipping" >> $LOG_FILE
                    elif [ ! -f $VULN_PATCH_DB/$repo/$cve/patch/$hsh/$src_file/graph/${func}.gpickle ]; then
                        echo "Missing patched graph for ${repo} ${cve} ${func}...Skipping" >> $LOG_FILE
                    else
                        # Should have everything we need
                        python gen_vgraph.py $VULN_PATCH_DB/$repo/$cve/vuln/$hsh/$src_file/graph/${func}.gpickle $VULN_PATCH_DB/$repo/$cve/patch/$hsh/$src_file/graph/${func}.gpickle $VGRAPH_DB/$repo/$cve/$hsh/$src_file $func >> $LOG_FILE &
                    fi
                    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
                        sleep 0.5
                    done
                done
            done
        done
    done
done

