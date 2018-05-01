# This script will look through all functions in neo4j and generate the CPG for vuln and patch
MAX_NUM_PROCS=10

mkdir -p vuln_graph_db
joern-list-funcs > scratchwork.tmp
while read line; do
    name=`echo $line | awk '{print $1}'`
    id=`echo $line | awk '{print $2}'`
    path=`echo $line | awk '{print $3}' | grep -E -o "/[a-zA-Z0-9_-]+/CVE-[0-9]*-[0-9]*/(patch|vuln)/"`
    #echo $name
    #echo $id
    #echo $path
    if grep -Fxq $name vuln_src_db/src_files/$path/../funcnames; then
        echo "Generating CPG for $name"
        mkdir -p vuln_graph_db/$path/
        python gen_cpg.py $id vuln_graph_db/$path/$name.gpickle &
        while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
            echo "Waiting for jobs to finish..."
            sleep 0.5
        done
    fi

done < scratchwork.tmp
rm -f scratchwork.tmp

