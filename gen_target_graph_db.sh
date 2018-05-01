# This script will look through all functions in neo4j and generate the CPG for vuln and patch
MAX_NUM_PROCS=10

mkdir -p target_graph_db
joern-list-funcs > scratchwork.tmp
while read line; do
    name=`echo $line | awk '{print $1}'`
    id=`echo $line | awk '{print $2}'`
    path=`echo $line | awk '{print $3}'`1
    #echo $name
    #echo $id
    #echo $path
    echo "Generating CPG for $name"
    mkdir -p target_graph_db/$path
    python gen_cpg.py $id target_graph_db/$path/$name.gpickle &
    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
        echo "Waiting for jobs to finish..."
        sleep 0.5
    done

done < scratchwork.tmp
rm -f scratchwork.tmp

