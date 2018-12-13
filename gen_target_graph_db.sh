
MAX_NUM_PROCS=10

mkdir -p target_graph_db

for line in `find parsed/ -name 'nodes.csv'`; do
    name=`echo $line | awk '{print $1}'`
    id=`echo $line | awk '{print $2}'`
    path=`echo $line | awk '{print $3}'`1
    #echo $name
    #echo $id
    #echo $path
    echo "Generating CPG for $name"
    mkdir -p target_graph_db/$path
    python parsed_to_networkx.py $line ./target_graph_db &
    
    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
        echo "Waiting for jobs to finish..."
        sleep 0.5
    done

done 

