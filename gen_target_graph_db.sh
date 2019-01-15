
MAX_NUM_PROCS=30
PARSED_DIR=$1
OUTPUT_DIR=$2

mkdir -p $OUTPUT_DIR

for line in `find $PARSED_DIR -name 'nodes.csv'`; do
    name=`echo $line | awk '{print $1}'`
    id=`echo $line | awk '{print $2}'`
    path=`echo $line | awk '{print $3}'`1
    #echo $name
    #echo $id
    #echo $path
    echo "Generating CPG for $name"
    mkdir -p $OUTPUT_DIR/$path
    python parsed_to_networkx.py $line ./$OUTPUT_DIR &
    
    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
        echo "Waiting for jobs to finish..."
        sleep 0.5
    done

done 

