#!/bin/bash
JOERN='/mnt/raid0_huge/bbowman/joern_testing/joern/joern-parse'
MAX_NUM_PROCS=20
TARGET_GRAPH_DB=`pwd`"/data/target_graph_db"
TARGET_CODE_DIR=$1

mkdir -p $TARGET_GRAPH_DB

echo "Generating CPGs for target directory: $TARGET_CODE_DIR"
$JOERN $TARGET_CODE_DIR

# Rename joern output dir
mv parsed parsed_target

echo "Generating vectors and triples..."
for line in `find parsed_target -name 'nodes.csv'`; do
    name=`echo $line | awk '{print $1}'`
    id=`echo $line | awk '{print $2}'`
    path=`echo $line | awk '{print $3}'`1
    echo "Generating CPG for $name"
    mkdir -p $TARGET_GRAPH_DB/$path
    python parsed_to_networkx.py $line $TARGET_GRAPH_DB &
    
    while [ "`jobs | wc -l`" -gt "$MAX_NUM_PROCS" ]; do
        sleep 0.5
    done

done 

