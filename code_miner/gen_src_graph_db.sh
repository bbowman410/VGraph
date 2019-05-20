#!/bin/bash

IN_DIR='src_files'
PARSED_DIR='parsed'
PARSED_DIR_RENAME='src_files_parsed'
OUT_DIR='vuln_patch_graph_db'
JOERN='/mnt/raid0_huge/bbowman/joern_testing/joern/joern-parse'

# Parse src_files
echo "Parsing $IN_DIR"
$JOERN $IN_DIR

# Rename so we know what this dir is
mv $PARSED_DIR $PARSED_DIR_RENAME
echo "Parsed Directory: $PARSED_DIR_RENAME"

# Generating graphs and extracting code
echo "Generating vuln patch graph database..."
python convert_parsed.py `pwd`/src_files $PARSED_DIR_RENAME $OUT_DIR

