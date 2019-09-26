#!/bin/bash
REPO_DIR=`pwd`"/data/repos"
COMMIT_DIR=`pwd`"/data/commits"
COMMIT_GREP_STRING='CVE-20'
VULN_PATCH_DIR=`pwd`"/data/vuln_patch_src_db"
VULN_PATCH_GRAPH_DIR=`pwd`"/data/vuln_patch_graph_db"
LOG_FILE=`pwd`"/mine.log"
SCRATCH_FILE=`pwd`"/mine.scratch"
JOERN='/mnt/raid0_huge/bbowman/joern_testing/joern/joern-parse'

source src/code/gen_src_files.sh

# Checkout Repositories
echo "Checking out all repositories in repos.config"
mkdir -p $REPO_DIR
while read line; do
    name=`echo $line | awk '{print $1}'`
    url=`echo $line | awk '{print $2}'`
    if [ -d "$REPO_DIR/$name" ]; then
        echo "Repository Exists: $name"
        continue
    fi
    mkdir $REPO_DIR/$name
    echo "Checking our Repository: $name"
    git clone $url $REPO_DIR/$name
done < ./repos.config

# Generate Relevant Commits and download associated src files
echo "Searching for interesting commits"
mkdir -p $COMMIT_DIR
for d in `ls $REPO_DIR`; do
    if [ -f "$COMMIT_DIR/$d.commits" ]; then
        echo "Commits exist: $d"
        continue
    fi
    cd $REPO_DIR/$d # need to change directories to use the git commands
    git log --no-merges --grep=$COMMIT_GREP_STRING | grep "^commit" | awk '{print $2}' > $COMMIT_DIR/$d.commits
    cd - > /dev/null

    echo "Downloading src code for commits"
    mkdir -p $VULN_PATCH_DIR
    # Download code associated with commit
    if [ -f "$COMMIT_DIR/$d.commits" ]; then
        # Found some commits to process
        process_commit_file "$COMMIT_DIR/$d.commits" $REPO_DIR/$d $d
    fi
done

# Use Joern to parse the directory

echo "Parsing $VULN_PATCH_DIR"
#$JOERN $VULN_PATCH_DIR # generates a parsed directory containing our parsed data

# Generating graphs and extracting code
echo "Generating vuln patch graph database..."
python convert_parsed.py $VULN_PATCH_DIR parsed $VULN_PATCH_GRAPH_DIR

