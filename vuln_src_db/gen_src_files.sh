# This is the next step in the vulnerability source code database
# This will go through all relevant commit files for each repository
# and inspect further the commit

# We will skip this commit (and in effect this CVE) if:
#   - there are more than 5 files covered in the commit
#   - The file name modified is not a C/C++ fle

# If we make it past the previous two checks, we will extract
# the ID of the original vulnerable file, and the patched file.
# Then we perform a 'git show <ID>' and direct that to a file
# in the directory structure ./src_files/<repository>/<CVE>/(vuln|patch)/<filename>
# Additionally, we will write all modified functions to a file
# named 'funcnames' in the <CVE> directory as well.  This way
# we know which functions are modified from vuln -> patch.  This helps with
# processing later.

LOG_FILE=`pwd`'/gen_src_files.output'
SCRATCH_FILE=`pwd`'/scratch'
SRC_CODE_DIR=`pwd`'/src_files'
SKIPPED=0
PROCESSED=0

function download_data {
  # Read arguments
  local commit_hash=$1
  local codebase=$2
  local cve=$3
  local path=$4
  local funcs=$5
  local vuln_hash=$6
  local patch_hash=$7
  
  log "Downloading source code for: $cve $codebase $path $funcs $commit_hash"

  # Make any necessary directories
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/vuln
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/patch
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/before
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/after

  # Download data from github.  save function names
  git show $curr_vuln_id > $SRC_CODE_DIR/$codebase/$cve/vuln/$curr_file
  git show $curr_patch_id > $SRC_CODE_DIR/$codebase/$cve/patch/$curr_file
  echo "$funcs" | tr ' ' '\n' | uniq > $SRC_CODE_DIR/$codebase/$cve/funcnames
  
  # Identify 2 commits before this one.  Write files.
  before_commits=`git log $path | grep "^commit" | grep -B 2 $commit_hash | head -2`
  if [ "$before_commits" != "" ]; then
    for bc in $before_commits; do
      if [ "$bc" != "commit" ]; then
        log "Downloading (addtl before vuln) source code for: $cve $codebase $path $funcs $bc"
        git show $bc:$path > $SRC_CODE_DIR/$codebase/$cve/before/${bc}_${curr_file}
      fi
    done
  fi

  # Identify 2 commits after this one.  Write files.
  after_commits=`git log $path | grep "^commit" | grep -A 2 $commit_hash | tail -2`
  if [ "$after_commits" != "" ]; then
    for ac in $after_commits; do
      if [ "$ac" != "commit" ]; then
        log "Downloading (addtl after patch) source code for: $cve $codebase $path $funcs $ac"
        git show $ac:$path > $SRC_CODE_DIR/$codebase/$cve/after/${ac}_${curr_file}
      fi
    done
  fi
}

# This function is called after the git show command is called
# and the output is written to SCRATCH_FILE
# This function is responsible for actually parsing the file lines
# and downloading the relevant source code
function process_commit_lines {
  local commit_hash=$1
  local codebase=$2
  local cve=$3

  local curr_file=""
  local curr_funcs=""
  local curr_vuln_id=""
  local curr_patch_id=""
  local path=""

  while read line; do
    if [ "`echo $line | grep "^diff --git"`" != "" ]; then
      log "Found diff line: $line"
      if [ "$curr_file" != "" ] && [ "$curr_funcs" != "" ]; then
        download_data $commit_hash $codebase $cve $path $curr_funcs $curr_vuln_id $curr_patch_id
      fi
      # Set new filename.  If its not C/C++ file then curr_filew ill be blank
      local curr_file=`echo $line | grep -o -m 1 "[a-zA-Z0-9_]*\.c[pp]*" | uniq`
      local path=`echo $line | grep -o -m 1 "a\/[\/a-zA-Z0-9_-]*\.c[pp]*" | uniq`
      local path=${path:2} # remove the 'a/' from front
      local curr_funcs=""
      local curr_vuln_id=""
      local curr_patch_id=""
      if [ "$curr_file" != "" ]; then
        log "Parsing modification to file: $curr_file"
      fi
    elif [ "$curr_file" != "" ] && [ "`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*"`" != "" ]; then
      log "Found index line: $line"
      local curr_vuln_id=`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*" | awk '{print $2}' | tr '..' ' ' | awk '{print $1}'`
      local curr_patch_id=`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*" | awk '{print $2}' | tr '..' ' ' | awk '{print $2}'`
    elif [ "$curr_file" != "" ] && [ "$curr_vuln_id" != "" ] && [ "$curr_patch_id" != "" ] && [ "`echo $line | grep "@@" | grep -o "[a-zA-Z0-9_]*(" | sed "s/(//g" | uniq`" != "" ]; then
      log "Found function line: $line"
      local func_name="`echo $line | grep "@@" | grep -o "[a-zA-Z0-9_]*(" | sed "s/(//g" | tail -1`" # only get the last occurence in case there are some weird return types
      local curr_funcs="${curr_funcs}${func_name} " # keep track of all
    else
      # Nothing important on this line.. skip it
      continue
    fi
  done < <(cat $SCRATCH_FILE)
  
  # We still may need to write out a file
  if [ "$curr_file" != "" ] && [ "$curr_funcs" != "" ] && [ "$curr_vuln_id" != "" ] && [ "$curr_patch_id" != "" ]; then
    download_data $commit_hash $codebase $cve $path $curr_funcs $curr_vuln_id $curr_patch_id
  fi
}

function process_commit {
  local commit=$1
  local codebase=$2
  log "Processing commit: $codebase $commit"
  git show $commit > $SCRATCH_FILE 
  local cve=`cat $SCRATCH_FILE | grep -o "CVE-[0-9]*-[0-9]*" | head -1`
  local num_files_covered=`grep "^diff --git" $SCRATCH_FILE | wc -l`
  if [ $num_files_covered -gt 5 ] || [ $num_files_covered -eq 0 ]; then
    log "ERROR: This commit covers $num_files_covered files. Skipping it."
    let SKIPPED=$SKIPPED+1
  else
    process_commit_lines $commit $codebase $cve
  fi
  rm $SCRATCH_FILE
}

function process_commit_file {
  local commit_file=$1
  local commits=`cat commits/$commit_file`
  local codebase=`echo $commit_file | awk -F'.' '{print $1}'`
  
  log "Processing commit file: $commit_file"
 
  cd repos/$codebase # We have to change directory to use git commands
  for c in $commits; do
    process_commit $c $codebase
  done
  cd ../../
}

function log {
  echo "$1" >> $LOG_FILE
}

function main {
  mkdir -p src_files
  cat /dev/null > $LOG_FILE # Reset log  

  echo "Logging to $LOG_FILE..."

  for commit_file in `ls commits`; do
    process_commit_file $commit_file
  done
  log "Finished.  Processed $PROCESSED, Skipped $SKIPPED"
}

main
