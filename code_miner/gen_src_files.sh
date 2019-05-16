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
  
  log "Downloading source code: $cve $codebase $path $funcs $commit_hash"

  # Make any necessary directories
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/vuln/$commit_hash
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/patch/$commit_hash
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/before
  mkdir -p $SRC_CODE_DIR/$codebase/$cve/after

  # Download vulnerable file and patched file.
  git show $vuln_hash > $SRC_CODE_DIR/$codebase/$cve/vuln/$commit_hash/$curr_file
  git show $patch_hash > $SRC_CODE_DIR/$codebase/$cve/patch/$commit_hash/$curr_file

  # Save function names so we know which functions to parse out
  echo "$funcs" | tr '|' '\n' | sed '/^$/d' | sort | uniq > $SRC_CODE_DIR/$codebase/$cve/funcnames

  # Get linux epoch time of commit
  timestamp=`git log -1 --pretty=format:"%ct" $commit_hash`
  # Compute cutoff times
  let timestamp_1mo_before=$timestamp-2592000
  let timestamp_6mo_before=$timestamp-15552000
  let timestamp_1mo_after=$timestamp+2592000
  let timestamp_6mo_after=$timestamp+15552000

  # Evaluation Dataset:
  # commits BEFORE current commit will be labeled as VULNERABLE to this CVE
  # commits AFTER current commit will be labeled as PATCHED to this CVE

  # rev-list provides revision  history to a certain path

  # Immediately before
  before_commit=`git rev-list $commit_hash $path | head -2 | grep -v $commit_hash`
  echo "before commit: $before_commit"
  # 1 month before
  before_commit_1mo=`git rev-list --min-age=$timestamp_1mo_before $commit_hash $path | head -1`
  echo "before commit 1mo: $before_commit_1mo"
  # 6 month before
  before_commit_6mo=`git rev-list --min-age=$timestamp_6mo_before $commit_hash $path | head -1`
  echo "before commit 6mo: $before_commit_6mo"

  # Immediately after
  after_commit=`git rev-list --ancestry-path ${commit_hash}..HEAD $path | tail -1`
  echo "after commit: $after_commit"
  # 1 month after.  This is sorta silly.  2 steps to get this...better than walking the
  # whole tree i suppose
  # this gets the NEWEST commit that is still OLDER than time cutoff.
  echo "git rev-list --ancestry-path --before=$timestamp_1mo_after ${commit_hash}..HEAD $path | head -1"
  tmp_hash=`git rev-list --ancestry-path --before=$timestamp_1mo_after ${commit_hash}..HEAD $path | head -1`
  if [ "$tmp_hash" == "" ]; then
    # if tmp_hash is empty, than all commits are after this date.. so just grab the next one
    # don't forget to remove the $after_commit we just harvested
    after_commit_1mo=`git rev-list --ancestry-path ${commit_hash}..HEAD $path | grep -v $after_commit | tail -1`
  else
    # otherwise use the tmp hash 
    after_commit_1mo=`git rev-list --ancestry-path ${tmp_hash}..HEAD $path | tail -1`
  fi

  echo "after commit 1mo: $after_commit_1mo"

  # same thing for 6 months...
  tmp_hash=`git rev-list --ancestry-path --before=$timestamp_6mo_after ${commit_hash}..HEAD $path | head -1`
  if [ "$tmp_hash" == "" ]; then
    after_commit_6mo=`git rev-list --ancestry-path ${commit_hash}..HEAD $path | grep -v $after_commit | grep -v $after_commit_1mo | tail -1`
  else
    # otherwise use the tmp hash 
    after_commit_6mo=`git rev-list --ancestry-path ${tmp_hash}..HEAD $path | tail -1`
  fi

  echo "after commit 6mo: $after_commit_6mo"

  # If we identified any before or after commits, we download them
  # Before commits
  if [ "$before_commit" != "" ]; then
    log "Downloading commit immediately before patch: $cve $codebase $path $funcs $before_commit"
    mkdir -p $SRC_CODE_DIR/$codebase/$cve/before/imm/$before_commit
    git show $before_commit:$path > $SRC_CODE_DIR/$codebase/$cve/before/imm/${before_commit}/${curr_file}
  fi

  if [ "$before_commit_1mo" != "" ]; then
    log "Downloading commit 1 month before patch: $cve $codebase $path $funcs $before_commit_1mo"
    mkdir -p $SRC_CODE_DIR/$codebase/$cve/before/1mo/$before_commit_1mo
    git show $before_commit_1mo:$path > $SRC_CODE_DIR/$codebase/$cve/before/1mo/${before_commit_1mo}/${curr_file}
  fi

  if [ "$before_commit_6mo" != "" ]; then
     log "Downloading commit 6 month before patch: $cve $codebase $path $funcs $before_commit_6mo"
     mkdir -p $SRC_CODE_DIR/$codebase/$cve/before/6mo/$before_commit_6mo
     git show $before_commit_6mo:$path > $SRC_CODE_DIR/$codebase/$cve/before/6mo/${before_commit_6mo}/${curr_file}
  fi
  # After Commits
  if [ "$after_commit" != "" ]; then
    log "Downloading commit immediately after patch: $cve $codebase $path $funcs $after_commit"
    mkdir -p $SRC_CODE_DIR/$codebase/$cve/after/imm/$after_commit
    git show $after_commit:$path > $SRC_CODE_DIR/$codebase/$cve/after/imm/${after_commit}/${curr_file}
  fi

  if [ "$after_commit_1mo" != "" ]; then
    log "Downloading commit 1 month after patch: $cve $codebase $path $funcs $after_commit_1mo"
    mkdir -p $SRC_CODE_DIR/$codebase/$cve/after/1mo/$after_commit_1mo
    git show $after_commit_1mo:$path > $SRC_CODE_DIR/$codebase/$cve/after/1mo/${after_commit_1mo}/${curr_file}
  fi

  if [ "$after_commit_6mo" != "" ]; then
     log "Downloading commit 6 month after patch: $cve $codebase $path $funcs $after_commit_6mo"
     mkdir -p $SRC_CODE_DIR/$codebase/$cve/after/6mo/$after_commit_6mo
     git show $before_commit_6mo:$path > $SRC_CODE_DIR/$codebase/$cve/before/6mo/${before_commit_6mo}/${curr_file}
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
      local curr_funcs="${curr_funcs}|${func_name}" # keep track of all
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
  local cve=`cat $SCRATCH_FILE | grep -o "CVE-[0-9]*-[0-9]*" | head -1` # Just get first reference to a CVE
  local num_files_covered=`grep "^diff --git" $SCRATCH_FILE | wc -l`
  if [ $num_files_covered -gt 5 ] || [ $num_files_covered -eq 0 ]; then
    log "ERROR: This commit covers $num_files_covered files. Skipping it." # Probably a merge
    let SKIPPED=$SKIPPED+1
  elif [ -d $SRC_CODE_DIR/$codebase/$cve ]; then
    log "ERROR: This CVE already covered by previous commit.  Skipping." # Probaly should change this...
    let SKIPPED=$SKIPPED+1
  else
    process_commit_lines $commit $codebase $cve
    let PROCESSED=$PROCESSED+1
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
