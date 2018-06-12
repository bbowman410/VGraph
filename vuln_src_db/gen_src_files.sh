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

mkdir -p src_files
for commit_file in `ls commits`; do
    echo "Generating src files for commit file: $commit_file"
    commits=`cat commits/$commit_file`
    codebase=`echo $commit_file | awk -F'.' '{print $1}'`
    cd repos/$codebase/
    for c in $commits; do
        echo "Processing commit $c"
        git show $c > ../../scratchwork
        cve=`cat ../../scratchwork | grep -o "CVE-[0-9]*-[0-9]*" | head -1`
        num_files_covered=`grep "^diff --git" ../../scratchwork | wc -l`
        if [ $num_files_covered -gt 5 ] || [ $num_files_covered -eq 0 ]; then
            echo "This commit covers $num_files_covered files...skipping it."
            continue
        fi

        curr_file=""
        curr_funcs=""
        curr_vuln_id=""
        curr_patch_id=""

        while read line; do

            # consume each line of the Github commit.
            # commits will follow this structure:
            # (1) diff --git a/path/file b/path/file
            # (2) index <hash>..<hash> number
            # (3) @@ location $$ function

            # Repeat 3 for each modification in file
            # Repeat 1,2 for each file in commit
            if [ "`echo $line | grep "^diff --git"`" != "" ]; then
                echo "Found diff git line: $line"
                if [ "$curr_file" != "" ] && [ "$curr_funcs" != "" ]; then
                    # signals the end of previous file
                    # we need to write results
                    echo "$cve"
                    echo "$codebase"
                    echo "Writing results for $curr_file"
                    echo "Writing results for $curr_funcs"
                    echo "Writing vuln id: $curr_vuln_id"
                    echo "Writing patch id: $curr_patch_id"
                    mkdir -p ../../src_files/$codebase/$cve/vuln
                    mkdir -p ../../src_files/$codebase/$cve/patch
                    git show $curr_vuln_id > ../../src_files/$codebase/$cve/vuln/$curr_file
                    git show $curr_patch_id > ../../src_files/$codebase/$cve/patch/$curr_file
                    echo "$curr_funcs" | tr ' ' '\n' | uniq > ../../src_files/$codebase/$cve/funcnames
                fi
                # Set new filename.  If its not a C/C++ file then curr_file will be blank and no processing will occur
                curr_file=`echo $line | grep -o -m 1 "[a-zA-Z0-9_]*\.c[pp]*" | uniq`
                curr_funcs=""
                curr_vuln_id=""
                curr_patch_id=""
            elif [ "$curr_file" != "" ] && [ "`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*"`" != "" ]; then
                echo "Found index line: $line"
                curr_vuln_id=`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*" | awk '{print $2}' | tr '..' ' ' | awk '{print $1}'`
                curr_patch_id=`echo $line | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*" | awk '{print $2}' | tr '..' ' ' | awk '{print $2}'`
                echo $curr_vuln_id
                echo $curr_patch_id
            elif [ "$curr_file" != "" ] && [ "`echo $line | grep "@@" | grep -o "[a-zA-Z0-9_]*(" | sed "s/(//g" | uniq`" != "" ]; then
                func_name="`echo $line | grep "@@" | grep -o "[a-zA-Z0-9_]*(" | sed "s/(//g" | uniq`"
                curr_funcs="${curr_funcs}${func_name} "
                echo "Found function names: $func_name"
            else
                #echo "Skipping line: $line"
                continue
            fi
        done < <(cat ../../scratchwork)

        if [ "$curr_file" != "" ] && [ "$curr_funcs" != "" ] && [ "$curr_vuln_id" != "" ] && [ "$curr_patch_id" != "" ]; then
            echo "Writing results for $curr_file"
            echo "$cve"
            echo "$codebase"
            echo "Writing results for $curr_funcs"
            echo "Writing vuln id: $curr_vuln_id"
            echo "Writing patch id: $curr_patch_id"
            mkdir -p ../../src_files/$codebase/$cve/vuln
            mkdir -p ../../src_files/$codebase/$cve/patch
            git show $curr_vuln_id > ../../src_files/$codebase/$cve/vuln/$curr_file
            git show $curr_patch_id > ../../src_files/$codebase/$cve/patch/$curr_file
            echo "$curr_funcs" | tr ' ' '\n' | uniq > ../../src_files/$codebase/$cve/funcnames
        fi
    done
    cd ../../
done
rm -f scratchwork
