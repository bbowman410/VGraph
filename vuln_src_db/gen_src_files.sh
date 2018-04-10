# This is the next step in the vulnerability source code database
# This will go through all relevant commit files for each repository
# and inspect further the commit

# We will skip this commit (and in effect this CVE) if:
#   - there are more than one files covered in the commit
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
        git show $c > ../../scratchwork
        cve=`cat ../../scratchwork | grep -o "CVE-[0-9]*-[0-9]*" | head -1`
        file_names=`cat ../../scratchwork | grep "diff --git"`
        num_file_names=`cat ../../scratchwork | grep "diff --git" | wc -l`
        if [ $num_file_names != 1 ]; then
            echo "More than one file modified...skipping for now..."
            continue
        fi

        echo $file_names
        file_name=`echo $file_names | grep -o -m 1 "[a-zA-Z0-9_]*\.c[pp]*" | head -1`
        if [ "$file_name" == "" ]; then
            echo "$file_names: File must not be C/C++ file... Skipping"
            continue
        fi

        function_names=`cat ../../scratchwork | grep "@@" | grep -o "[a-zA-Z0-9_]*(" | sed "s/(//g" | uniq`
        file_ids=`cat ../../scratchwork | grep -o "^index [a-z0-9]*\.\.[a-z0-9]*"`
        vuln_id=`echo $file_ids | awk '{print $2}' | tr '..' ' ' | awk '{print $1}'`
        patch_id=`echo $file_ids | awk '{print $2}' | tr '..' ' ' | awk '{print $2}'`
        echo $cve
        echo $file_name
        echo $file_ids
        echo "Vuln id: $vuln_id"
        echo "Patch id: $patch_id"
        mkdir -p ../../src_files/$codebase/$cve/vuln
        mkdir -p ../../src_files/$codebase/$cve/patch
        git show $vuln_id > ../../src_files/$codebase/$cve/vuln/$file_name
        git show $patch_id > ../../src_files/$codebase/$cve/patch/$file_name
        echo "$function_names" > ../../src_files/$codebase/$cve/funcnames
    done
    cd ../../
done
rm -f scratchwork
