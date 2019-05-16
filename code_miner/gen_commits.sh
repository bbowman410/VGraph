# This is the first step to build the vulnerability source code database
# This will grep through the commit logs for all repositories in 'repos'
# looking for GREP_STRING (user define).

# If GREP_STRING is found, the commit hash value is stored in a file
# in the commits repo

echo "Generating relevant commit files for all repositories in the 'repos' directory..."

GREP_STRING='CVE-20'

mkdir -p commits
for d in `ls repos`; do
    echo "$d"
    cd ./repos/$d
    git log --no-merges --grep=$GREP_STRING | grep "^commit" | awk '{print $2}' > ../../commits/$d.commits
    cd ../../
done
