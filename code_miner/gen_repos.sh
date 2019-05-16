#!/bin/bash

echo "Checking out all repositories in repos.config"
mkdir -p repos


while read line; do
    name=`echo $line | awk '{print $1}'`
    url=`echo $line | awk '{print $2}'`
    echo $name
    echo $url
    if [ -d "./repos/$name" ]; then
        echo "Repository already checked out...skipping."
        #rm -rf ./repos/$name
        continue
    fi
    mkdir ./repos/$name
    echo "Checking out $name at $url..."
    git clone $url ./repos/$name
done < ./repos.config
