#!/bin/bash

echo "Checking out all repositories in repos.config"
mkdir -p repos


while read line; do
    echo "Checking out $line"
    name=`echo $line | awk '{print $1}'`
    url=`echo $line | awk '{print $2}'`
    echo $name
    echo $url
    if [ -d "./repos/$name" ]; then
        echo "Removing previous checkout..."
        rm -rf ./repos/$name
    fi
    mkdir ./repos/$name
    echo "Checking out $name at $url..."
    git clone $url ./repos/$name
done < ./repos.config
