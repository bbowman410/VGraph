# VGraph: A Robust Vulnerable Code Clone Detection System Using Code Property Triplets

This is the code for our paper published in EuroS&P 2020.  This tool mines GitHub for vulnerable and patched code samples, converts them to code property graphs, and ultimately to our VGraph structure which contains elements from the vulnerable code, patched code, and contextual code, for various vulnerabilities.  

VGraphs can then be used to find new vulnerable code clones with a significant amount of modification from the original.

# Preqrequesties for running the code

VGraph relies on Joern to generate code property graphs.  We were using Joern v. 0.2.5 (really old by now).  If you plan to use a newer version the code may need some tweaking.  We were using the `joern-parse` utility which would skip the neo4j database stuff and just parse the code and generate the CPGs as a text file.  Once you have a suitable version of Joern installed, you need to modify the `mine.sh` file and update the path of the `JOERN` variable to point to the location of `joern-parse`.  

The majority of the code is Python + Bash.  There is a requirements.txt file that can be used to install the required Python packages: `pip install -r requirements.txt`.

# Running the code simple

Most of the code has been streamlined into a couple of scripts:

```#> ./mine.sh```

This will crawl github for the repositories listed in `repos.config`.  It will checkout the various repositories, and then scan through their commits looking for references to CVE numbers.  It will Then download the raw sourcecode associated with those commits, as well as historic versions from both before and after the relevent commits.  Next it will generate the graphs with Joern, and finally convert the Joern graphs to NetworkX format.

The result will be a ton of useful data in the `data` directory.  There will be raw source code in directories indicating what CVE they are associated with, if they are vulnerable or patched to that particular CVE, the commit hashes which created the particular files, and more.  

Next, we will actually build the VGraph database:

```#> ./gen_vgraph_db.sh```

This will scan through the `data` directory and build a VGraph for each vulnerable/patched code sample we extracted from GitHub.  The resulting VGraphs will be placed in the `data` directory in an appropriately named directory.

Also included is an evaluation script: `evaluate_vgraph.py`, which will allow you to see how well the VGraph representation was able to detect and differentiate between the original vulnerable/patched code samples, as well as the historic versions downloaded for testing.  


