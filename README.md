# PAVE

## Vulnerability Database Setup

### Vulnerability Source Code Database Setup
1. See README in vuln_db.  You will be procesing guthub logs for repos checked out in /vuln_db/repos (probably should automate this)

### Joern Database Setup
1. Use Joern to generate the CPG for each vuln+patch sample in vulnerability DB.  Assuming you followd the readme in vuln_src_db, you should run ```joern ./vuln_src_db/src_files```

2. Once completed, you should now have a hidden file named ```.joernIndex``` in your working directory.  Configure neo4j to use this database file and start ```neo4j console```

### Generate Code Property Graph (CPG) in NetworkX format for each function in Neo4j

Next, we suck out the CPG for each vulnerable and patch function in Neo4j and store it in a NetworkX format.

```
./gen_vuln_graph_db.sh

```

### Generate pCVG and nCVG for each vuln/patch pair in our database

Next we will be generating our positive Core Vulnerability Graph (pCVG), and our negative Core Vulnerability Graph (nCVG).  a simple script takes care of this.

```
./gen_core_vuln_graphs.sh
```

## Vulnerability Extrapolation

### Joern Database Setup

We utilize Joern to generate the Code Property Graph (CPG) of all functions in our target source code.

```
joern <source_code_directory>
```

The result of this command will be a hidden file ```.joernIndex``` which will be used with Neo4j.  Point neo4j server to this file and start it with ```neo4j console```.

### Generate Target Graph Database

Now we will utilize Joern and Neo4j to export the CPG of each function into NetworkX format for processing

```
./gen_target_graph_db.sh
```

### Vulnerability Extrapolation

Now, using the TALE approximate graph matching algorithm, we will compare target functions against the pCVG and nCVG in order to identify possible vulnerabilities.

```
./find_matches.py
```
