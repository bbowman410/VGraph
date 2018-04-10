# PAVE
## Vulnerability Source Code Database Setup
1. See README in vuln_db.  You will be procesing guthub logs for repos checked out in /vuln_db/repos (probably should automate this)

## Vulnerability Database Setup
1. Use Joern to generate the CPG for each vuln+patch sample in vulnerability DB
2. Generate +CVG, -CVG (Python NetworkX format) by querying neo4j

## Vulnerability Detection
1. Use joern to generate the CPG for all functions in target program
2. Generate Python NetworkX CPG for every function in program by querying Neo4j
3. Perform matching on vulnerability DB and target functions
