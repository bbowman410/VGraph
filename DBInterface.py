from joern.all import JoernSteps
import os

JOERN_TOOLS_STEPDIR = os.path.join(os.path.dirname(__file__), 'steps')

class DBInterface:

    def __init__(self):
        self.connectToDatabase()

    def connectToDatabase(self):
        self.j = JoernSteps()
        self.j.addStepsDir(JOERN_TOOLS_STEPDIR)
        self.j.connectToDatabase()

    def runGremlinQuery(self, query):
        return self.j.runGremlinQuery(query)
    def runCypherQuery(self, query):
        return self.j.runCypherQuery(query)

    def chunks(self, ids, chunkSize):
        return self.j.chunks(ids, chunkSize)


