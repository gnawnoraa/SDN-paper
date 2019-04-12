

class State(object):
	def nextState(self):
		raise NotImplementedError()
	def process(self):
		raise NotImplementedError()

class NoCongested(State):
	def process(self):
		print "Enable ECN"

class Congested(State):
	def process(self):
		print "Disable ECN"




class State( object ):
    def transitionRule( self, input ):
        return eval(self.map[input])()

class S1( State ): 
    map = { "input": "S2", "other": "S3" }
    pass # Overrides to state-specific methods

class S2( State ):
    map = { "foo": "S1", "bar": "S2" }

class S3( State ):
    map = { "quux": "S1" }