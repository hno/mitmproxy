import sys
import controller
import hashlib
import utils

class Count(dict):
    def __init__(self):
	dict.__init__(self)

    def __missing__(self, key):
	return 0

class RecordMaster(controller.Master):
    """
        A simple master that just records to files.
    """
    def __init__(self, server, verbosity):
	self.sequence = Count()
        self.verbosity = verbosity
        controller.Master.__init__(self, server)

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, msg):
	request = msg
	headers = request.headers
	utils.try_del(headers, 'if-modified-since')
	utils.try_del(headers, 'if-none-match')
	msg.ack()

    def handle_response(self, msg):
	print >> sys.stderr, ">>",
	print >> sys.stderr, msg.request.short()
	print >> sys.stderr, "<<",
	print >> sys.stderr, msg.short()
	req_text = msg.request.assemble()
	resp_text = msg.assemble()
	m = hashlib.sha224(req_text).hexdigest()
	path = (msg.request.host + msg.request.path)[:60].replace("/","_")+"."+m
	n = self.sequence[path]
	self.sequence[path] = n + 1
	path = path + "." + str(n)
	f = open(path+".req", 'w')
	f.write(req_text)
	f.close()
	f = open(path+".resp", 'w')
	f.write(resp_text)
	f.close()
        msg.ack()
