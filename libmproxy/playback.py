import sys
import controller
import hashlib
import utils
import proxy

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
	req_text = request.assemble()
	m = hashlib.sha224(req_text).hexdigest()
	path = (request.host + request.path)[:60].replace("/","_")+"."+m
	n = self.sequence[path]
	self.sequence[path] = n + 1
	path = path + "." + str(n)
	try:
	    fp = open(path+".resp", 'r')
	    proto, code, status = fp.readline().strip().split(" ", 2)
	    code = int(code)
	    headers = utils.Headers()
	    headers.read(fp)
	    utils.try_del(headers, 'transfer-encoding')
	    if request.method == "HEAD":
		content = None
	    else:
		content = proxy.read_http_body(fp, headers, True)
	    fp.close()
	    msg.ack(proxy.Response(request, code, proto, status, headers, content))
	except IOError:
	    print >> sys.stderr, ">>",
	    print >> sys.stderr, request.short()
	    print >> sys.stderr, "<<",
	    print >> sys.stderr, "ERROR: No matching response: " + path
	    print >> sys.stderr, req_text
	    msg.kill = True
	    msg.ack()

    def handle_response(self, msg):
	request = msg.request
	response = msg
	print >> sys.stderr, ">>",
	print >> sys.stderr, request.short()
	print >> sys.stderr, "<<",
	print >> sys.stderr, response.short()
        msg.ack()
