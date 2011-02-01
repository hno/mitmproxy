"""
    A simple proxy server implementation, which always reads all of a server
    response into memory, performs some transformation, and then writes it back
    to the client. 

    Development started from Neil Schemenauer's munchy.py
"""
import sys, os, time, string, socket, urlparse, re, select, copy
import SocketServer, ssl
import utils, controller

NAME = "mitmproxy"
config = None


class ProxyError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg

    def __str__(self):
        return "ProxyError(%s, %s)"%(self.code, self.msg)


class Config:
    def __init__(self, pemfile):
        self.pemfile = pemfile


def read_chunked(fp):
    content = ""
    while 1:
        line = fp.readline()
        if line == "":
            raise IOError("Connection closed")
        if line == '\r\n' or line == '\n':
            continue
        length = int(line,16)
        if not length:
            break
        content += fp.read(length)
        line = fp.readline()
        if line != '\r\n':
            raise IOError("Malformed chunked body")
    while 1:
        line = fp.readline()
        if line == "":
            raise IOError("Connection closed")
        if line == '\r\n' or line == '\n':
            break
    return content
    
def read_http_body(rfile, connection, headers, all):
    if headers.has_key('transfer-encoding'):
        if not ",".join(headers["transfer-encoding"]) == "chunked":
            raise IOError('Invalid transfer-encoding')
        content = read_chunked(rfile)
    elif headers.has_key("content-length"):
        content = rfile.read(int(headers["content-length"][0]))
    elif all:
        content = rfile.read()
        connection.close = True
    else:
        content = None
    return content

def parse_url(url):
    """
        Returns a (scheme, host, port, path) tuple, or None on error.
    """
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    if not scheme:
        return None
    if ':' in netloc:
        host, port = string.split(netloc, ':')
        port = int(port)
    else:
        host = netloc
        port = 80
    path = urlparse.urlunparse(('', '', path, params, query, fragment))
    if not path:
        path = "/"
    return scheme, host, port, path


def parse_request_line(request):
    """
        Parse a proxy request line. Return (method, scheme, host, port, path).
        Raise ProxyError on error.
    """
    try:
        method, url, protocol = string.split(request)
    except ValueError:
        raise ProxyError(400, "Can't parse request")
    if method == 'CONNECT':
        scheme = None
        path = None
        try:
            host, port = url.split(":")
        except ValueError:
            raise ProxyError(400, "Can't parse request")
        port = int(port)
    else:
        if url.startswith("/") or url == "*":
            scheme, port, host, path = None, None, None, url
        else:
            parts = parse_url(url)
            if not parts:
                raise ProxyError(400, "Invalid url: %s"%url)
            scheme, host, port, path = parts
    if not protocol.startswith("HTTP/"):
        raise ProxyError(400, "Unsupported protocol")
    major,minor = protocol.split('/')[1].split('.')
    major = int(major)
    minor = int(minor)
    if major != 1:
        raise ProxyError(400, "Unsupported protocol")
    return method, scheme, host, port, path, minor


class Request(controller.Msg):
    FMT = '%s %s HTTP/1.1\r\n%s\r\n%s'
    FMT_PROXY = '%s %s://%s:%s%s HTTP/1.1\r\n%s\r\n%s'
    def __init__(self, connection, host, port, scheme, method, path, headers, content):
        self.connection = connection
        self.host, self.port, self.scheme = host, port, scheme
        self.method, self.path, self.headers, self.content = method, path, headers, content
        self.kill = False
        self.close = False
        controller.Msg.__init__(self)

    def is_cached(self):
        return False

    def copy(self):
        c = copy.copy(self)
        c.headers = self.headers.copy()
        return c

    def hostport(self):
        if (self.port, self.scheme) in [(80, "http"), (443, "https")]:
            host = self.host
        else:
            host = "%s:%s"%(self.host, self.port)
        return host

    def url(self):
        return "%s://%s%s"%(self.scheme, self.hostport(), self.path)

    def set_url(self, url):
        parts = parse_url(url)
        if not parts:
            return False
        self.scheme, self.host, self.port, self.path = parts
        return True

    def is_response(self):
        return False

    def short(self):
        return "%s %s"%(self.method, self.url())

    def assemble_proxy(self):
        return self.assemble(True)

    def assemble(self, _proxy = False):
        """
            Assembles the request for transmission to the server. We make some
            modifications to make sure interception works properly.
        """
        headers = self.headers.copy()
        utils.try_del(headers, 'accept-encoding')
        utils.try_del(headers, 'proxy-connection')
        utils.try_del(headers, 'keep-alive')
        utils.try_del(headers, 'connection')
        utils.try_del(headers, 'content-length')
        utils.try_del(headers, 'transfer-encoding')
        if not headers.has_key('host'):
            headers["host"] = [self.hostport()]
        content = self.content
        if content is not None:
            headers["content-length"] = [str(len(content))]
        else:
            content = ""
        if self.close:
            headers["connection"] = ["close"]
        if not _proxy:
            return self.FMT % (self.method, self.path, str(headers), content)
        else:
            return self.FMT_PROXY % (self.method, self.scheme, self.host, self.port, self.path, str(headers), content)


class Response(controller.Msg):
    FMT = '%s\r\n%s\r\n%s'
    def __init__(self, request, code, msg, headers, content):
        self.request = request
        self.code, self.msg = code, msg
        self.headers, self.content = headers, content
        self.kill = False
        self.cached = False
        controller.Msg.__init__(self)

    def copy(self):
        c = copy.copy(self)
        c.headers = self.headers.copy()
        return c

    def is_response(self):
        return True

    def is_cached(self):
        return self.cached

    def short(self):
        return "%s %s"%(self.code, self.msg)

    def assemble(self):
        """
            Assembles the response for transmission to the client. We make some
            modifications to make sure interception works properly.
        """
        headers = self.headers.copy()
        utils.try_del(headers, 'accept-encoding')
        utils.try_del(headers, 'proxy-connection')
        utils.try_del(headers, 'connection')
        utils.try_del(headers, 'keep-alive')
        utils.try_del(headers, 'transfer-encoding')
        content = self.content
        if content is not None:
            headers["content-length"] = [str(len(content))]
        else:
            content = ""
        if self.request.connection.close:
            headers["connection"] = ["close"]
        proto = "HTTP/1.1 %s %s"%(self.code, self.msg)
        data = (proto, str(headers), content)
        return self.FMT%data


class BrowserConnection(controller.Msg):
    def __init__(self, address, port):
        self.address, self.port = address, port
        self.close = False
        controller.Msg.__init__(self)

    def copy(self):
        return copy.copy(self)


class Error(controller.Msg):
    def __init__(self, connection, msg):
        self.connection, self.msg = connection, msg
        controller.Msg.__init__(self)

    def copy(self):
        return copy.copy(self)


class FileLike:
    def __init__(self, o):
        self.o = o

    def __getattr__(self, attr):
        return getattr(self.o, attr)

    def flush(self):
        pass

    def read(self, length):
        result = ''
        while len(result) < length:
            data = self.o.read(length)
            if not data:
                break
            result += data
        return result

    def readline(self):
        result = ''
        while True:
            ch = self.read(1)
            if not ch:
                break
            else:
                result += ch
                if ch == '\n':
                    break
        return result


class ServerConnection:
    def __init__(self, request):
        self.host = request.host
        self.port = request.port
        self.scheme = request.scheme
        self.close = False
        self.server, self.rfile, self.wfile = None, None, None
        self.connect()

    def connect(self):
        try:
            addr = socket.gethostbyname(self.host)
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.scheme == "https":
                server = ssl.wrap_socket(server)
            server.connect((addr, self.port))
        except socket.error, err:
            raise ProxyError(504, 'Error connecting to "%s": %s' % (self.host, err))
        self.server = server
        self.rfile, self.wfile = server.makefile('rb'), server.makefile('wb')

    def send_request(self, request):
        self.request = request
        request.close = self.close
        try:
            self.wfile.write(request.assemble())
            self.wfile.flush()
        except socket.error, err:
            raise ProxyError(504, 'Error sending data to "%s": %s' % (request.host, err))

    def read_response(self):
        line = self.rfile.readline()
        if line == "\r\n" or line == "\n": # Possible leftover from previous message
            line = self.rfile.readline()
        parts = line.strip().split(" ", 2)
        if not len(parts) == 3:
            raise ProxyError(502, "Invalid server response.")
        proto, code, msg = parts
        code = int(code)
        headers = utils.Headers()
        headers.read(self.rfile)
        if code >= 100 and code <= 199:
            return self.read_response()
        if self.request.method == "HEAD" or code == 204 or code == 304:
            content = None
        else:
            content = read_http_body(self.rfile, self, headers, True)
        return Response(self.request, code, msg, headers, content)

    def terminate(self):
        try:
            if not self.wfile.closed:
                self.wfile.flush()
            self.server.close()
        except IOError:
            pass


class ProxyHandler(SocketServer.StreamRequestHandler):
    def __init__(self, request, client_address, server, q):
        self.mqueue = q
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        bc = BrowserConnection(*self.client_address)
        bc.send(self.mqueue)
        while not bc.close:
            self.handle_request(bc)
        self.finish()

    def handle_request(self, bc):
        server = None
        try:
            request = self.read_request(bc)
            if request is None:
                bc.close = True
                return
            request = request.send(self.mqueue)
            if request.kill:
                bc.close = True
                return
            if request.is_response():
                response = request
                request = False
                response = response.send(self.mqueue)
            else:
                server = ServerConnection(request)
                server.send_request(request)
                response = server.read_response()
                response = response.send(self.mqueue)
                if response.kill:
                    server.terminate()
            if response.kill:
                bc.close = True
                return
            self.send_response(response)
        except IOError:
            pass
        except ProxyError, e:
            err = Error(bc, e.msg)
            err.send(self.mqueue)
            self.send_error(e.code, e.msg)
        if server:
            server.terminate()

    def read_request(self, connection):
        line = self.rfile.readline()
        if line == "\r\n" or line == "\n": # Possible leftover from previous message
            line = self.rfile.readline()
        if line == "":
            return None
        method, scheme, host, port, path, httpminor = parse_request_line(line)
        if method == "CONNECT":
            # Discard additional headers sent to the proxy. Should I expose
            # these to users?
            while 1:
                d = self.rfile.readline()
                if d == '\r\n' or d == '\n':
                    break
            self.wfile.write('HTTP/1.1 200 Connection established\r\n')
            self.wfile.write('Proxy-agent: %s\r\n'%NAME)
            self.wfile.write('\r\n')
            self.wfile.flush()
            self.connection = ssl.wrap_socket(
                self.connection,
                certfile = config.pemfile,
                keyfile = config.pemfile,
                server_side = True,
                ssl_version = ssl.PROTOCOL_SSLv23,
                do_handshake_on_connect = False
            )
            self.rfile = FileLike(self.connection)
            self.wfile = FileLike(self.connection)
            method, scheme, host, port, path, httpminor = parse_request_line(self.rfile.readline())
            if scheme is None:
                scheme = "https"
        headers = utils.Headers()
        headers.read(self.rfile)
        if host is None and headers.has_key("host"):
            netloc = headers["host"][0]
            if ':' in netloc:
                host, port = string.split(netloc, ':')
                port = int(port)
            else:
                host = netloc
                if scheme == "https":
                    port = 443
                else:
                    port = 80
            port = int(port)
        if host is None:
            raise ProxyError(400, 'Invalid request: %s'%request)
        if headers.has_key('expect'):
            expect = ",".join(headers['expect'])
            if expect == "100-continue" and httpminor >= 1:
                self.wfile.write('HTTP/1.1 100 Continue\r\n')
                self.wfile.write('Proxy-agent: %s\r\n'%NAME)
                self.wfile.write('\r\n')
                del headers['expect']
            else:
                raise ProxyError(417, 'Unmet expect: %s'%expect)
        if httpminor == 0:
            connection.close = True
        if headers.has_key('connection'):
            for value in ",".join(headers['connection']).split(","):
                value = value.strip()
                if value == "close":
                    connection.close = True
                if value == "keep-alive":
                    connection.close = False
        content = read_http_body(self.rfile, connection, headers, False)
        return Request(connection, host, port, scheme, method, path, headers, content)

    def send_response(self, response):
        self.wfile.write(response.assemble())
        self.wfile.flush()

    def terminate(self, connection, wfile, rfile):
        try:
            if not getattr(wfile, "closed", False):
                wfile.flush()
            connection.close()
        except IOError:
            pass

    def finish(self):
        self.terminate(self.connection, self.wfile, self.rfile)

    def send_error(self, code, body):
        import BaseHTTPServer
        response = BaseHTTPServer.BaseHTTPRequestHandler.responses[code][0]
        self.wfile.write("HTTP/1.1 %s %s\r\n" % (code, response))
        self.wfile.write("Server: %s\r\n"%NAME)
        self.wfile.write("Content-type: text/html\r\n")
        self.wfile.write("\r\n")
        self.wfile.write('<html><head>\n<title>%d %s</title>\n</head>\n'
                '<body>\n%s\n</body>\n</html>' % (code, response, body))
        self.wfile.flush()
        self.wfile.close()
        self.rfile.close()


ServerBase = SocketServer.ThreadingTCPServer
ServerBase.daemon_threads = True	# Terminate workers when main thread terminates
class ProxyServer(ServerBase):
    allow_reuse_address = True
    def __init__(self, port):
        self.port = port
        ServerBase.__init__(self, ('', port), ProxyHandler)
        self.masterq = None

    def set_mqueue(self, q):
        self.masterq = q

    def process_request(self, request, client_address):
        return ServerBase.process_request(self, request, client_address)

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, self.masterq)

