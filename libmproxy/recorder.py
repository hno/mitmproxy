#!/usr/bin/env python

# Copyright (C) 2010  Henrik Nordstrom <henrik@henriknordstrom.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import hashlib
import utils
import recorder
import proxy
import collections
import string
import Cookie

class Count(collections.defaultdict):
    def __init__(self):
        collections.defaultdict.__init__(self, int)

    def getnext(self,key):
        self[key] = self[key] + 1
        return self[key]

class Recorder:
    """
        A simple record/playback cache
    """
    def __init__(self):
        self.sequence = Count()
	self.cookies = {}

    def filter_request(self, request):
        """
            Filter forwarded requests to enable better recording
        """
        request = request.copy()
        headers = request.headers
        utils.try_del(headers, 'if-modified-since')
        utils.try_del(headers, 'if-none-match')
        return request;

    def path(self, request):
        """
            Create cache file name
        """
        request = self.filter_request(request)
        headers = request.headers
	m = hashlib.sha224()
	m.update(request.method)
	m.update(" ")
	m.update(request.url())
	m.update(" ")
	if headers.has_key("cookie"):
	    cookies = Cookie.SimpleCookie("; ".join(headers["cookie"]))
	    del headers["cookie"]
	    for key, morsel in cookies.iteritems():
		if self.cookies.has_key(key):
		    m.update(key)
		    m.update("=")
		    m.update(morsel.value)
		    m.update(" ")
        req_text = request.assemble()
	m.update(req_text)
        m = m.hexdigest()
        path = (request.host + request.path)[:80].translate(string.maketrans(":/?","__."))+"."+m
        n = self.sequence.getnext(path)
        path = path + "." + str(n)
        return path

    def save_response(self, response):
        """
            Save response for later playback
        """
        request = response.request;
        req_text = request.assemble()
        resp_text = response.assemble()
        path = self.path(request)

        f = open(path+".req", 'w')
        f.write(req_text)
        f.close()
        f = open(path+".resp", 'w')
        f.write(resp_text)
        f.close()

	if response.headers.has_key('set-cookie'):
	    for header in response.headers['set-cookie']:
		key = header.split('=',1)[0]
		self.cookies[key] = True

    def get_response(self, request):
        """
            Retrieve previously saved response saved by save_response
        """
        path = self.path(request)
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
        return proxy.Response(request, code, proto, status, headers, content)
