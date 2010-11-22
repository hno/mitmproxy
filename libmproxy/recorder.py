#!/usr/bin/env python

# Copyright (C) 2010  Henrik Nordstrom <henrik@henriknordstrom.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# HENRIK NORDSTROM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
# OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Alternatively you may this file under a GPLv3 license as follows:
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
import time
import hashlib
import utils
import recorder
import proxy
import collections
import itertools
import string
import Cookie

def constant_factory(value):
    return itertools.repeat(value).next

class Recorder:
    """
        A simple record/playback cache
    """
    def __init__(self, options):
        self.static = collections.defaultdict(constant_factory(False))
        self.sequence = collections.defaultdict(int)
        self.cookies = {}
        try:
            for cookie in options.cookies:
                self.cookies[cookie] = True
        except AttributeError: pass
        self.verbosity = options.verbose
        self.storedir = options.cache
        self.indexfp = None
        self.load_config("default")

    def load_config(self, name):
        """
            Load configuration settings from name
        """
        try:
            file = name + ".cfg"
            if self.verbosity > 2:
                print >> sys.stderr, "config: " + file
            fp = self.open(file, "r")
        except IOError:
            return
        for line in fp:
            directive, value = line.strip().split(" ", 1)
            if directive == "Cookie:":
                self.cookies[value] = True
            if directive == "Static:":
                self.static[value] = True
        fp.close()

    def filter_request(self, request):
        """
            Filter forwarded requests to enable better recording
        """
        request = request.copy()
        headers = request.headers
        utils.try_del(headers, 'if-modified-since')
        utils.try_del(headers, 'if-none-match')
        return request

    def normalize_request(self, request):
        """
            Filter request to simplify storage matching
        """
        return request

    def open(self, path, mode):
        return open(self.storedir + "/" + path, mode)

    def pathn(self, request):
        """
            Create cache file name and sequence number
        """
        request = self.filter_request(request)
        request = self.normalize_request(request)
        headers = request.headers
	urlkey = (request.host + request.path.split('?',1)[0])[:80].translate(string.maketrans(":/?","__."))
        self.load_config(urlkey)
        if self.static[urlkey]:
	    return urlkey, self.sequence[urlkey]
        urlkey = (request.host + request.path)[:80].translate(string.maketrans(":/?","__."))
        self.load_config(urlkey)
        if self.static[urlkey]:
	    return urlkey, self.sequence[urlkey]
        id = request.method + " " + request.url() + " "
        m = hashlib.sha224(id)
        self.load_config(urlkey+"."+m.hexdigest())
        if headers.has_key("cookie"):
            cookies = Cookie.SimpleCookie("; ".join(headers["cookie"]))
            del headers["cookie"]
            for key, morsel in cookies.iteritems():
                if self.cookies.has_key(key):
                    id = id + key + "=" + morsel.value + " "
        if self.verbosity > 1:
            print >> sys.stderr, "ID: " + id
        m = hashlib.sha224(id)
        path = urlkey+"."+m.hexdigest()
        self.load_config(path)
        if self.static[path]:
	    return path, self.sequence[path]
        req_text = request.assemble()
        m.update(req_text)
        path = urlkey+"."+m.hexdigest()
        self.load_config(path)
	n = self.sequence[path]
        n = str(n)
        self.load_config(path+"."+n)
        if self.verbosity > 1:
            print >> sys.stderr, "PATH: " + path + "." + n
        return path, n

    def filter_response(self, response):
        if response.headers.has_key('set-cookie'):
            for header in response.headers['set-cookie']:
                key = header.split('=',1)[0]
                self.cookies[key] = True
        return response

    def save_response(self, response):
        """
            Save response for later playback
        """

        if self.indexfp is None:
            self.indexfp = self.open("index.txt", "wa")
	    try:
		cfg = self.open("default.cfg", "r")
	    except:
		cfg = self.open("default.cfg", "w")
		for cookie in iter(self.cookies):
		    print >> cfg, "Cookie: " + cookie
            cfg.close()
        request = response.request
        req_text = request.assemble()
        resp_text = response.assemble()
        path, n = self.pathn(request)
	self.sequence[path] += 1

        f = self.open(path+"."+n+".req", 'w')
        f.write(req_text)
        f.close()
        f = self.open(path+"."+n+".resp", 'w')
        f.write(resp_text)
        f.close()

        print >> self.indexfp , time.time(), request.method, request.path
        if request.headers.has_key('referer'):
            print >> self.indexfp, 'referer:', ','.join(request.headers[referer])
        if len(self.cookies) > 0:
            print >> self.indexfp, 'cookies:', ','.join(self.cookies)
        print >> self.indexfp , path
        print >> self.indexfp , ""


    def get_response(self, request):
        """
            Retrieve previously saved response saved by save_response
        """
        path, n = self.pathn(request)
	fp = self.open(path+"."+n+".resp", 'r')
	if not self.static[path]:
	    if not self.static[path+"."+n]:
		self.sequence[path]+=1
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
        response = proxy.Response(request, code, proto, status, headers, content)
	response.cached = True
	return response
