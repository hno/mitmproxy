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
    def __init__(self, options):
        self.sequence = Count()
        self.cookies = {}
        self.verbosity = options.verbose
        self.storedir = options.cache
        self.indexfp = None

    def filter_request(self, request):
        """
            Filter forwarded requests to enable better recording
        """
        request = request.copy()
        headers = request.headers
        utils.try_del(headers, 'if-modified-since')
        utils.try_del(headers, 'if-none-match')
        return request;

    def open(self, path, mode):
        return open(self.storedir + "/" + path, mode)

    def path(self, request):
        """
            Create cache file name
        """
        request = self.filter_request(request)
        headers = request.headers
        id = request.method + " " + request.url() + " ";
        if headers.has_key("cookie"):
            cookies = Cookie.SimpleCookie("; ".join(headers["cookie"]))
            del headers["cookie"]
            for key, morsel in cookies.iteritems():
                if self.cookies.has_key(key):
                    id = id + key + "=" + morsel.value + " "
        if self.verbosity > 1:
            print >> sys.stderr, "ID: " + id
        m = hashlib.sha224(id)
        req_text = request.assemble()
        m.update(req_text)
        m = m.hexdigest()
        path = (request.host + request.path)[:80].translate(string.maketrans(":/?","__."))+"."+m
        n = self.sequence.getnext(path)
        path = path + "." + str(n)
        if self.verbosity > 1:
            print >> sys.stderr, "PATH: " + path
        return path

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
        request = response.request;
        req_text = request.assemble()
        resp_text = response.assemble()
        path = self.path(request)

        f = self.open(path+".req", 'w')
        f.write(req_text)
        f.close()
        f = self.open(path+".resp", 'w')
        f.write(resp_text)
        f.close()
        if self.indexfp is None:
            self.indexfp = self.open("index.txt", "w")
        print >> self.indexfp , time.time(), request.method, request.path
        if request.headers.has_key('referer'):
            print >> self.indexfd , 'referer:', ','.join(request.headers[referer])
        print >> self.indexfp , path
        print >> self.indexfp , ""


    def get_response(self, request):
        """
            Retrieve previously saved response saved by save_response
        """
        path = self.path(request)
        fp = self.open(path+".resp", 'r')
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
