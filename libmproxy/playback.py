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
import controller
import utils
import proxy
import recorder

class RecordMaster(controller.Master):
    """
        A simple master that just records to files.
    """
    def __init__(self, server, verbosity):
        self.store = recorder.Recorder()
        self.verbosity = verbosity
        controller.Master.__init__(self, server)

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, msg):
        request = msg
        try:
            msg.ack(self.store.get_response(request))
        except IOError:
            print >> sys.stderr, ">>",
            print >> sys.stderr, request.short()
            print >> sys.stderr, "<<",
            print >> sys.stderr, "ERROR: No matching response.",
            print >> sys.stderr, ",".join(self.store.cookies)
            print >> sys.stderr, request.assemble()
            msg.kill = True
            msg.ack()

    def handle_response(self, msg):
        request = msg.request
        response = msg
        print >> sys.stderr, ">>",
        print >> sys.stderr, request.short()
        print >> sys.stderr, "<<",
        print >> sys.stderr, response.short()
        msg.ack(self.store.filter_response(msg))
