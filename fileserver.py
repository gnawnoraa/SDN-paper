# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.

import json
from webob import Response
import os
import mimetypes

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication


# REST API
#
############# Configure tap
#
# get root
# GET /
#
# get file
# GET /web/{file}
#

def get_as_uri(G):
    """Export graph as an html png.

    Arguments:
    G -- networkx.Graph -- the graph that will be exported

    Return:
    it returns a string containing the html representation
    """
    #clear the figure, in case another one was already drawn.
    plt.clf()
    #draw the graph on the figure.
    nx.draw(G, nx.fruchterman_reingold_layout(G))
    #save the figure on a stream.
    imgdata = StringIO.StringIO()
    plt.savefig(imgdata, format='png')
    #return to the beginning of the stream.
    imgdata.seek(0)
    #convert to 64 bit representation.
    buf64 = base64.b64encode(imgdata.buf)
    uri = 'data:image/png;base64,' + urllib.quote(buf64)
    #return the html code for the representation.
    return '<img src = "%s"/>' % uri

class WebController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(WebController, self).__init__(req, link, data, **config)
        self.directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui')

    def make_response(self, filename):
        filetype, encoding = mimetypes.guess_type(filename)
        if filetype == None:
            filetype = 'application/octet-stream'
        res = Response(content_type=filetype)
        res.body = open(filename, 'rb').read()
        return res

    def get_root(self, req, **_kwargs):
        return self.get_file(req, None)

    def get_file(self, req, filename, **_kwargs):
        if (filename == "" or filename == None):
            filename = "index.html"
        try:
            filename = os.path.join(self.directory, filename)
            return self.make_response(filename)
        except IOError:
            return Response(status=400)


class WebRestApi(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(WebRestApi, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        mapper.connect('web', '/web/{filename:.*}',
                       controller=WebController, action='get_file',
                       conditions=dict(method=['GET']))

        # mapper.connect('web', '/',
        #                controller=WebController, action='get_root',
        #                conditions=dict(method=['GET']))


