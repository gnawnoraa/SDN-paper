

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import os
import json
from webob.static import DirectoryApp
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import network_monitor

PATH = os.path.dirname(__file__)
BASE_URL = "/traffic/routing"
REQUIREMENTS = {'dpid': dpid_lib.DPID_PATTERN}

class NetworkMonitorController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkMonitorController, self).__init__(req, link, data, **config)
        path = "%s/gui/" % PATH
        self.static_app = DirectoryApp(path)
        self.multipath_app = data['multipath_app']

    @route('multipath', '/gui/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)

    url = BASE_URL + '/flow_loading'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_flow_loading(self, req, **kwargs):
        multipath_app = self.multipath_app
        body = json.dumps(multipath_app.network_monitor.get_flow_loading())
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/path_table'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_path_table(self, req, **kwargs):
        multipath_app = self.multipath_app
        body = json.dumps(multipath_app.get_all_path_load())
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/link_loading'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_link_loading(self, req, **kwargs):
        network_monitor = self.multipath_app.network_monitor
        body = json.dumps(network_monitor.get_all_link_loading())
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/path_load_test'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_path_load(self, req, **kwargs):
        multipath_app = self.multipath_app
        load_table = {}
        path = ['00:00:00:00:00:01', 1, 3, '00:00:00:00:00:04']
        load_table[1] = multipath_app.get_path_load(path)
        path = ['00:00:00:00:00:01', 1, 2, 3, '00:00:00:00:00:04']
        load_table[2] = multipath_app.get_path_load(path)
        path = ['00:00:00:00:00:01', 1, 4, 3, '00:00:00:00:00:04']
        load_table[3] = multipath_app.get_path_load(path)
        body = json.dumps(load_table)
        return Response(content_type='application/json', body=body)

class NetworkMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        "Network_Monitor": network_monitor.Network_Monitor,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.network_monitor = kwargs['Network_Monitor']
        self.topology_api_app = self
        self.route_table = {}
        self.net = nx.DiGraph()
        self.host_list = []

        wsgi = kwargs['wsgi']
        wsgi.register(NetworkMonitorController, {'multipath_app': self})

    def get_all_path_load(self):
        table = self.route_table
        for path_id in table.keys():
            path = table[path_id]['path']
            if path is not None:
                load_list = [self.network_monitor.get_link_loading_mbps(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 1)]
                table[path_id]['load'] = max(load_list)
        return table

    def get_path_load(self, path):
        if path is not None:
            load_list = [self.network_monitor.get_link_loading_mbps(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 2)]
            pload = max(load_list)
            return pload
        else:
            return None

    events = [event.EventSwitchEnter, event.EventLinkAdd, event.EventPortAdd]
    @set_ev_cls(events)
    def update_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

        self.net_updated()

    def net_updated(self):
        self.logger.info("Links: %s", self.net.edges())

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        if pkt.get_protocol(lldp.lldp):
            return None

        if pkt.get_protocol(ipv6.ipv6):
            return None

        if dst == 'ff:ff:ff:ff:ff:ff':
            return None

        mac_list = ['00:00:00:00:00:01', '00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04', '00:00:00:00:00:05', '00:00:00:00:00:06']
        if src not in mac_list or dst not in mac_list:
            return None

        # <editor-fold desc="Learn sender's MAC address">
        if src not in self.net:
            # we received a packet from a MAC address that we've never seen
            # add this MAC to our network graph
            self.net.add_node(src)
            self.host_list.append(src)
            # remember to which port of the switch (dpid) this MAC is attached
            self.net.add_edge(dpid, src, {'port': in_port})
            self.net.add_edge(src, dpid)
            self.net_updated()

            self.install_core_label(src)
            # if src not in self.arp_table.values():
            #     pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            #     if pkt_ipv4 is not None:
            #         self.arp_table[pkt_ipv4.src] = src

        # arp_pkt = pkt.get_protocol(arp.arp)
        # if arp_pkt:
        #     self.arp_table[arp_pkt.src_ip] = src
        #     self.logger.info("Learned ARP %s<->%s", arp_pkt.src_ip, src)

        # if dst in self.net:
        #     pass            
        # else:
            # if dst not in self.arp_table.values():
            #     pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            #     if pkt_ipv4 is not None:
            #         self.arp_table[pkt_ipv4.src] = dst


    def install_core_label(self, src):
        host_list = self.host_list
        for host in (h for h in host_list if h != src):
            all_paths = list(nx.all_simple_paths(self.net, src, host))
            for path in all_paths:
                if len(path) > 3:   # above 1 hop
                    path_id = self.save_route_table(src, host, path)

            all_paths = list(nx.all_simple_paths(self.net, host, src))
            for path in all_paths:
                if len(path) > 3:   # above 1 hop
                    path_id = self.save_route_table(host, src, path)

    def save_route_table(self, src, dst, path):
        if len(self.route_table) == 0:
            path_id = 0
        else:
            path_id = max(self.route_table.keys(), key=int) + 1
        self.route_table[path_id] = {}
        self.route_table[path_id]['src'] = src
        self.route_table[path_id]['dst'] = dst
        self.route_table[path_id]['path'] = path
        return path_id