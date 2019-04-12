# Copyright (C) 2011, Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014, Georgia Institute of Technology
# Copyright (C) 2014, Beijing University of Posts and Telecommunications
# Copyright (C) 2015, University of Wuerzburg, Germany
#
# Contributors:
#
#    Akshar Rawal (arawal@gatech.edu)
#    Flavio Castro (castro.flaviojr@gmail.com)
#    Logan Blyth (lblyth3@gatech.edu)
#    Matthew Hicks (mhicks34@gatech.edu)
#    Uy Nguyen (unguyen3@gatech.edu)
#    Li Cheng, (http://www.muzixing.com)
#    Steffen Gebert, (http://www3.informatik.uni-wuerzburg.de/staff/steffen.gebert/)
#
# #  To run:
#
#    ryu--manager --observe-links shortestpath.py
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json
import operator
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import network_monitor
import classification
import qos_control

import os
from webob.static import DirectoryApp

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

PATH = os.path.dirname(__file__)

BASE_URL = "/traffic/routing"
REQUIREMENTS = {'dpid': dpid_lib.DPID_PATTERN}
DATA_MICE_LABEL = classification.DATA_MICE_LABEL
DATA_ELEPHCANTS_LABEL = classification.DATA_ELEPHCANTS_LABEL
QOS_HIGH_LABEL = classification.QOS_HIGH_LABEL
QOS_LOW_LABEL = classification.QOS_LOW_LABEL

class MultipathController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(MultipathController, self).__init__(req, link, data, **config)
        path = "%s/web/" % PATH
        self.static_app = DirectoryApp(path)
        self.multipath_app = data['multipath_app']

    @route('web', '/gui/{filename:.*}')
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

    url = BASE_URL + '/qos_rule'
    @route('multipath', url, methods=['POST'], requirements=REQUIREMENTS)
    def set_qos_rule(self, req, **kwargs):    
        """
            example:
            {'qos_id': 2, 
            'rule': {'src': '00:00:00:00:00:01', 
            'dst': '00:00:00:00:00:04',
            'proto':'UDP', 
            'port_no':5002, 
            'rate':20,
            'rule': {'data_share': 0.5, 'qos_share':0.5}}}
        """
        multipath_app = self.multipath_app
        input_val = eval(req.body)
        qos_id = input_val['qos_id']
        value = input_val['rule']
        src = value['src']
        dst = value['dst']
        proto = value['proto']
        port_no = value['port_no']
        rate = value['rate']
        data_share = value['rule']['data_share']
        qos_share = value['rule']['qos_share']
        # calc shortest weight path
        path = multipath_app.shortest_weight_path(src, dst)
        multipath_app.qos_rule_table[qos_id] = value
        multipath_app.qos_rule_table[qos_id]['path'] = path
        # setting the path output port queue
        for i in range(1, len(path) - 1):
            switch = path[i]
            next_switch = path[i + 1]
            qos_control.set_qos_queue(switch, data_share, qos_share, rate * 1000 * 1000, multipath_app.net[switch][next_switch]['port'])
        # install flow table
        # multipath_app.install_new_flow_path(path, msg)
        ip_proto = inet.IPPROTO_TCP if proto is "TCP" else inet.IPPROTO_UDP
        match_fields = {}
        match_fields['in_port'] = multipath_app.net[path[1]][path[0]]['port']
        match_fields['eth_dst'] = path[-1]
        match_fields['eth_type'] = ether.ETH_TYPE_IP
        match_fields['ipv4_src'] = multipath_app.arp_table.keys()[multipath_app.arp_table.values().index(path[0])]
        match_fields['ipv4_dst'] = multipath_app.arp_table.keys()[multipath_app.arp_table.values().index(path[-1])]
        match_fields['ip_proto'] = ip_proto
        match_fields['udp_dst'] = port_no
        multipath_app.install_qos_high_path(path, QOS_HIGH_LABEL, match_fields)
        body = json.dumps(path)
        return Response(content_type='application/json', body=body)

class MultipathForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        "Network_Monitor": network_monitor.Network_Monitor,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(MultipathForwarding, self).__init__(*args, **kwargs)
        self.network_monitor = kwargs['Network_Monitor']
        # self.network_monitor = network_monitor.Network_Monitor
        # self.network_monitor = Network_Monitor(*args, **kwargs)
        self.arp_table = {}
        self.host_list = []
        self.sw = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.datapaths = self.network_monitor.datapaths
        # self.datapaths = kwargs['dpset'].dps
        self.route_table = {}
        self.qos_rule_table = {}

        wsgi = kwargs['wsgi']
        wsgi.register(MultipathController, {'multipath_app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called during handshake, defines rule to send all unknown packets to controller

        :type ev: ryu.controller.ofp_event.EventOFPSwitchFeatures
        :return: None
        :rtype: None
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # delete all table
        match = parser.OFPMatch()
        self.del_flow(datapath, match, 0)
        self.del_flow(datapath, match, 1)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # this rule has to stay forever
        timeout = 0
        # with the lowest priority
        priority = 0
        self.add_flow(datapath, priority, match, actions, timeout, timeout)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=10, hard_timeout=180):
        """
        Pushes a new flow to the datapath (=switch)

        :type datapath: ryu.controller.controller.Datapath
        :type priority: int
        :type match: ryu.ofproto.ofproto_v1_3_parser.OFPMatch
        :type actions: list
        :type idle_timeout: int
        :type hard_timeout: int
        :return: None
        :rtype: None
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                table_id=table_id,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Called every time, when the controller receives a PACKET_IN message

        :type ev: ryu.controller.ofp_event.EventOFPPacketIn
        :return: None
        :rtype: None
        """

        # <editor-fold desc="Initialization of couple of variables">
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # create a Packet object out of the payload
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        # source and destination mac address of the ethernet packet
        dst = eth.dst
        src = eth.src

        # DPID is just like the number of the switch
        dpid = datapath.id
        # </editor-fold>

        # <editor-fold desc="Drop LLDP">
        if pkt.get_protocol(lldp.lldp):
            return None
        # </editor-fold>

        # <editor-fold desc="Drop IPv6 Packets">
        if pkt.get_protocol(ipv6.ipv6):
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None
        # </editor-fold>

        # <editor-fold desc="Logging">
        # self.logger.info("sw%s: PACKET_IN %s %s->%s at port %s", dpid, eth.ethertype, src, dst, in_port)
        # </editor-fold>

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

            if src not in self.arp_table.values():
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                if pkt_ipv4 is not None:
                    self.arp_table[pkt_ipv4.src] = src
        # </editor-fold>

        # <editor-fold desc="Learn IPs from ARP packets">
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src
            self.logger.info("Learned ARP %s<->%s", arp_pkt.src_ip, src)
        # </editor-fold>

        # <editor-fold desc="Know destination MAC address">
        if dst in self.net:
            # compute the path to the destination
            label = self.classifiy(msg)
            # path = nx.shortest_path(self.net, src, dst)
            path = []
            if label is QOS_HIGH_LABEL:
                # path = nx.shortest_path(self.net, src, dst)
                # path = self.shortest_weight_path(src, dst)
                # path = self.qos_path(src, dst)
                rate = 0
                for rule in self.qos_rule_table.values():
                    if src == rule['src'] and dst == rule['dst']:
                        rate = rule['rate']

                path = self.high_priority_path(src, dst, rate=rate)
            elif label is QOS_LOW_LABEL:
                path = self.qos_path(src, dst)
            elif label is DATA_ELEPHCANTS_LABEL or label is DATA_MICE_LABEL:
                path = self.load_balance_path(src, dst)[0]
            # path = self.load_balance_path(src, dst)[0]   #load balance
            # self.logger.info("Path %s -> %s via %s", src, dst, [path[i] for i in range(1, len(path)-1)])
            self.install_new_flow_path(path, msg)
            
        # </editor-fold>

        # <editor-fold desc="Unknown destination MAC address">
        else:
            if dst not in self.arp_table.values():
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                if pkt_ipv4 is not None:
                    self.arp_table[pkt_ipv4.src] = dst
            # the destination is yet unknown, so call ARP handler
            if self.arp_handler(msg):
                # when we are here, then the ARP handler responded back and we don't have to care
                return None
            else:
                # we don't know anything, so flood the packet
                self.logger.info("we don't know anything, so flood the packet")
                #out_port = ofproto.OFPP_FLOOD
                self.broadcast_handler(msg)
                return
        # </editor-fold>

    def shortest_weight_path(self, src, dst):
        # update weight 
        load = self.network_monitor.get_flow_loading()
        for dpid in load.keys():
            for port in load[dpid].keys():
                # curr_speed = self.network_monitor.port_link[dpid][port][2] / 1000   # Mbps
                curr_speed = network_monitor.DEFAULT_CURR_SPEED / 1000   # Mbps

                # find next dpid
                nb_dpid = None
                for next_dpid, link_port in self.net[dpid].iteritems():
                    if link_port['port']  == port:
                        nb_dpid = next_dpid

                # Mbps
                qos_load = 0   
                if QOS_HIGH_LABEL in load[dpid][port]:
                    qos_load += load[dpid][port][QOS_HIGH_LABEL]
                if QOS_LOW_LABEL in load[dpid][port]:
                	qos_load += load[dpid][port][QOS_LOW_LABEL]
                # for qos_id in self.qos_rule_table.keys():
                # 	high_priority_path = self.qos_rule_table[qos_id]['path']
                # 	if switch in high_priority_path:
                # 		if next_switch == high_priority_path[high_priority_path.index(switch) + 1]:
                # 			qos_load += self.qos_rule_table[qos_id]['rate']

                weight = curr_speed / (curr_speed - qos_load)
                # print "[dpid,port:", dpid, port, "](curr_speed, qos_load, weight)", (curr_speed, qos_load, weight)
                self.net[dpid][nb_dpid]['weight'] = weight

        # print "[nx.edges()] ", self.net.edges(data=True)
        path = nx.dijkstra_path(self.net, src, dst, weight='weight')
        self.logger.info("[ShortestPath]Path %s -> %s via %s", src, dst, path)
        return path

    def qos_path(self, src, dst, qos_share=0.5):
        route_table = self.route_table
        curr_speed = network_monitor.DEFAULT_CURR_SPEED / 1000   # Mbps
        threshold = curr_speed * qos_share * 0.9
        available_path = self.min_loading_algorithm(src, dst, threshold)
        # min hop count
        if len(available_path) > 0:
        	path = route_table[min(available_path, key=available_path.get)]['path']
        else:
    		path = route_table[min(paths_loading, key=paths_loading.get)]['path']

    	if path == []:
    		raise ValueError("QoS path all full")

        self.logger.info("[QoSPath]Path %s -> %s via %s", src, dst, path)
        return path

    def high_priority_path(self, src, dst, rate, qos_share=0.5):
        route_table = self.route_table
        curr_speed = network_monitor.DEFAULT_CURR_SPEED / 1000   # Mbps
        threshold = (curr_speed * qos_share) - rate
        available_path = self.min_loading_algorithm(src, dst, threshold)
        if len(available_path) > 0:
        	#min hop count
        	path = route_table[min(available_path, key=available_path.get)]['path']
        	self.logger.info("[QoS High Path]Path %s -> %s with rate %s via %s", src, dst, rate, path)
        	return path
        else:
        	return []

    def min_loading_algorithm(self, src, dst, threshold):
    	load = self.network_monitor.get_flow_loading()
        route_table = self.route_table
        paths_loading = {}
        for pid, item in route_table.iteritems():
            if item['src'] == src and item['dst'] == dst:
                loadings = []
                path = item['path']
                for i in range(1, len(path) - 2):
                    switch = path[i]
                    next_switch = path[i + 1]
                    port = self.net[switch][next_switch]['port']
                    qos_load = 0
                    if switch in load and port in load[switch]:
                        if QOS_HIGH_LABEL in load[switch][port]:
                            qos_load += load[switch][port][QOS_HIGH_LABEL]
                        if QOS_LOW_LABEL in load[switch][port]:
                            qos_load += load[switch][port][QOS_LOW_LABEL]

                    loadings.append(qos_load)

                paths_loading[pid] = max(loadings)

        available_path = {}
        for loading in sorted(paths_loading.items(), key=operator.itemgetter(1)):
            if loading[1] <= threshold:
                hop_count = len(route_table[loading[0]]['path'])
                available_path[loading[0]] = hop_count
        return available_path

    def admission_control(self, rule):
        rule['rule']['qos_share']

    def install_core_label(self, src):
        # host_list = self.arp_table.values()
        host_list = self.host_list
        for host in (h for h in host_list if h != src):
            all_paths = list(nx.all_simple_paths(self.net, src, host))
            for path in all_paths:
                if len(path) > 3:   # above 1 hop
                    path_id = self.save_route_table(src, host, path)
                    self.install_core_path_flow(path_id, path)

            all_paths = list(nx.all_simple_paths(self.net, host, src))
            for path in all_paths:
                if len(path) > 3:   # above 1 hop
                    path_id = self.save_route_table(host, src, path)
                    self.install_core_path_flow(path_id, path)

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

    def install_core_path_flow(self, path_id, path):
        '''
            path=[src_mac, dpid1, dpid2 ... dst_mac]
        '''
        for i in range(2, len(path) - 1):   # install flow from dpid_ingress_next to dpid_egress
            switch = path[i]
            prev_switch = path[i - 1]
            next_switch = path[i + 1]
            out_port = self.net[switch][next_switch]['port']
            parser = self.datapaths[switch].ofproto_parser

            labels = [QOS_HIGH_LABEL,
                      QOS_LOW_LABEL,
                      DATA_ELEPHCANTS_LABEL,
                      DATA_MICE_LABEL]
            for label in labels:
                match_fields = dict()
                match_fields['vlan_pcp'] = label
                match_fields['vlan_vid'] = (path_id | 0x1000)
                match = parser.OFPMatch(**match_fields)

                actions = []
                if switch == path[-2]:
                    # egress switch -> pop LABEL
                    actions = []
                    actions.append(self.classifiy_to_action(parser, label))
                    actions.append(parser.OFPActionPopVlan())      # defalut use IPv4 0x0800
                    actions.append(parser.OFPActionOutput(out_port))
                else:
                    # core switch -> LABEL routing
                    actions = [self.classifiy_to_action(parser, label), parser.OFPActionOutput(out_port)]

                self.add_flow(self.datapaths[switch], 1, match, actions, idle_timeout=0, hard_timeout=0)
                # self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", switch, match, actions)

    def install_new_flow_path(self, path, msg):
        '''
            path=[src_mac, dpid1, dpid2 ... dst_mac]
        '''
        path_id = None
        for pid, item in self.route_table.iteritems():
            if item['path'] == path:
                path_id = pid

        label = self.classifiy(msg)

        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # match
        match_fields = self.get_match_l4(msg)
        match = parser.OFPMatch(**match_fields)

        # actions
        index = path.index(datapath.id)
        out_port = self.net[path[index]][path[index + 1]]['port']
        actions = []
        actions.append(self.classifiy_to_action(parser, label))
        if path_id is not None:
            actions.append(parser.OFPActionPushVlan())
            actions.append(parser.OFPActionSetField(vlan_pcp=label))
            actions.append(parser.OFPActionSetField(vlan_vid=(path_id | 0x1000)))
        actions.append(parser.OFPActionOutput(out_port))

        self.add_flow(datapath, 1, match, actions, idle_timeout=0, hard_timeout=0)
        # self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", datapath.id, match, actions)
        out_actions = actions

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=out_actions, data=data)
        datapath.send_msg(out)
        # self.logger.info("Path Start Send Pkt from sw%s with actions:%s", datapath.id, out_actions)

    def install_qos_high_path(self, path, label, match_fields):
        path_id = None
        for pid, item in self.route_table.iteritems():
            if item['path'] == path:
                path_id = pid

        datapath = self.datapaths[path[1]]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**match_fields)

        # actions
        index = path.index(datapath.id)
        out_port = self.net[path[index]][path[index + 1]]['port']
        actions = []
        actions.append(self.classifiy_to_action(parser, label))
        if path_id is not None:
            actions.append(parser.OFPActionPushVlan())
            actions.append(parser.OFPActionSetField(vlan_pcp=label))
            actions.append(parser.OFPActionSetField(vlan_vid=(path_id | 0x1000)))
        actions.append(parser.OFPActionOutput(out_port))

        self.add_flow(datapath, 1, match, actions, idle_timeout=0, hard_timeout=0)
        # self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", datapath.id, match, actions)

    def classifiy_to_action(self, parser, label):
        queue_id = 0
        if label == DATA_ELEPHCANTS_LABEL:
            queue_id = 0
        elif label == DATA_MICE_LABEL:
            queue_id = 0
        elif label == QOS_HIGH_LABEL:
            queue_id = 2
        elif label == QOS_LOW_LABEL:
            queue_id = 1
        return parser.OFPActionSetQueue(queue_id)

    def classifiy(self, msg):
        elephants_port = [21]
        qos_high_port = []
        qos_high_tcp_port = []

        label = DATA_MICE_LABEL     # default
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        dst = eth.dst
        src = eth.src

        qos_table = self.qos_rule_table
        for qos_id in qos_table.keys():
            if qos_table[qos_id]['src'] == src and qos_table[qos_id]['dst'] == dst:
                if qos_table[qos_id]['proto'] == "TCP":
                    qos_high_tcp_port.append(qos_table[qos_id]['port'])
                elif qos_table[qos_id]['proto'] == "UDP":
                    qos_high_port.append(qos_table[qos_id]['port'])

        if pkt_ipv4 is not None:
            if pkt_ipv4.proto == inet.IPPROTO_TCP:
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                label = DATA_ELEPHCANTS_LABEL if pkt_tcp.dst_port in elephants_port else DATA_MICE_LABEL
                label = QOS_HIGH_LABEL if pkt_tcp.dst_port in qos_high_tcp_port else label
            elif pkt_ipv4.proto == inet.IPPROTO_UDP:
                pkt_udp = pkt.get_protocol(udp.udp)
                label = QOS_HIGH_LABEL if pkt_udp.dst_port in qos_high_port else QOS_LOW_LABEL
        return label

    def load_balance_path(self, src, dst):
        all_paths = list(nx.all_simple_paths(self.net, src, dst))
        #self.logger.info("All paths: %s", all_paths)
        loading = []
        for path in all_paths:
            load_list = [self.network_monitor.get_link_loading(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 1)]
            loading.append(max(load_list))
            # total = 0
            # for i in range(1, len(path)-1):
            #     switch = path[i]
            #     next_switch = path[i+1]
            #     total += self.network_monitor.get_switch_loading(switch)
            #     total += self.network_monitor.get_link_loading(switch, self.net[switch][next_switch]['port'])
            # loading.append(total)
        lowest_path = all_paths[loading.index(min(loading))]
        # self.logger.info("All paths loading: %s", loading)
        #self.logger.info("Path %s -> %s loading(bits):%s via", src, dst, min(loading))
        self.logger.info("[LoadBalancing]Path %s -> %s loading(bits):%s via %s", src, dst, min(loading), lowest_path)
        return lowest_path, loading

    def arp_handler(self, msg):
        return False
        """
        Handles ARP messages for us, avoids broadcast storms

        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
        :return: True, if the ARP was handeled, False otherwise
        :rtype: bool
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    arp_reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    self.logger.info("Replied to ARP request for %s with %s", arp_dst_ip, self.arp_table[arp_dst_ip])
                    return True
        return False

    def broadcast_handler(self, msg):
        '''
            send to the non switch link port
        '''
        pkt = packet.Packet(msg.data)
        for dpid, datapath in self.datapaths.iteritems():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            #send to the non switch link
            state = self.network_monitor.get_switch_ports_state(dpid)
            ports = state.keys()
            link_ports = [link_port['port'] for link_port in self.net[dpid].values()]
            for out_port in ports:
                if out_port not in link_ports:
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions, data=msg.data)
                    datapath.send_msg(out)
                    #self.logger.info("[broadcast]Send Pkt sw%s at port %s - %s", dpid, out_port, pkt)
                    self.logger.info("[broadcast]Send Pkt sw%s at port %s", dpid, out_port)

            #send to all host
            hosts = self.arp_table.values()
            for host in hosts:
                if host in self.net.neighbors(dpid):
                    out_port = self.net[dpid][host]['port']
                    if out_port != msg.match['in_port'] or dpid != msg.datapath.id:        # no send to src
                        actions = [parser.OFPActionOutput(out_port)]
                        out = parser.OFPPacketOut(
                                    datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=msg.data)
                        datapath.send_msg(out)
                        #self.logger.info("[broadcast]Send Pkt sw%s at port %s - %s", dpid, out_port, pkt)
                        self.logger.info("[broadcast]Send Pkt sw%s at port %s", dpid, out_port)

    #@set_ev_cls(event.EventSwitchEnter)
    # events = [event.EventSwitchEnter, event.EventSwitchLeave, 
    #           event.EventPortAdd, event.EventPortDelete, event.EventPortModify,
    #           event.EventLinkAdd, event.EventLinkDelete]
    events = [event.EventSwitchEnter, event.EventLinkAdd, event.EventPortAdd]
    @set_ev_cls(events)
    def update_topology(self, ev):
        """
        Watches the topology for updates (new switches/links)
        :type ev:ryu.topology.event.EventSwitchEnter
        :return: None
        :rtype: None
        """
        #self.net.clear()
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

        self.net_updated()

    # @set_ev_cls(event.EventSwitchLeave)
    # def leave_topology(self, ev):
    #     print "event.EventSwitchLeave sw" , ev.switch.dp.id
    #     self.net.remove_node(ev.switch.dp.id)
    #     self.net_updated()
    #     self.check_route()

    # @set_ev_cls(event.EventLinkDelete)
    # def delete_topology(self, ev):
    #     print "event.EventLinkDelete"
    #     src_dpid = ev.link.src.dpid
    #     dst_dpid = ev.link.dst.dpid
    #     if self.net.has_node(src_dpid) and self.net.has_node(dst_dpid):
    #         self.net.remove_edge(src_dpid, dst_dpid)
    #         self.net_updated()
    #         # self.check_route()

    # def check_route(self):
    #     for match, path in self.route_table.iteritems():
    #         correct = True
    #         for i in range(1, len(path) - 2):       #only check the 
    #             correct &= self.net.has_node(path[i])
    #             correct &= self.net.has_edge(path[i], path[i + 1])
    #             #print '[link]' , path[i] , '->' , path[i+1] , ' : ' , self.net.has_edge(path[i], path[i + 1])
    #         print match , ' via ' , path , ' : ' , correct
    #         if not correct:
    #             match_fields = dict(match)
    #             # match_fields['in_port'] = self.net[switch][prev_switch]['port']
    #             self.remove_path_flow(path, match_fields)
    #     pass

    def net_updated(self):
        """
        Things we want to do, when the topology changes
        :return: None
        :rtype: None
        """
        self.logger.info("Links: %s", self.net.edges())

    def get_match_l4(self, msg):
        """
        Define the match to match packets up to Layer 4 (TCP/UDP ports)

        :param msg: The message to process
        :type msg: ryu.controller.ofp_event.EventOFPMsgBase
        :return: Dictionary containing matching fields
        :rtype: dict
        """
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        match_fields = dict()
        match_fields['in_port'] = in_port
        match_fields['eth_dst'] = eth.dst
        match_fields['eth_type'] = eth.ethertype

        # we try to parse this as IPv4 packet
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        if pkt_ipv4 is None:
            if eth.ethertype == ether.ETH_TYPE_ARP:
                self.logger.debug("ARP packet")
            else:
                self.logger.debug("Not interested in ethertype %s (hex: %s)", eth.ethertype, hex(eth.ethertype))
        else:
            # we have an IPv4 packet
            self.logger.debug("Got an IPv4 packet")
            match_fields['ip_proto'] = pkt_ipv4.proto
            match_fields['ipv4_src'] = pkt_ipv4.src
            match_fields['ipv4_dst'] = pkt_ipv4.dst

            if pkt_ipv4.proto == inet.IPPROTO_ICMP:
                self.logger.debug("Got an ICMP packet")

            elif pkt_ipv4.proto == inet.IPPROTO_TCP:
                self.logger.debug("Got a TCP packet")

                pkt_tcp = pkt.get_protocol(tcp.tcp)
                match_fields['tcp_dst'] = pkt_tcp.dst_port

            elif pkt_ipv4.proto == inet.IPPROTO_UDP:
                self.logger.debug("Got a UDP packet")

                pkt_udp = pkt.get_protocol(udp.udp)
                match_fields['udp_dst'] = pkt_udp.dst_port

        return match_fields

    def remove_path_flow(self, path, match_fields):
        if len(path) > 2:
            for i in range(1, len(path) - 1):
                print '[Remove path flow] with Path', i 
                switch = path[i]
                parser = self.datapaths[switch].ofproto_parser
                prev_switch = path[i - 1]
                next_switch = path[i + 1]
                print 'match: ' , match_fields
                match = parser.OFPMatch(**match_fields)
                self.del_flow(self.datapaths[switch], match)
