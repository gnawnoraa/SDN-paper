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

QOS_HIGH_LABEL = 0 << 10
QOS_LOW_LABEL = 1 << 10
DATA_ELEPHCANTS_LABEL = 2 << 10
DATA_MICE_LABEL = 3 << 10

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp
from ryu.lib import mac
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import network_monitor

class MultipathForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(MultipathForwarding, self).__init__(*args, **kwargs)
        self.network_monitor = kwargs["Network_Monitor"]
        self.arp_table = {}
        self.sw = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.datapaths = self.network_monitor.datapaths
        self.route_table = {}

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
                                flag=ofproto.OFPFF_SEND_FLOW_REM,
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
        #self.logger.info("sw%s: PACKET_IN %s->%s at port %s - %s", dpid, src, dst, in_port, pkt)
        self.logger.info("sw%s: PACKET_IN %s %s->%s at port %s", dpid, eth.ethertype, src, dst, in_port)
        # </editor-fold>

        # <editor-fold desc="Learn sender's MAC address">
        if src not in self.net:
            # we received a packet from a MAC address that we've never seen
            # add this MAC to our network graph
            self.net.add_node(src)
            # remember to which port of the switch (dpid) this MAC is attached
            self.net.add_edge(dpid, src, {'port': in_port})
            self.net.add_edge(src, dpid)
            self.net_updated()

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
            # compute the shortest path to the destination
            path = nx.shortest_path(self.net, src, dst)
            #path = self.load_balance_path(src, dst)[0]   #load balance
            self.logger.info("Path %s -> %s via %s", src, dst, [path[i] for i in range(1, len(path)-1)])
            if pkt.get_protocol(ipv4.ipv4):
                self.install_mpls_path_flow(path, msg)
                # self.install_path_flow(path, msg)
            else:
                self.install_path_flow(path, msg)
            #next_switch = path[path.index(dpid)+1]
            # find the switch port, where the next switch is connected
            #out_port = self.net[dpid][next_switch]['port']
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

        # # <editor-fold desc="Action for the packet_out / flow entry">
        # actions = [parser.OFPActionOutput(out_port)]
        # # </editor-fold>

        # # <editor-fold desc="Install a flow to avoid packet_in next time">
        # if out_port != ofproto.OFPP_FLOOD:
        #     # generate a pretty precise match
        #     match_fields = self.get_match_l4(msg)
        #     #self.logger.info("Pushing flow rule to sw%s: %s", dpid, match_fields)
        #     match = parser.OFPMatch(**match_fields)
        #     self.add_flow(datapath, 1, match, actions)
        # # </editor-fold>

        # # <editor-fold desc="Send PACKET_OUT">
        # data = None
        # # if the switch has buffered the packet, we don't have to send back the payload
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data
        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)
        # # </editor-fold>

    def load_balance_path(self, src, dst):
        all_paths = list(nx.all_simple_paths(self.net, src, dst))
        #self.logger.info("All paths: %s", all_paths)
        loading = []
        for path in all_paths:
            total = 0
            for i in range(1, len(path)-1):
                switch = path[i]
                next_switch = path[i+1]
                total += self.network_monitor.get_switch_loading(switch)
                total += self.network_monitor.get_link_loading(switch, self.net[switch][next_switch]['port'])
            loading.append(total)
        lowest_path = all_paths[loading.index(min(loading))]
        self.logger.info("All paths loading: %s", loading)
        #self.logger.info("Path %s -> %s loading(bits):%s via", src, dst, min(loading))
        self.logger.info("Path %s -> %s loading(bits):%s via %s", src, dst, min(loading), lowest_path)
        return lowest_path, loading

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

    @set_ev_cls(event.EventSwitchLeave)
    def leave_topology(self, ev):
        print "event.EventSwitchLeave sw" , ev.switch.dp.id
        self.net.remove_node(ev.switch.dp.id)
        self.net_updated()
        self.check_route()

    @set_ev_cls(event.EventLinkDelete)
    def delete_topology(self, ev):
        print "event.EventLinkDelete"
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        if self.net.has_node(src_dpid) and self.net.has_node(dst_dpid):
            self.net.remove_edge(src_dpid, dst_dpid)
            self.net_updated()
            # self.check_route()

    def check_route(self):
        # to do
        for match, path in self.route_table.iteritems():
            correct = True
            for i in range(1, len(path) - 2):       #only check the 
                correct &= self.net.has_node(path[i])
                correct &= self.net.has_edge(path[i], path[i + 1])
                #print '[link]' , path[i] , '->' , path[i+1] , ' : ' , self.net.has_edge(path[i], path[i + 1])
            print match , ' via ' , path , ' : ' , correct
            if not correct:
                match_fields = dict(match)
                # match_fields['in_port'] = self.net[switch][prev_switch]['port']
                self.remove_path_flow(path, match_fields)
        pass

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

    def classifiy(self, msg):
        elephants_port = [21]
        qos_high_port = [5555]

        label = DATA_MICE_LABEL
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4 is not None:
            if pkt_ipv4.proto == inet.IPPROTO_TCP:
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                label = DATA_ELEPHCANTS_LABEL if pkt_tcp.dst_port in elephants_port else DATA_MICE_LABEL
            elif pkt_ipv4.proto == inet.IPPROTO_UDP:
                pkt_udp = pkt.get_protocol(udp.udp)
                label = QOS_HIGH_LABEL if pkt_udp.dst_port in qos_high_port else QOS_LOW_LABEL
        return label

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

    def install_mpls_path_flow(self, path, msg):
        '''
            path=[src_mac, dpid1, dpid2 ... dst_mac]
        '''
        in_port = msg.match['in_port']
        datapath = msg.datapath
        index = path.index(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mpls_value = self.classifiy(msg)
        out_actions = []
        
        # if len(path) > 2 and path[1] == datapath.id: # include src and dst mac
        if len(path) > 3:    # different switch
            for i in range(1, len(path) - 1):
                match = None
                actions = []
                switch = path[i]
                prev_switch = path[i - 1]
                next_switch = path[i + 1]
                out_port = self.net[switch][next_switch]['port']
                if switch == path[1]:
                    # ingress switch -> push MPLS
                    match_fields = self.get_match_l4(msg)
                    match_fields['in_port'] = self.net[switch][prev_switch]['port']
                    match = parser.OFPMatch(**match_fields)

                    actions = []
                    actions.append(self.classifiy_to_action(parser, mpls_value))
                    actions.append(parser.OFPActionPushVlan())
                    actions.append(parser.OFPActionSetField(vlan_vid=(mpls_value | 0x1000)))
                    actions.append(parser.OFPActionOutput(out_port))
                else:
                    pkt = packet.Packet(msg.data)
                    eth = pkt.get_protocol(ethernet.ethernet)
                    match_fields = dict()
                    match_fields['in_port'] = self.net[switch][prev_switch]['port']
                    match_fields['eth_src'] = eth.src
                    match_fields['eth_dst'] = eth.dst
                    match_fields['eth_type'] = eth.ethertype
                    match_fields['vlan_vid'] = (mpls_value | 0x1000)
                    match = parser.OFPMatch(**match_fields)

                    if switch == path[-2]:
                        # egress switch -> pop MPLS
                        actions = []
                        actions.append(self.classifiy_to_action(parser, mpls_value))
                        actions.append(parser.OFPActionPopVlan())      # defalut use IPv4 0x0800
                        actions.append(parser.OFPActionOutput(out_port))
                    else:
                        # core switch -> MPLS routing
                        actions = [self.classifiy_to_action(parser, mpls_value), parser.OFPActionOutput(out_port)]
                if path[1] == datapath.id:
                    self.add_flow(self.datapaths[switch], 1, match, actions, idle_timeout=0, hard_timeout=0)
                    self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", switch, match, actions)
                if path[i] == datapath.id:
                    out_actions = actions
        elif len(path) == 3:     # same switch
            match_fields = self.get_match_l4(msg)
            match = parser.OFPMatch(**match_fields)
            out_port = self.net[path[index]][path[index + 1]]['port']
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions, idle_timeout=0, hard_timeout=0)
            self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", datapath.id, match, actions)
            out_actions = actions
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=out_actions, data=data)
        datapath.send_msg(out)
        self.logger.info("Path Start Send Pkt from sw%s with actions:%s", datapath.id, out_actions)

    def install_path_flow(self, path, msg):
        '''
            path=[src_mac, dpid1, dpid2 ... dst]
        '''
        datapath = msg.datapath
        first_datapath = path.index(datapath.id)
        if path[1] != datapath.id:
            self.logger.info("sw%s Not first switch path!", datapath.id)
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match_fields = self.get_match_l4(msg)     
        # save to routing table
        match_fields.pop('in_port', None)  
        self.route_table[frozenset(match_fields.items())] = path
        #self.route_table[tuple(sorted(match_fields.items()))] = path

        if len(path) > 2 and path[1] == datapath.id: # include src and dst mac
            for i in range(first_datapath, len(path) - 1):
                switch = path[i]
                prev_switch = path[i - 1]
                next_switch = path[i + 1]
                port = self.net[switch][next_switch]['port']
                actions = []
                actions.append(parser.OFPActionOutput(port))

                match_fields['in_port'] = self.net[switch][prev_switch]['port']
                match = parser.OFPMatch(**match_fields)
                self.add_flow(self.datapaths[switch], 1, match, actions, idle_timeout=0, hard_timeout=0)
                self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", switch, match, actions)
                #self.logger.info("Pushing flow rule to sw%s: %s | actions:%s", switch, match_fields, actions)

        out_actions = []
        out_port = self.net[path[first_datapath]][path[first_datapath+1]]['port']
        out_actions.append(parser.OFPActionOutput(out_port))
        # <editor-fold desc="Send PACKET_OUT">
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=out_actions, data=data)
        datapath.send_msg(out)
        # self.logger.info("Path Start Send Pkt sw%s at port%s", datapath.id, out_port)
        self.logger.info("Path Start Send Pkt from sw%s with actions:%s", datapath.id, out_actions)

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
