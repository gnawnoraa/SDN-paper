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
# import StringIO
# import urllib
# import base64
# import time
import json
import operator
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp, dhcp
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac
from ryu.lib import hub
from ryu.lib import ofctl_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
# import matplotlib.pyplot as plt
import network_monitor
import classification
import qos_control
import congestionECN

import os
from webob.static import DirectoryApp

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

PATH = os.path.dirname(__file__)

BASE_URL = "/traffic/routing"
REQUIREMENTS = {'dpid': dpid_lib.DPID_PATTERN}
DATA_MICE_LABEL = classification.DATA_MICE_LABEL
DATA_ELEPHANTS_LABEL = classification.DATA_ELEPHANTS_LABEL
QOS_HIGH_LABEL = classification.QOS_HIGH_LABEL
QOS_LOW_LABEL = classification.QOS_LOW_LABEL

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
    # nx.draw(G, nx.circular_layout(G))
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

class MultipathController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(MultipathController, self).__init__(req, link, data, **config)
        path = "%s/gui/" % PATH
        self.static_app = DirectoryApp(path)
        self.multipath_app = data['multipath_app']

    @route('web', '/gui/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)

    @route('web', '/show_topo', methods=['GET'])
    def show_topology(self, req, **kwargs):
        """Show the topology in PNG format.
        """
        body = get_as_uri(self.multipath_app.net)
        return Response(content_type='text/html', body=body)

    url = BASE_URL + '/congestion_control'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_is_contestion_control(self, req, **kwargs):
        body = json.dumps(self.multipath_app.isContestionControl)
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/congestion_control/{bool}'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def set_is_contestion_control(self, req, **kwargs):
        input_val = kwargs['bool'].lower()
        if input_val == "false":
            self.multipath_app.del_ECN()
            self.multipath_app.isContestionControl = False
        elif input_val == "true":
            self.multipath_app.isContestionControl = True
        body = json.dumps(self.multipath_app.isContestionControl)
        return Response(content_type='application/json', body=body)

    url= BASE_URL + '/congestion_control_state'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_congestion_control_state(self, req, **kwargs):
        body = json.dumps(self.multipath_app.network_monitor.congestion_state)
        return Response(content_type='application/json', body=body)

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

    url = BASE_URL + '/link_loading'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_link_loading(self, req, **kwargs):
        network_monitor = self.multipath_app.network_monitor
        body = json.dumps(network_monitor.get_all_link_loading())
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/admin_rule'
    @route('multipath', url, methods=['POST'], requirements=REQUIREMENTS)
    def get_qos_rule(self, req, **kwargs):
        multipath_app = self.multipath_app
        new_entry = eval(req.body)
        data_share = float(new_entry['data'])
        qos_share = float(new_entry['qos'])
        multipath_app.data_share = data_share
        multipath_app.qos_share = qos_share
        body = json.dumps(new_entry)
        return Response(content_type='application/json', body=body)

    url = BASE_URL + '/qos_rule'
    @route('multipath', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_qos_rule(self, req, **kwargs):
        table = self.multipath_app.qos_rule_table
        body = json.dumps(table)
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
        # path = multipath_app.shortest_weight_path(src, dst)
        path = multipath_app.policy_admission_control(src, dst, rate, qos_share)
        if path == []:
            return Response(content_type='application/json', body=json.dumps(path))
            # return Response(content_type='application/json', body=json.dumps('QoS High Priority can not send!!!'))
        multipath_app.qos_rule_table[qos_id] = value
        multipath_app.qos_rule_table[qos_id]['path'] = path
        # setting the path output port queue
        qos_table = multipath_app.qos_rule_table
        qos_high_path = [(qos_table[qid]['path'], qos_table[qid]['rate']) for qid in qos_table.keys()]
        switch = path[1]
        next_switch = path[2]
        port_rate = 0
        for qpath in qos_high_path:
            if qpath[0][qpath[0].index(switch) + 1] == next_switch:
                port_rate += qpath[1]
        for i in range(1, len(path) - 1):
            switch = path[i]
            next_switch = path[i + 1]
            # qos_control.set_qos_queue(switch, data_share, qos_share, rate * 1000 * 1000, multipath_app.net[switch][next_switch]['port'])
            qos_control.set_qos_queue(switch, data_share, qos_share, port_rate * 1000 * 1000, multipath_app.net[switch][next_switch]['port'])
        
        # install flow table
        # multipath_app.install_new_flow_path(path, msg)
        ip_proto = inet.IPPROTO_TCP if proto.upper() == "TCP" else inet.IPPROTO_UDP
        match_fields = {}
        match_fields['in_port'] = multipath_app.net[path[1]][path[0]]['port']
        # match_fields['eth_src'] = path[0]
        match_fields['eth_dst'] = path[-1]
        match_fields['eth_type'] = ether.ETH_TYPE_IP
        match_fields['ipv4_src'] = multipath_app.arp_table.keys()[multipath_app.arp_table.values().index(path[0])]
        match_fields['ipv4_dst'] = multipath_app.arp_table.keys()[multipath_app.arp_table.values().index(path[-1])]
        match_fields['ip_proto'] = ip_proto
        if proto is "TCP":
            match_fields['tcp_dst'] = port_no
        else:
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
        self.ofctl = ofctl_v1_3
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
        self.qos_share = qos_control.DEFAULT_QOS_SHARE
        self.data_share = qos_control.DEFAULT_DATA_SHARE

        wsgi = kwargs['wsgi']
        wsgi.register(MultipathController, {'multipath_app': self})

        self.monitor_thread = hub.spawn(self._monitor)
        self.isContestionControl = True

    def _monitor(self):
        while True:
            if self.isContestionControl:
                #result = self.network_monitor.congestion_detection(data_share=0.5, threshold=0.75)
                #if result['state'] == "Enable ECN" or result['state'] == "Disable ECN":
                #    self.select_flow(result)
                self.congestion_control()
            # self.policy_checking()
            hub.sleep(network_monitor.SLEEP_PERIOD * 2)

    def congestion_control(self, threshold=0.8):
        #state = self.network_monitor.congestion_state
        link_capacity = network_monitor.DEFAULT_CURR_SPEED / 1000
        state = self.network_monitor.get_flow_loading()
        bodys = self.network_monitor.stats['flow']
        for dpid in state.keys():
            for port in state[dpid].keys():
                # for label in state[dpid][port].keys():
                label = DATA_ELEPHANTS_LABEL
                utilization = self.network_monitor.get_link_loading_mbps(dpid, port) / link_capacity
                if utilization >= threshold:
                    #for stat in [flow for flow in bodys[dpid] if flow.priority == 2 and len(flow.instructions) > 0]:
                    for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 1 and not self.is_flow_in_table(self.datapaths[dpid], flow.match)]):
                        isTagret = False
                        match = stat.match
                        if len(stat.instructions) > 0:
                            actions = stat.instructions[0].actions
                            if port == actions[-1].port: 
                                if 'vlan_pcp' in match:
                                    vpcp = match.get('vlan_pcp')
                                    if vpcp == label:
                                        #print "the match rule have label"
                                        vid = match.get('vlan_vid') & 0xEFFF
                                        #isTagret = True
                   
                                for act in actions:
                                    action_type = act.cls_action_type
                                    if action_type == ofproto_v1_3.OFPAT_SET_FIELD:
                                        if act.key == 'vlan_pcp':
                                            if act.value == label:
                                                #print "action have label"
                                                vid = act.value & 0xEFFF
                                                isTagret = True

                            if isTagret is True:
                                # print "[match]" , match.items()
                                match_fields = dict()
                                for key, value in match.iteritems():
                                    match_fields[key] = value
                                #print "install ecn flow (dpid, match_fields, actions)", (dpid, match_fields, actions)
                                #print "Install ECN flow (dpid, port)", (dpid, port)
                                congestionECN.install_ECN_flow(self.datapaths[dpid], match_fields, actions)
                else:
                    for stat in [flow for flow in bodys[dpid] if flow.priority == 2]:
                        isTagret = False
                        match = stat.match
                        if len(stat.instructions) > 0:
                            actions = stat.instructions[0].actions
                            if port == actions[-1].port:
                                if 'ip_ecn' in match:
                                    isTarget = True
                                for act in actions:
                                    if act.cls_action_type == ofproto_v1_3.OFPAT_SET_FIELD:
                                        if act.key == 'ip_ecn':
                                            isTagret = True
                            
                            if isTagret is True:
                                match_fields = dict()
                                for key, value in match.iteritems():
                                    match_fields[key] = value
                                # print "remove ecn flow (dpid, match_fields, actions)", (dpid, match_fields, actions)
                                #print "Remove ECN flow (dpid, port)", (dpid, port)
                                congestionECN.remove_ECN_flow(self.datapaths[dpid], match_fields)

    def is_flow_in_table(self, datapath, match_, priority=2):
        dpid = datapath.id
        match_fields = dict()
        for key, value in match_.iteritems():
            match_fields[key] = value
        match_fields['ip_ecn'] = 1
        match1 = datapath.ofproto_parser.OFPMatch(**match_fields)
        match_fields['ip_ecn'] = 2
        match2 = datapath.ofproto_parser.OFPMatch(**match_fields)
        bodys = self.network_monitor.stats['flow']
        for stat in [flow for flow in bodys[dpid] if flow.priority == priority]:
            # print stat.match, match1
            if stat.match == match1 or stat.match == match2:
                print "flow entry is in flow table"
                return True
        return False

    def select_flow(self, rule):
        dpid = rule['dpid']
        port = rule['port']
        label = rule['label']

        if rule['state'] == "Enable ECN":
            bodys = self.network_monitor.stats['flow']
            # for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 1]):
            for stat in sorted([flow for flow in bodys[dpid]]):
                # match = stat.match
                # key = (frozenset(self.ofctl.match_to_str(stat.match).items()), tuple(self.ofctl.actions_to_str(stat.instructions)))
                # flow_speed = self.flow_speed[dpid][key][-1] * 8 / 1024 / 1024

                isTagret = False
                match = stat.match
                if len(stat.instructions) <= 0:
                    return
                actions = stat.instructions[0].actions
                if port == actions[-1].port: 
                    if 'vlan_pcp' in match:
                        vpcp = match.get('vlan_pcp')
                        if vpcp == label:
                            print "the match rule have label"
                            vid = match.get('vlan_vid') & 0xEFFF
                            isTagret = True
       
                    for act in actions:
                        action_type = act.cls_action_type
                        if action_type == ofproto_v1_3.OFPAT_SET_FIELD:
                            if act.key == 'vlan_pcp':
                                if act.value == label:
                                    print "action have label"
                                    vid = act.value & 0xEFFF
                                    isTagret = True

                if isTagret is True:
                    # print "[match]" , match.items()
                    match_fields = dict()
                    for key, value in match.iteritems():
                        match_fields[key] = value
                    # print "install ecn flow (dpid, match_fields, actions)", (dpid, match_fields, actions)
                    congestionECN.install_ECN_flow(self.datapaths[dpid], match_fields, actions)
        elif rule['state'] == "Disable ECN":
            bodys = self.network_monitor.stats['flow']
            # for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 1]):
            for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 2]):
                isTagret = False
                match = stat.match
                if len(stat.instructions) <= 0:
                    return
                actions = stat.instructions[0].actions
                if port == actions[-1].port:
                    if 'ip_ecn' in match:
                        isTarget = True
                    for act in actions:
                        if act.cls_action_type == ofproto_v1_3.OFPAT_SET_FIELD:
                            if act.key == 'ip_ecn':
                                isTagret = True
                
                if isTagret is True:
                    match_fields = dict()
                    for key, value in match.iteritems():
                            match_fields[key] = value
                    # print "remove ecn flow (dpid, match_fields, actions)", (dpid, match_fields, actions)
                    #print "Remove ECN flow"
                    #congestionECN.remove_ECN_flow(self.datapaths[dpid], match_fields)

    def del_ECN(self):
        state = self.network_monitor.congestion_state
        for dpid in state.keys():
            for port in state[dpid].keys():
                for label in state[dpid][port].keys():
                    state[dpid][port][label] = "NoCongested"

        bodys = self.network_monitor.stats['flow']
        for dpid in bodys.keys():
            for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 2]):
                match = stat.match
                match_fields = dict()
                for key, value in match.iteritems():
                    match_fields[key] = value
                congestionECN.remove_ECN_flow(self.datapaths[dpid], match_fields)
            # for stat in sorted([flow for flow in bodys[dpid]]):
            #     isTagret = False
            #     match = stat.match
            #     if len(stat.instructions) <= 0:
            #         return
            #     actions = stat.instructions[0].actions
            #     if 'ip_ecn' in match and port == match.get('in_port'):
            #         isTarget = True

            #     # if port == actions[-1].port:
            #     for act in actions:
            #         if act.cls_action_type == ofproto_v1_3.OFPAT_SET_FIELD:
            #             if act.key == 'ip_ecn':
            #                 isTagret = True
                
            #     if isTagret is True:
            #         match_fields = dict()
            #         for key, value in match.iteritems():
            #                 match_fields[key] = value
            #         # print "remove ecn flow (dpid, match_fields, actions)", (dpid, match_fields, actions)
            #         congestionECN.remove_ECN_flow(self.datapaths[dpid], match_fields)

    def policy_checking(self, data_share=0.5):
        qos_table = self.qos_rule_table
        curr_speed = network_monitor.DEFAULT_CURR_SPEED / 1000
        for qos_id in qos_table.keys():
            entry = qos_table[qos_id]
            path = entry['path']
            switch = path[1]
            next_switch = path[2]
            datapath = self.datapaths[switch]
            ip_proto = inet.IPPROTO_TCP if entry['proto'] is "TCP" else inet.IPPROTO_UDP
            ipv4_src = self.arp_table.keys()[self.arp_table.values().index(path[0])]
            ipv4_dst = self.arp_table.keys()[self.arp_table.values().index(path[-1])]
            if ip_proto == inet.IPPROTO_TCP:
                qos_match = datapath.ofproto_parser.OFPMatch(in_port=self.net[path[1]][path[0]]['port'], eth_dst=path[-1], eth_type=ether.ETH_TYPE_IP, ip_proto=ip_proto, ipv4_src=ipv4_src, tcp_dst=entry['port_no'])
            elif ip_proto == inet.IPPROTO_UDP:
                qos_match = datapath.ofproto_parser.OFPMatch(in_port=self.net[path[1]][path[0]]['port'], eth_dst=path[-1], eth_type=ether.ETH_TYPE_IP, ip_proto=ip_proto, ipv4_dst=ipv4_dst, udp_dst=entry['port_no'])

            flow_load = self.network_monitor.get_flow_loading()
            port = self.net[switch][next_switch]['port']
            data_load = 0
            qos_low_load = 0
            if switch in flow_load:
                if port in flow_load[switch]:
                    if DATA_MICE_LABEL in flow_load[switch][port]:
                        data_load += flow_load[switch][port][DATA_MICE_LABEL]
                    if DATA_ELEPHANTS_LABEL in flow_load[switch][port]:
                        data_load += flow_load[switch][port][DATA_ELEPHANTS_LABEL]
                    if QOS_LOW_LABEL in flow_load[switch][port]:
                        qos_low_load = flow_load[switch][port][QOS_LOW_LABEL]
            data_load = data_load if data_load <= (curr_speed * data_share) else (curr_speed * data_share)

            qos_high_path = [(qos_table[qid]['path'], qos_table[qid]['rate']) for qid in qos_table.keys()]
            rate = 0
            for qpath in qos_high_path:
                if qpath[0][qpath[0].index(switch) + 1] == next_switch:
                    rate += qpath[1]

            qos_low_bw = curr_speed - data_load - rate

            print "(qos_low_load, qos_low_bw, data_load, qos_high_rate)", (qos_low_load, qos_low_bw, data_load, rate)
            priority = 3
            if qos_low_load > qos_low_bw:
                print "QoS Low Flow need to drop"
                self.add_flow(datapath, priority, qos_match, [], 0, 0)
            else:
                self.del_priority_flow(datapath, priority, qos_match)

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

        # increase miss_send_len to the max (OVS default: 128Bytes)
        conf = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 0xFFFF)
        datapath.send_msg(conf)

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

    def del_priority_flow(self, datapath, priority, match, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                priority=priority,
                                table_id=table_id,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def mod_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath = datapath,
                                priority = priority,
                                match = match,
                                instructions = inst,
                                command = ofproto.OFPFC_MODIFY)
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
            self.add_flow(datapath, 1, match, actions, 0, 0)
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
            if src in self.net.neighbors(dpid) and dst in self.net.neighbors(dpid):
                path = [src, dpid, dst]
            else:
                # compute the path to the destination
                label = self.classifiy(msg)
                # path = nx.shortest_path(self.net, src, dst)
                path = []
                if label is QOS_HIGH_LABEL:
                    print "[QOS_HIGH_LABEL]"
                    path = self.admission_control(msg)
                    # path = self.high_priority_path(src, dst, rate=rate)
                    if path == []:
                        return
                elif label is QOS_LOW_LABEL:
                    path = self.qos_path(src, dst)
                    # path = self.load_balance_path(src, dst)[0]
                elif label is DATA_ELEPHANTS_LABEL or label is DATA_MICE_LABEL:
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
                self.logger.info("we don't know anything, so flood the packet from %s to %s", src, dst)
                #out_port = ofproto.OFPP_FLOOD
                self.broadcast_handler(msg)
                return
        # </editor-fold>

    def admission_control(self, msg):
        rate = 0
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        for rule in self.qos_rule_table.values():
            print "[admission control]", rule
            proto = tcp.tcp if rule['proto'] == "TCP" else udp.udp
            if src == rule['src'] and dst == rule['dst'] and pkt.get_protocol(proto) is not None:
                rate = rule['rate']
                break
        print "[Admission Control]rate =", rate
        path = self.high_priority_path(src, dst, rate=rate)
        if path == []:
            print "[Admission Control]High priority flow can't send"
            match = self.get_match_l4(msg)
            actions = []
            self.add_flow(datapath, 1, match, actions)
        return path

    def policy_admission_control(self, src, dst, rate, qos_share):
        path = self.high_priority_path(src, dst, rate=rate, qos_share=qos_share)
        if path == []:
            print "[Admission Control]High priority flow can't send"
            # match = self.get_match_l4(msg)
            # actions = []
            # self.add_flow(datapath, 1, match, actions)
        return path

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
        # available_path = self.min_loading_algorithm(src, dst, threshold)
        paths_loading = self.min_loading_algorithm(src, dst, threshold)[1]
        # min hop count
        # if len(available_path) > 0:
        #     path = route_table[min(available_path, key=available_path.get)]['path']
        #     path = route_table[available_path.keys()[0]]['path']
        # else:
        pid = min(paths_loading, key=paths_loading.get)
        equal_load = [key for key, load in paths_loading.iteritems() if load == paths_loading[pid]]
        if len(equal_load) > 1:
            hop_count = [(pathid, len(route_table[pathid]['path'])) for pathid in equal_load]
            pid = min(hop_count, key=operator.itemgetter(1))[0]
        path = route_table[pid]['path']

    	if path == []:
    		raise ValueError("QoS path all full")

        self.logger.info("[QoSPath]Path %s -> %s via %s", src, dst, path)
        return path

    def high_priority_path(self, src, dst, rate, qos_share=0.5):
        route_table = self.route_table
        curr_speed = network_monitor.DEFAULT_CURR_SPEED / 1000   # Mbps
        threshold = (curr_speed * qos_share) - rate
        available_path = self.min_loading_algorithm(src, dst, threshold, True)[0]
        if len(available_path) > 0:
        	#min hop count
        	path = route_table[min(available_path, key=available_path.get)]['path']
        	self.logger.info("[QoS High Path]Path %s -> %s with rate %s via %s", src, dst, rate, path)
        	return path
        else:
        	return []

    def min_loading_algorithm(self, src, dst, threshold, isHighRule=False):
    	load = self.network_monitor.get_flow_loading()
        route_table = self.route_table
        qos_table = self.qos_rule_table
        paths_loading = {}
        # for pid, item in route_table.iteritems():
        for pid, item in sorted(route_table.iteritems(), key=lambda (k,v): len(v['path'])):
            if item['src'] == src and item['dst'] == dst:
                loadings = []
                path = item['path']
                for i in range(1, len(path) - 2):
                    switch = path[i]
                    next_switch = path[i + 1]
                    port = self.net[switch][next_switch]['port']
                    qos_load = 0
                    for qos_id in qos_table.keys():
                        qpath = qos_table[qos_id]['path']
                        if switch in qpath:
                            if next_switch == qpath[qpath.index(switch) + 1]:
                                qos_load += qos_table[qos_id]['rate']
                    if switch in load and port in load[switch] and not isHighRule:
                        # if QOS_HIGH_LABEL in load[switch][port]:
                            # qos_load += load[switch][port][QOS_HIGH_LABEL]
                        if QOS_LOW_LABEL in load[switch][port]:
                            qos_load += load[switch][port][QOS_LOW_LABEL]

                    loadings.append(qos_load)

                paths_loading[pid] = max(loadings)

        available_path = {}
        for loading in sorted(paths_loading.items(), key=operator.itemgetter(1)):
            if loading[1] <= threshold:
                hop_count = len(route_table[loading[0]]['path'])
                available_path[loading[0]] = hop_count
        return available_path, paths_loading

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

    def get_all_path_load(self):
        table = self.route_table
        for path_id in table.keys():
            path = table[path_id]['path']
            if path is not None:
                load_list = [self.network_monitor.get_link_loading_mbps(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 2)]
                table[path_id]['load'] = max(load_list)
        return table

    def get_path_load(self, path):
        if path is not None:
            load_list = [self.network_monitor.get_link_loading_mbps(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 2)]
            pload = max(load_list)
            return pload
        else:
            return None

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
                      DATA_ELEPHANTS_LABEL,
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
        if path_id is not None:
            actions.append(parser.OFPActionPushVlan())
            actions.append(parser.OFPActionSetField(vlan_pcp=label))
            actions.append(parser.OFPActionSetField(vlan_vid=(path_id | 0x1000)))
        actions.append(self.classifiy_to_action(parser, label))
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
        if path_id is not None:
            actions.append(parser.OFPActionPushVlan())
            actions.append(parser.OFPActionSetField(vlan_pcp=label))
            actions.append(parser.OFPActionSetField(vlan_vid=(path_id | 0x1000)))
        actions.append(self.classifiy_to_action(parser, label))
        actions.append(parser.OFPActionOutput(out_port))

        self.add_flow(datapath, 1, match, actions, idle_timeout=0, hard_timeout=0)
        # self.logger.info("Pushing flow rule to sw%s match:%s | actions:%s", datapath.id, match, actions)

    def classifiy_to_action(self, parser, label):
        queue_id = 0
        if label == DATA_ELEPHANTS_LABEL:
            queue_id = 0
        elif label == DATA_MICE_LABEL:
            queue_id = 0
        elif label == QOS_HIGH_LABEL:
            queue_id = 2
            # queue_id = 1
        elif label == QOS_LOW_LABEL:
            queue_id = 1
        return parser.OFPActionSetQueue(queue_id)

    def classifiy(self, msg):
        elephants_port = [5001, 5002, 5003, 5004, 60000, 60001]
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
                    qos_high_tcp_port.append(qos_table[qos_id]['port_no'])
                elif qos_table[qos_id]['proto'] == "UDP":
                    qos_high_port.append(qos_table[qos_id]['port_no'])

        if pkt_ipv4 is not None:
            if pkt_ipv4.proto == inet.IPPROTO_TCP:
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                label = DATA_ELEPHANTS_LABEL if (pkt_tcp.dst_port in elephants_port or pkt_tcp.src_port in elephants_port) else DATA_MICE_LABEL
                label = QOS_HIGH_LABEL if pkt_tcp.dst_port in qos_high_tcp_port else label
            elif pkt_ipv4.proto == inet.IPPROTO_UDP:
                pkt_udp = pkt.get_protocol(udp.udp)
                label = QOS_HIGH_LABEL if (pkt_udp.dst_port in qos_high_port or pkt_udp.src_port in qos_high_port) else QOS_LOW_LABEL
        return label

    def load_balance_path(self, src, dst):
        all_paths = list(nx.all_simple_paths(self.net, src, dst))
        #self.logger.info("All paths: %s", all_paths)
        loading = []
        for path in all_paths:
            load_list = [self.network_monitor.get_link_loading(path[i], self.net[path[i]][path[i + 1]]['port']) for i in range(1, len(path) - 2)]
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
            already_send = []
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
                    self.logger.info("[broadcast]Send Pkt to sw%s at port %s", dpid, out_port)

            #send to all host
            hosts = self.arp_table.values()
            # hosts = self.host_list
            for host in hosts:
                if host in self.net.neighbors(dpid):
                    out_port = self.net[dpid][host]['port']
                    if out_port != msg.match['in_port'] or dpid != msg.datapath.id:        # no send to src
                        if out_port not in already_send:
                            already_send.append(out_port)
                            actions = [parser.OFPActionOutput(out_port)]
                            out = parser.OFPPacketOut(
                                        datapath=datapath,
                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER,
                                        actions=actions, data=msg.data)
                            datapath.send_msg(out)
                            #self.logger.info("[broadcast]Send Pkt sw%s at port %s - %s", dpid, out_port, pkt)
                            self.logger.info("[broadcast]Send Pkt to sw%s at port %s dst %s", dpid, out_port, host)

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
                match_fields['tcp_src'] = pkt_tcp.src_port
                match_fields['tcp_dst'] = pkt_tcp.dst_port

            elif pkt_ipv4.proto == inet.IPPROTO_UDP:
                self.logger.debug("Got a UDP packet")

                pkt_udp = pkt.get_protocol(udp.udp)
                match_fields['udp_dst'] = pkt_udp.dst_port
                
                dhcp_port = [67, 68]
                if pkt_udp.dst_port in dhcp_port:
                    match_fields.pop('ipv4_dst', None)

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
