import json
import logging
import copy

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp, ether_types

class CongestionECN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CongestionECN, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # delete table 0 & 1
        match = parser.OFPMatch()
        # self.del_flow(datapath, match, 0)
        # self.del_flow(datapath, match, 1)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0, 0)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=10, hard_timeout=180, table_id=0):
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
                                match=match, instructions=inst, table_id=table_id)
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

    def install_ECN_flow(self, datapath, match_fields_, actions_, idle_timeout=0, hard_timeout=0):
    	# if match_fields['eth_type'] = 0x0800:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**match_fields_)
        self.del_flow(datapath, match)
        
        match_fields = copy.deepcopy(match_fields_)
        actions = copy.deepcopy(actions_)
        match_fields['ip_ecn'] = 1
        match = parser.OFPMatch(**match_fields)
        actions.insert(0, parser.OFPActionSetField(ip_ecn=3))
        self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
        
        match_fields = copy.deepcopy(match_fields_)
        actions = copy.deepcopy(actions_)
        match_fields['ip_ecn'] = 2
        match = parser.OFPMatch(**match_fields)
        actions.insert(0, parser.OFPActionSetField(ip_ecn=3))
        self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)

        match_fields = copy.deepcopy(match_fields_)
        actions = copy.deepcopy(actions_)
        # match_fields['ip_ecn'] = 0
        match = parser.OFPMatch(**match_fields)
        self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)

    def remove_ECN_flow(self, datapath, match_fields):
        match_fields['ip_ecn'] = 1
        match = parser.OFPMatch(**match_fields)
        self.del_flow(datapath, match)

        match_fields['ip_ecn'] = 2
        match = parser.OFPMatch(**match_fields)
        self.del_flow(datapath, match)

    def start_control(self, dpid, port, label):
        pass

    def select_flow(self, dpid, port, label):
