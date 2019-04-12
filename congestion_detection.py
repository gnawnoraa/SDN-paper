from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp
from ryu.lib import mac
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import network_monitor

SLEEP_PERIOD = 5

class CongestionDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(MultipathForwarding, self).__init__(*args, **kwargs)
        self.network_monitor = kwargs["Network_Monitor"]
        self.monitor_thread = hub.spawn(self._detect)
        self._state = "NoCongested"

    def _detect(self):
    	while True:
    		if self.network_monitor.
            hub.sleep(SLEEP_PERIOD)

    def flow_load(self):
    	bodys = self.network_monitor.stats['flow']
    	load = {}
    	for dpid in bodys.keys():
    		for stats in sorted([flow for flow in bodys[dpid] if flow.priority == 1]):
    			match = stats.match
    			actions = stats.instructions[0].actions[0]
    			flow_speed = self.flow_speed[dpid][(stat.match, stat.instructions[0].actions[0])][-1]
    			# if 'vlan_vid'
    			if 'vlan_vid' in match:
    				if match.get('vlan_vid') not in load:
    					load[match.get('vlan_vid')] = 0
    				load[match.get('vlan_vid')] += flow_speed

    	print "[flow_load]" , load

    def change_state(self, action):
        if action == "StartControl":
            if self._state == "NoCongested":
                print "Enable ECN"
                self._state = "Congested"
            elif self._state == "Congested":
                print "Nothing Change"
                self._state = "Congested"
        elif action == "StopControl":
            if self._state == "NoCongested":
                print "Nothing Change"
                self._state = "NoCongested"
            elif self._state == "Congested":
                print "Disable ECN"   
                self._state = "NoCongested"

