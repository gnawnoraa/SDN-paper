# Example
# curl -X PUT -d '{"data" : 0.5, "qos" : 0.5}' http://127.0.0.1:8080/traffic/rule

import json
import requests
import time
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
from webob import Response

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
# from route import MultipathForwarding
# import network_monitor

VLANID_NONE = 0
# TEST_LINK_CAPACITY = 100000000	# 100M
DEFAULT_LINK_CAPACITY = 100000000 # 100M
#DEFAULT_LINK_CAPACITY = 1000000000 # 1G
DEFAULT_QOS_SHARE = 0.5
DEFAULT_DATA_SHARE = 0.5

BASE_URL = '/traffic'
REQUIREMENTS = {'dpid': dpid_lib.DPID_PATTERN}
instance_name = 'qos_control_api_app'

OVSDB_ADDRESS = {'0000000000000001': '"tcp:10.0.0.11:6632"',
                 '0000000000000002': '"tcp:10.0.0.12:6632"',
                 '0000000000000003': '"tcp:10.0.0.13:6632"',
                 '0000000000000004': '"tcp:10.0.0.14:6632"',
                 '0000000000000005': '"tcp:10.0.0.15:6632"'}
# OVSDB_ADDRESS = {1: 'tcp:10.0.0.11:6632',
#                  2: 'tcp:10.0.0.12:6632',
#                  3: 'tcp:10.0.0.13:6632',
#                  4: 'tcp:10.0.0.14:6632'}

def set_queue(dpid, data_share, qos_share):
    dpid_str = dpid_lib.dpid_to_str(dpid)
    url = 'http://localhost:8080/qos/queue/' + dpid_str
    payload = '{"type": "linux-htb", "max_rate": "%d", "queues": [{"min_rate": "%d"}, {"min_rate": "%d"}]}' % (
    			DEFAULT_LINK_CAPACITY,
    			DEFAULT_LINK_CAPACITY * data_share,
    			DEFAULT_LINK_CAPACITY * qos_share)
    # payload = '{"port_name": "s1-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}'
    r = requests.post(url, data=payload)
    print "[SET_QUEUE]" , r.text

def set_qos_queue(dpid, data_share, qos_share, qos_high_rate, ofport):
    dpid_str = dpid_lib.dpid_to_str(dpid)
    url = 'http://localhost:8080/qos/queue/' + dpid_str
    payload = '{"port": %d,"type": "linux-htb", "max_rate": "%d", "queues": [{"min_rate": "%d"}, {"min_rate": "%d"}, {"min_rate": "%d"}]}' % (
                ofport,
                DEFAULT_LINK_CAPACITY,
                DEFAULT_LINK_CAPACITY * data_share,
                DEFAULT_LINK_CAPACITY * qos_share - qos_high_rate,
                qos_high_rate)
    # payload = '{"port_name": "s1-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}'
    r = requests.post(url, data=payload)
    print "[SET_QUEUE]" , r.text

def update_queue(dpid, data_share, qos_share, ofport):
    dpid_str = dpid_lib.dpid_to_str(dpid)
    url = 'http://localhost:8080/qos/queue/' + dpid_str
    payload = '{"port": %d,"type": "linux-htb", "max_rate": "%d", "queues": [{"min_rate": "%d"}, {"min_rate": "%d"}]}' % (
                ofport,
                DEFAULT_LINK_CAPACITY * 10,
                DEFAULT_LINK_CAPACITY * 10 * data_share,
                DEFAULT_LINK_CAPACITY * 10 * qos_share)
    # payload = '{"port_name": "s1-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}'
    r = requests.post(url, data=payload)
    print "[update_queue]" , r.text

    # url = 'http://localhost:8080/qos/rules/' + dpid_str
    # payload_tcp = '{"match": {"dl_type": "IPv4", "nw_proto": "TCP"}, "actions":{"queue": "1"}}'
    # payload_udp = '{"match": {"dl_type": "IPv4", "nw_proto": "UDP"}, "actions":{"queue": "2"}}'
    # r = requests.post(url, data=payload_tcp)
    # r = requests.post(url, data=payload_udp)
    

# class QoSControlController(app_manager.RyuApp):
class QoSControlController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QoSControlController, self).__init__(req, link, data, **config)
        self.dpset = data['data']['dpset']
        self.qos_control_app = data[instance_name]

    url = BASE_URL + '/rule'
    @route('qos_control', url, methods=['POST'], requirements=REQUIREMENTS)
    def set_rule(self, req, **kwargs):
        qos_control = self.qos_control_app
    	new_entry = eval(req.body)
    	data_share = float(new_entry['data'])
    	qos_share = float(new_entry['qos'])
        qos_control.data_share = data_share
        qos_control.qos_share = qos_share

    	if data_share + qos_share > 1:
            return Response(status=400)

    	dps = list(self.dpset.dps.keys())
    	for dpid in dps:
    		set_queue(dpid, data_share, qos_share)

        url = 'http://localhost:8080/traffic/routing/admin_rule'
        payload = req.body
        r = requests.post(url, data=payload)
        # return Response(content_type='application/json', body=json.dumps(r.json))

    url = BASE_URL + '/qos_admin'
    @route('qos_control', url, methods=['POST'], requirements=REQUIREMENTS)
    def set_qos_high_flow(self, req, **kwargs):
        """
        Exapmle:
            {'src': '00:00:00:00:00:01', 
            'dst': '00:00:00:00:00:04',
            'proto': 'UDP', 
            'port_no': 5001, 
            'rate': 20}
        """
        qos_control = self.qos_control_app
        new_entry = eval(req.body)

        result = qos_control.set_qos_high_rule(new_entry)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

        # dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

    url = BASE_URL + '/qos_admin'
    @route('qos_control', url, methods=['GET'], requirements=REQUIREMENTS)
    def get_qos_high_flow(self, req, **kwargs):
        qos_control = self.qos_control_app
        result = qos_control.get_qos_high_rule()
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

class QoSControlApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(QoSControlApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']	
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['QoSControlController'] = self.data
        # uri = BASE_URL + '/rule'
        # mapper.connect('stats', uri,
        #                controller=QoSControlController, action='set_rule',
        #                conditions=dict(method=['PUT']))

        wsgi.register(QoSControlController, {instance_name: self, 'data': self.data})
        # self.route_calc = kwargs['Route_Calc']
        # self.route_calc = kwargs['route_calc'](args, kwargs)
        # self.route_calc = route_calc.MultipathForwarding
        self.qos_rule_table = {}
        self.data_share = DEFAULT_DATA_SHARE
        self.qos_share = DEFAULT_QOS_SHARE

    @set_ev_cls(event.EventSwitchEnter)
    # @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_enter(self, ev):
    	dpid = ev.switch.dp.id
        # dpid = ev.msg.datapath.id
        dpid_str = dpid_lib.dpid_to_str(dpid)
        url = 'http://localhost:8080/v1.0/conf/switches/' + dpid_str + '/ovsdb_addr'
        # payload = '"tcp:127.0.0.1:6632"'
        payload = OVSDB_ADDRESS[dpid_str]
        r = requests.put(url, data=payload)
        time.sleep(0.25)
    	set_queue(dpid, self.data_share, self.qos_share)

    def set_qos_high_rule(self, value):
        src = value['src']
        dst = value['dst']
        proto = value['proto']
        port_no = int(value['port_no'])
        rate = int(value['rate'])
        if self._save_qos_rule_table(src, dst, proto, port_no, rate) == []:
            return "QoS High Priority can not send!!!"
        else:
            return self.qos_rule_table

    def get_qos_high_rule(self):
        return self.qos_rule_table

    def _save_qos_rule_table(self, src, dst, proto, port_no, rate):
        if len(self.qos_rule_table) == 0:
            qos_id = 0
        else:
            qos_id = max(self.qos_rule_table.keys(), key=int) + 1
        self.qos_rule_table[qos_id] = {}
        self.qos_rule_table[qos_id]['src'] = src
        self.qos_rule_table[qos_id]['dst'] = dst 
        self.qos_rule_table[qos_id]['proto'] = proto
        self.qos_rule_table[qos_id]['port_no'] = port_no
        self.qos_rule_table[qos_id]['rate'] = rate

        # path = self.route_calc.shortest_weight_path(src, dst)
        url = 'http://localhost:8080/traffic/routing/qos_rule'
        self.qos_rule_table[qos_id]['rule'] = {'data_share': self.data_share, 'qos_share': self.qos_share}
        payload = {'qos_id': qos_id, 'rule': self.qos_rule_table[qos_id]}
        payload = json.dumps(payload)
        self.qos_rule_table[qos_id].pop('rule', None)

        r = requests.post(url, data=payload)
        path = r.json()
        print "QOS Control", path
        self.qos_rule_table[qos_id]['path'] = path
        return path