from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from pprint import pprint
import classification

SLEEP_PERIOD = 3
DEFAULT_CURR_SPEED = 100000     #100M
# DEFAULT_CURR_SPEED = 1000000     #1G

supported_ofctl = {
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
 }

class Network_Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'Network_Monitor'

    def __init__(self, *args, **kwargs):
        super(Network_Monitor, self).__init__(*args, **kwargs)
        self.ofctl = ofctl_v1_3
        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {} # {"port":{dpid:{port:body,..},..},"flow":{dpid:body,..}
        self.port_link = {}  # {dpid:{port_no:(config,state,cur),..},..}
        self.monitor_thread = hub.spawn(self._monitor)
        self.congestion_state = {}  # two state = NoCongested, Congested

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.stats['flow'] = {}
            self.stats['port'] = {}
            for dp in self.datapaths.values():
                self.port_link.setdefault(dp.id, {})
                self._request_stats(dp)
            hub.sleep(1)
            # if self.stats['flow'] or self.stats['port']:
                # self.show_stat('flow', self.stats['flow'])
                # self.show_stat('port', self.stats['port'])
                # self.get_flow_loading()
                # self.congestion_detection(0.5, 0.8)
                # pass
            hub.sleep(SLEEP_PERIOD)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
            dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def get_switch_loading(self, dpid):
        loading = 0
        bodys = self.stats['port']
        if dpid not in bodys.keys():
            return 0
        for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                loading += abs(self.port_speed[(dpid, stat.port_no)][-1])
        return loading

    def get_all_link_loading(self):
        bodys = self.stats['port']
        link_load = {}
        for dpid in bodys.keys():
            link_load[dpid] = {}
            for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                    link_load[dpid][stat.port_no] = self.get_link_loading_mbps(dpid, stat.port_no)
        return link_load

    def get_link_loading(self, dpid, port):
        bodys = self.stats['port']
        if dpid not in bodys.keys():
            return 0
        curr_speed = self.port_link[dpid][port][2]
        if curr_speed == 0: 
            curr_speed = DEFAULT_CURR_SPEED
        return abs(self.port_speed[(dpid, port)][-1]) / curr_speed

    def get_link_loading_mbps(self, dpid, port):
        bodys = self.stats['port']
        if dpid not in bodys.keys():
            return 0
        return abs(self.port_speed[(dpid, port)][-1]) * 8 / 1024 / 1024

    def get_switch_ports_state(self, dpid):
        '''
            list: {port_no:[port-stat, link-stat, cuur_capacity], ...}
            no return the local port(4294967294L)
        '''
        if dpid not in self.port_link.keys():
            return {}
        state_list = {}
        for port, state in self.port_link[dpid].iteritems():
            if port != ofproto_v1_3.OFPP_LOCAL and state[1]=='up':
                state_list[port] = state
        return state_list

    def get_flow_loading(self):
        '''
            flow_speed  (Mb/s)
            load[dpid][port][label_value] = xxx Mb/s
        '''
        bodys = self.stats['flow']
        load = {}
        for dpid in bodys.keys():
            load[dpid] = {}
            # for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 1]):
            for stat in sorted([flow for flow in bodys[dpid]]):
                match = stat.match
                key = (frozenset(self.ofctl.match_to_str(stat.match).items()), tuple(self.ofctl.actions_to_str(stat.instructions)))
                flow_speed = abs(self.flow_speed[dpid][key][-1]) * 8 / 1024 / 1024
                
                '''
                # core and egress switch match have label
                if 'vlan_pcp' in match:
                    # vid = match.get('vlan_vid') & 0xEFFF
                    vid = match.get('vlan_pcp')
                    port = match.get('in_port')
                    self.save_flow_loading(load, dpid, port, vid, flow_speed)
                '''

                # core and egress switch match have label and actions have out_port
                if 'vlan_pcp' in match:
                    vid = match.get('vlan_pcp')
                    if len(stat.instructions) > 0:
                        actions = stat.instructions[0].actions
                        for act in actions:
                            action_type = act.cls_action_type
                            if action_type == ofproto_v1_3.OFPAT_OUTPUT:
                                port = act.port
                                self.save_flow_loading(load, dpid, port, vid, flow_speed)


                # ingress switch actions have label
                if len(stat.instructions) > 0:
                    actions = stat.instructions[0].actions
                    for act in actions:
                        action_type = act.cls_action_type
                        if action_type == ofproto_v1_3.OFPAT_SET_FIELD:
                            if act.key == 'vlan_pcp':
                                # vid = act.value & 0xEFFF
                                vid = act.value
                                port = actions[-1].port    #default the last action is output_port
                                self.save_flow_loading(load, dpid, port, vid, flow_speed)
        # print "[flow_load]" , load
        return load

    def save_flow_loading(self, load, dpid, port, label, speed):
        state = self.congestion_state
        if dpid not in state:
            state[dpid] = {}
        if port not in state[dpid]:
            state[dpid][port] = {}
        if label not in state[dpid][port]:
            state[dpid][port][label] = "NoCongested"

        if port not in load[dpid]:
            load[dpid][port] = {}
        if label not in load[dpid][port]:
            load[dpid][port][label] = 0
        load[dpid][port][label] += speed

    def congestion_detection(self, data_share, threshold):
        # link_capacity = self.port_link[dpid][][2]  #Mbps
        link_capacity = 100     #Mbps
        flow_load = self.get_flow_loading()
        label = classification.DATA_ELEPHANTS_LABEL
        for dpid in flow_load.keys():
            for port in flow_load[dpid].keys():
                if label in flow_load[dpid][port]:
                    # utilization = flow_load[dpid][port][label] / (link_capacity * data_share)
                    utilization = self.get_link_loading_mbps(dpid, port) / link_capacity
                    if utilization >= threshold:
                        if self.change_state("StartControl", dpid, port, label) == "Enable ECN":
                            print "Enable ECN --> (dpid,port,label)", (dpid, port, label), self.congestion_state[dpid][port][label]
                            # todo
                            result = {}
                            result['state'] = "Enable ECN"
                            result['dpid'] = dpid
                            result['port'] = port
                            result['label'] = label
                            return result
                    else:
                        if self.change_state("StopControl", dpid, port, label) == "Disable ECN":
                            print "Disable ECN --> (dpid,port,label)", (dpid, port, label), self.congestion_state[dpid][port][label]
                            # todo
                            result = {}
                            result['state'] = "Disable ECN"
                            result['dpid'] = dpid
                            result['port'] = port
                            result['label'] = label
                            return result
        return {'state':''}

    def change_state(self, action, dpid, port, label):
        if action == "StartControl":
            if self.congestion_state[dpid][port][label] == "NoCongested":
                self.congestion_state[dpid][port][label] = "Congested"
                return "Enable ECN"
            elif self.congestion_state[dpid][port][label] == "Congested":
                self.congestion_state[dpid][port][label] = "Congested"
                # print "Nothing Change"
        elif action == "StopControl":
            if self.congestion_state[dpid][port][label] == "NoCongested":
                self.congestion_state[dpid][port][label] = "NoCongested"
                # print "Nothing Change"
            elif self.congestion_state[dpid][port][label] == "Congested": 
                self.congestion_state[dpid][port][label] = "NoCongested"
                return "Disable ECN"

    def show_stat(self, type, bodys):
        '''
            type: 'port' 'flow'
            bodys: port or flow `s information :{dpid:body}
        '''
        if(type == 'flow'):
            # pprint(bodys)
            # return
            # print('datapath         ''   in-port        ip-dst      '
            #       'out-port packets  bytes  flow-speed(Kb/s)')
            # print('---------------- ''  -------- ----------------- '
            #       '-------- -------- -------- -----------')
            print "[Flow Table Stats]----------------------------------------------"
            for dpid in bodys.keys():
                for stat in sorted([flow for flow in bodys[dpid] if flow.priority == 1]):
                    key = (frozenset(self.ofctl.match_to_str(stat.match).items()), tuple(self.ofctl.actions_to_str(stat.instructions)))
                    print(' dp:\t\t%016x \n match:\t\t%s \n actions:\t%s \n pkt_count:\t%d \t byte_count:\t%d \t flow-speed:\t%.3f' % (
                        dpid,
                        self.ofctl.match_to_str(stat.match),
                        self.ofctl.actions_to_str(stat.instructions),
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][key][-1] * 8 / 1000 )))
                    print "----------------------------------------------------"
                # for stat in sorted(
                #     [flow for flow in bodys[dpid] if flow.priority == 1],
                #     key=lambda flow: (flow.match.get('in_port'),
                #                       flow.match.get('ipv4_dst'))):
                #     if 'in_port' in stat.match and 'ipv4_dst' in stat.match:
                #         print('%016x %8x %17s %8x %8d %8d %8.3f' % (
                #             dpid,
                #             stat.match.get('in_port'), stat.match.get('ipv4_dst'),
                #             stat.instructions[0].actions[0].port,
                #             stat.packet_count, stat.byte_count,
                #             abs(self.flow_speed[dpid][
                #                 (stat.match.get('in_port'),
                #                 stat.match.get('ipv4_dst'),
                #                 stat.instructions[0].actions[0].port)][-1] / 1000)))
            print ''

        if(type == 'port'):
            # pprint(bodys)
            # return
            print('datapath             port   ''rx-pkts  rx-bytes rx-error rx-dropped '
                  'tx-pkts  tx-bytes tx-error tx-dropped  port-speed(B/s)'
                  ' current-capacity(Kbps)  '
                  'port-stat   link-stat')
            print('----------------   -------- ''-------- -------- -------- '
                  '-------- -------- -------- '
                  '----------------  ----------------   '
                  '   -----------    -----------')
            format = '%016x %8x %8d %8d %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
            for dpid in bodys.keys():
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                        print(format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.rx_dropped,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors, stat.tx_dropped,
                            abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            self.port_link[dpid][stat.port_no][2],
                            self.port_link[dpid][stat.port_no][0],
                            self.port_link[dpid][stat.port_no][1]))
            print '\n'

            for dpid in bodys.keys():
                self.logger.info("[SW_LOADING]sw%s: %s", dpid, self.get_switch_loading(dpid))
                #self.logger.info("[port state]sw%s: %s", dpid, self.get_switch_port_state(dpid))
                #self.logger.info("[LINK_LOADING]sw%s: %s", dpid, self.get_link_loading(dpid, 1))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        # print "[body]", body
        # for stat in sorted([flow for flow in body if flow.priority == 1]):
        for stat in sorted([flow for flow in body]):
            ####  stat.match = OFPMatch(oxm_fields={'eth_dst': '00:00:00:00:00:02', 'ipv4_dst': '10.0.0.2', 'ipv4_src': '10.0.0.1', 'eth_type': 2048, 'ip_proto': 1, 'in_port': 1})
            # key = (stat.match, stat.instructions[0])
            key = (frozenset(self.ofctl.match_to_str(stat.match).items()), tuple(self.ofctl.actions_to_str(stat.instructions)))
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre_byte_count = 0
            period = SLEEP_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre_byte_count = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre_byte_count, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.stats['port'][ev.msg.datapath.id] = body
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (ev.msg.datapath.id, stat.port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = SLEEP_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dist = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dist = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dist:
                config = config_dist[p.config]
            else:
                config = "up"

            if p.state in state_dist:
                state = state_dist[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_link[dpid][p.port_no] = port_feature

        #self.logger.debug('OFPPortDescStatsReply received: %s', ports)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:

            print "switch%d: port %s %s" % (dpid, reason_dict[reason], port_no)
        else:
            print "switch%d: Illeagal port state %s %s" % (port_no, reason)