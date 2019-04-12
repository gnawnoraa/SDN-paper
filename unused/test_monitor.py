from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet


class SimpleMonitor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_stats = {}
        self.flow_speed = {}
        # self.ports = []
        self.sleep = 2
        self.state_len = 3
        self.max_speed = 0
        self.max_bw = (10000000000)/8

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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

    # get the ports' features.
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def port_features_handler(self, ev):
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

        # port_no = 3
        # hw_addr = 'fa:c8:e8:76:1d:7e'
        # config = 0
        # mask = (ofproto.OFPPC_PORT_DOWN | ofproto.OFPPC_NO_RECV |
        #         ofproto.OFPPC_NO_FWD | ofproto.OFPPC_NO_PACKET_IN)
        # advertise = (ofproto.OFPPF_10MB_HD | ofproto.OFPPF_100MB_FD |
        #             ofproto.OFPPF_1GB_FD | ofproto.OFPPF_COPPER |
        #             ofproto.OFPPF_AUTONEG | ofproto.OFPPF_PAUSE |
        #             ofproto.OFPPF_PAUSE_ASYM)
        # req = parser.OFPPortMod(datapath, port_no, hw_addr, config,
        #                         mask, advertise)
        # datapath.send_msg(req)


    def _save_stats(self, dist, key, value, length):
        if key not in dist:
                dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return abs((now-pre)/period)
        else:
            return 0

    def _get_time(self, sec, nsec):
        return abs(sec + nsec/(10**9))

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return abs(self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec))

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        ports = []
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        """for stat in sorted(body, key=attrgetter('port_no')):
            print '++++++++++++++++++++++++++++++++++++++++++++++'
            # print 'max_speed:\n' , stat.max_speed
            print 'curr_speed:\n' , stat.curr_speed
            self.max_speed = stat.curr_speed
            print '++++++++++++++++++++++++++++++++++++++++++++++'"""
        # print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        for p in body:
            ports = ('port_no=%d hw_addr=%s name=%s config=0x%08x '
                     'state=0x%08x curr=%d advertised=0x%08x '
                     'supported=0x%08x peer=0x%08x curr_speed=%d '
                     'max_speed=%d' %
                     (p.port_no, p.hw_addr,
                      p.name, p.config,
                      p.state, p.curr, p.advertised,
                      p.supported, p.peer, p.curr_speed,
                      p.max_speed))
            """port_no = p.port_no
            hw_addr = p.hw_addr
            config = 0
            mask = (ofproto.OFPPC_PORT_DOWN | ofproto.OFPPC_NO_RECV |
                    ofproto.OFPPC_NO_FWD | ofproto.OFPPC_NO_PACKET_IN)
            advertise = (ofproto.OFPPF_10MB_HD | ofproto.OFPPF_100MB_FD |
                        ofproto.OFPPF_1GB_FD | ofproto.OFPPF_COPPER |
                        ofproto.OFPPF_AUTONEG | ofproto.OFPPF_PAUSE |
                        ofproto.OFPPF_PAUSE_ASYM)
            req = parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                mask, advertise)
            datapath.send_msg(req)"""
            # print 'info:\n' , ports
        # print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        # self.logger.debug('OFPPortDescStatsReply received: %s', ports)

    """def send_port_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port_no = 3
        hw_addr = 'fa:c8:e8:76:1d:7e'
        config = 0
        mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
        advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                    ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                    ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                    ofp.OFPPF_PAUSE_ASYM)
        req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                mask, advertise)
        datapath.send_msg(req)"""

    """@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                        reason, msg.desc)"""
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

            key = (stat.match['in_port'], stat.match['eth_dst'],
                   stat.instructions[0].actions[0].port,)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)

            #self._save_stats(self.flow_stats, key, value, self.state_len)
            self._save_stats(self.flow_stats, key, value, 6)

            # Get flow's speed.
            pre = 0
            period = self.sleep
            pre2 = 0
            period2 = self.sleep
            pre3 = 0
            period3 = self.sleep
            pre4 = 0
            period4 = self.sleep
            pre5 = 0
            period5 = self.sleep
            speed = 0
            speed2 = 0
            speed3 = 0
            speed4 = 0
            speed5 = 0
            average_speed = 0
            # max_speed = 0
            tmp = self.flow_stats[key]
            '''if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)'''

            if len(tmp) == 2:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
                average_speed = speed
            elif len(tmp) == 3:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                pre2 = tmp[-3][1]
                period2 = self._get_period(tmp[-2][2], tmp[-2][3],
                                           tmp[-3][2], tmp[-3][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
                speed2 = self._get_speed(self.flow_stats[key][-2][1], pre2, period2)
                average_speed = (speed + speed2)/2
            elif len(tmp) == 4:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                pre2 = tmp[-3][1]
                period2 = self._get_period(tmp[-2][2], tmp[-2][3],
                                           tmp[-3][2], tmp[-3][3])
                pre3 = tmp[-4][1]
                period3 = self._get_period(tmp[-3][2], tmp[-3][3],
                                           tmp[-4][2], tmp[-4][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
                speed2 = self._get_speed(self.flow_stats[key][-2][1], pre2, period2)
                speed3 = self._get_speed(self.flow_stats[key][-3][1], pre3, period3)
                average_speed = (speed + speed2 + speed3)/3
            elif len(tmp) == 5:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                pre2 = tmp[-3][1]
                period2 = self._get_period(tmp[-2][2], tmp[-2][3],
                                           tmp[-3][2], tmp[-3][3])
                pre3 = tmp[-4][1]
                period3 = self._get_period(tmp[-3][2], tmp[-3][3],
                                           tmp[-4][2], tmp[-4][3])
                pre4 = tmp[-5][1]
                period4 = self._get_period(tmp[-4][2], tmp[-4][3],
                                           tmp[-5][2], tmp[-5][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
                speed2 = self._get_speed(self.flow_stats[key][-2][1], pre2, period2)
                speed3 = self._get_speed(self.flow_stats[key][-3][1], pre3, period3)
                speed4 = self._get_speed(self.flow_stats[key][-4][1], pre4, period4)
                average_speed = (speed + speed2 + speed3 + speed4)/4
            elif len(tmp) > 5:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
                pre2 = tmp[-3][1]
                period2 = self._get_period(tmp[-2][2], tmp[-2][3],
                                           tmp[-3][2], tmp[-3][3])
                pre3 = tmp[-4][1]
                period3 = self._get_period(tmp[-3][2], tmp[-3][3],
                                           tmp[-4][2], tmp[-4][3])
                pre4 = tmp[-5][1]
                period4 = self._get_period(tmp[-4][2], tmp[-4][3],
                                           tmp[-5][2], tmp[-5][3])
                pre5 = tmp[-6][1]
                period5 = self._get_period(tmp[-5][2], tmp[-5][3],
                                           tmp[-6][2], tmp[-6][3])
                speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
                speed2 = self._get_speed(self.flow_stats[key][-2][1], pre2, period2)
                speed3 = self._get_speed(self.flow_stats[key][-3][1], pre3, period3)
                speed4 = self._get_speed(self.flow_stats[key][-4][1], pre4, period4)
                speed5 = self._get_speed(self.flow_stats[key][-5][1], pre5, period5)
                average_speed = (speed + speed2 + speed3 + speed4 + speed5)/5

            # speed = self._get_speed(self.flow_stats[key][-1][1], pre, period)
            # speed2 = self._get_speed(pre, pre2, period2)
            # speed3 = self._get_speed(pre2, pre3, period3)
            # speed4 = self._get_speed(pre3, pre4, period4)
            # speed5 = self._get_speed(pre4, pre5, period5)

            info =(stat.packet_count, stat.byte_count, period)

            speeds = (speed, speed2, speed3, speed4, speed5)
            utilization = (average_speed/self.max_bw)

            # self._save_stats(self.flow_speed, key, speed, self.state_len)
            self._save_stats(self.flow_speed, key, speed, 6)
            # self.max_speed = self._port_desc_stats_reply_handler(ev)
            
            print '---------------------------------------------------------------'
            print '\n packet_count, byte_count, period:\n', info
            print ' in_port, eth_dst, out_port:\n', key
            # print 'byte_count', stat.byte_count
            # print 'speed:\n', speed, '(Byte/sec)'
            # print 'speeds:\n', speeds
            # print 'average speed:\n', average_speed
            # print 'max_speed:\n', self.max_speed
            # print 'utilization:\n', format(utilization, '.20f'), '%'
            print '---------------------------------------------------------------'