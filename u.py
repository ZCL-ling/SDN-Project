#coding:utf-8

import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib import hub
from operator import attrgetter
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class Index_Measure(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Index_Measure, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_average_packet = {} #流平均数据包
        self.flow_average_byte = {} #流平均字节数
        self.port_change = {} #端口变化
        self.flow_table_consistency = {} #存储流表一致性
        self.flow_table_consistency_res = {} #存储流表一致性结果
        self.packetin_rate = {} #packet in 速率
        self.transmission_capacity = {} #交换机传输容量
        self.transmission_efficiency = {} #交换机传输效率
        self.start_time = time.time() 
        #问题1：可以把下面的注释掉吧？  
        #self.start_time = 0 
        self.packetin_num = {}
        self.switch_traffic = {}
        self.flow_table = {}
        self.port_nums = {}
        self.sampling_time = 3
        self.monitor_thread = hub.spawn(self._monitor)
        self.show_index_thread = hub.spawn(self._show_index)
        self.write_csv_thread = hub.spawn(self._write_csv)
        file = open("SDN.csv","w")
        file.write("索引,时间戳,交换机,平均包数,平均字节数,端口变化率,流表一致性检测,packet_in速率,传输容量,传输效率\n")
        file.close()
    
    #下发的默认流表
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    #下发流表
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                             priority=priority, match=match,
                             instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                             match=match, instructions=inst)
        datapath.send_msg(mod)

    #获取全部datapath
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


    #mac learning
    def mac_learning(self, datapath, src, in_port):
        self.mac_to_port.setdefault((datapath,datapath.id), {})
        # learn a mac address to avoid FLOOD next time.
        if src in self.mac_to_port[(datapath,datapath.id)]:
            if in_port != self.mac_to_port[(datapath,datapath.id)][src]:
                return False
        else:
            self.mac_to_port[(datapath,datapath.id)][src] = in_port
            return True

    #处理packet in 时间
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #问题2：这里的两个if语句是什么意思？为什么要把LLDP 和 IPV6单独拿出来说？
        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     match = parser.OFPMatch(eth_type=eth.ethertype)
        #     actions = []
        #     self.add_flow(datapath, 10, match, actions)
        #     return

        # if eth.ethertype == ether_types.ETH_TYPE_IPV6:
        #     match = parser.OFPMatch(eth_type=eth.ethertype)
        #     actions = []
        #     self.add_flow(datapath, 10, match, actions)
        #     return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        if dpid not in self.packetin_num.keys():
            self.packetin_num[dpid] = 0
        #计算packet in 数量
        self.packetin_num[dpid]  += 1
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_learning(datapath, src, in_port)

        if dst in self.mac_to_port[(datapath,datapath.id)]:
            out_port = self.mac_to_port[(datapath,datapath.id)][dst]
        else:
            if self.mac_learning(datapath, src, in_port) is False:
                out_port = ofproto.OFPPC_NO_RECV
            else:
                out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                # if ICMP Protocol
                #匹配ICMP协议
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
            
                #  if TCP Protocol
                # 匹配TCP协议
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)#去掉了最后的那个，
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    #不停循环获取流变以及交换机的数据包值
    # _monitor() 方法确保了可以在每sampling_time秒的间隔中，不断地向注册的交换器发送要求以取得统计信息。
    def _monitor(self):
        #问题3：180行和184行的sleep时间，特别是180行这里，代表什么意思？
        hub.sleep(4)
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sampling_time)
 
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #不停循环，获取Flow信息
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        #不停循环，获取交换机端口数据包
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        tmp = 0
        if ev.msg.datapath.id not in self.port_nums.keys():
            self.port_nums[ev.msg.datapath.id] = []
        for stat in body:
            if stat.priority != 1:
                continue
            
            if ev.msg.datapath.id not in self.flow_table_consistency_res.keys():
                self.flow_table_consistency_res[ev.msg.datapath.id] = 0

            if ev.msg.datapath.id not in self.flow_table_consistency.keys():
                self.flow_table_consistency[ev.msg.datapath.id] = {}

            if ev.msg.datapath.id not in self.flow_table.keys():
                self.flow_table[ev.msg.datapath.id] = {}
            #根据不同协议ICMP.TCP进行组装key
            #问题4：key在这里的作用是什么？这里是计算端口数量的吗？10.0.0.4-10.0.0.5-80-100
            if stat.match['ip_proto'] == 1:#ICMP协议
                key = "{}-{}-{}".format(stat.match['ipv4_src'], stat.match['ipv4_dst'],stat.match['ip_proto'])
            elif stat.match['ip_proto'] == 6:#TCP协议
                #计算端口数量
                tmp += 1
                key = "{}-{}-{}-{}".format(stat.match['ipv4_src'], stat.match['ipv4_dst'],stat.match['tcp_src'], stat.match['tcp_dst'])
            if stat.duration_sec == 0:
                duration_sec = 0.00001
            else:
                duration_sec = stat.duration_sec
            if key not in self.flow_table_consistency[ev.msg.datapath.id].keys():
                self.flow_table_consistency[ev.msg.datapath.id][key] = {"ipv4_dst": stat.match['ipv4_dst'], "ipv4_src": stat.match['ipv4_src'], "ip_proto": stat.match['ip_proto'],
                                                   "out_port": stat.instructions[0].actions[0].port}
            else:
                if stat.match['ipv4_src'] not in ["10.0.0.1", "10.0.0.2","10.0.0.3","10.0.0.4","10.0.0.5","10.0.0.6","10.0.0.7"]:
                    continue
                #判断流表是否一致
                if self.flow_table_consistency[ev.msg.datapath.id][key] != {"ipv4_dst": stat.match['ipv4_dst'], "ipv4_src": stat.match['ipv4_src'], "ip_proto": stat.match['ip_proto'],
                                                   "out_port": stat.instructions[0].actions[0].port}:
                    #流表不一致加1
                    self.flow_table_consistency_res[ev.msg.datapath.id] += 1
                    self.flow_table_consistency[ev.msg.datapath.id][key] =  {"ipv4_dst": stat.match['ipv4_dst'], "ipv4_src": stat.match['ipv4_src'], "ip_proto": stat.match['ip_proto'],
                                                   "out_port": stat.instructions[0].actions[0].port}


            #存储最新的流表
            self.flow_table[ev.msg.datapath.id][key] =  {"ipv4_dst": stat.match['ipv4_dst'], "ipv4_src": stat.match['ipv4_src'], "ip_proto": stat.match['ip_proto'],
                                                   "out_port": stat.instructions[0].actions[0].port,
                                                    "packet_count": stat.packet_count, "byte_count": stat.byte_count,
                                                    "duration_sec": duration_sec}
        #问题5：这里存储的时候是dpid,但是昨天修改端口变化率，都改成了key,这个地方不理解
        self.port_nums[ev.msg.datapath.id].append(tmp)
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        rx_count, tx_count = 0, 0 
        if ev.msg.datapath.id not in self.switch_traffic.keys():
                self.switch_traffic[ev.msg.datapath.id] = []

        for stat in sorted(body, key=attrgetter('port_no')):
            #问题6：为什么要加>10000这个限制条件？
            if stat.port_no > 10000:
                continue
            rx_count += stat.rx_bytes
            tx_count += stat.tx_bytes
        #存储最新的交换机的rx tx 的值
        self.switch_traffic[ev.msg.datapath.id].append({"rx_bytes":rx_count, "tx_bytes":tx_count})

    #计算各个参数的值，并且打印输出
    def _show_index(self):
        n = 0
        while True:
            n += 1
            print "================={}=======================".format(str(n))
            self.end_time =  time.time()    
            for dpid, flows in self.flow_table.items():
                packet_rate, byte_rate, num = 0.000001, 0.000001, 0
                for _, flow in flows.items():
                    num += 1
                    packet_rate += flow["packet_count"] / float(flow["duration_sec"])
                    byte_rate += flow["byte_count"] / float(flow["duration_sec"])
                self.flow_average_packet[dpid] = packet_rate/float(num)
                self.flow_average_byte[dpid] = byte_rate/float(num)
            print "平均包数", self.flow_average_packet 
            print "平均字节数",  self.flow_average_byte
            interval_time = self.end_time - self.start_time
            for key in self.port_nums.keys(): 
                if len(self.port_nums[key]) < 2:
                    continue
                #问题7：为什么不除float(self.sampling_time)，-1和-2表示的不是最新的数据和次新的数据嘛？这里为啥除interval_time 
                #port_nums[key]是有的？？明明上面是用tmp计算，251行是， self.port_nums[dpid].append(tmp)
                #329行，port_change[item]
                self.port_change[key] = (self.port_nums[key][-1] -  self.port_nums[key][-2] )  / interval_time
            print "端口变化率", self.port_change

            for dpid, packetin in self.packetin_num.items():
                self.packetin_rate[dpid] = packetin / interval_time
            
            print "packet_in速率", self.packetin_rate

            for dpid in self.switch_traffic.keys():
                if len(self.switch_traffic[dpid]) < 2:
                    continue
                #self.transmission_capacity[dpid] = (self.switch_traffic[dpid][-1]["tx_bytes"] - self.switch_traffic[dpid][-2]["tx_bytes"]) / float(self.sampling_time)
                interval_time = self.end_time - self.start_time
                self.transmission_capacity[dpid] = self.switch_traffic[dpid][-1]["tx_bytes"]  / float(interval_time)
                self.transmission_efficiency[dpid] = self.switch_traffic[dpid][-1]["tx_bytes"] / float(self.switch_traffic[dpid][-1]["rx_bytes"]) 

            print "交换机传输容量", self.transmission_capacity

            print "交换机传输效率", self.transmission_efficiency

            print "流表一致性检测", self.flow_table_consistency_res

            hub.sleep(5)

    def _write_csv(self):
        hub.sleep(20)
        i = 0
        file = open("SDN.csv","a+")
        while True:
            i += 1
            for item in self.datapaths.keys():
                file.write("{},{},{},{},{},{},{},{},{},{}\n".format(
                    str(i),
                    str(time.time()),
                    str(item),
                    str(self.flow_average_packet[item]),
                    str(self.flow_average_byte[item]),
                    str(self.port_change[item]),
                    str(self.flow_table_consistency_res[item]),
                    str(self.packetin_rate[item]),
                    str(self.transmission_capacity[item]),
                    str(self.transmission_efficiency[item])))

            hub.sleep(5)
        file.close()
