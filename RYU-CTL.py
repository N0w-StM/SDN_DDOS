##############################################
#                                            #
#               @Zinder_AB                   #
#                                            #
##############################################
import pandas as pd
from termcolor import colored as cr
import warnings,collections,time,math
from ryu.lib.packet import packet, ethernet, ipv4, arp,icmp ,tcp, udp
from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.dpid import dpid_to_str
import joblib
import numpy as np


class Controller(RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.atck_ip = []
        self.atck_mac =[]
        self.flow_stats={}
        self.pkt_num={}
        try:
            self.model = joblib.load('MODELS/AL_MOD.pkl')
            self.scaler = joblib.load('MODELS/AL_SC.pkl')
            self.logger.info(cr("[+]FISRT MODEL Loaded",'green','on_grey',['bold']))
            self.det_model = joblib.load('MODELS/NEW_MOD.pkl')
            self.logger.info(cr("[+]SECOND MODEL Loaded",'green','on_grey',['bold']))
        except Exception as e:
            self.logger.error(cr(f"Error loading :{e}",'red','on_grey',['bold']))
            self.model = None
            self.scaler = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info(cr(" --> Handshake with :{}".format(dpid_to_str(datapath.id)),'yellow','on_grey',['bold']))
        self.__add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
            pkt = packet.Packet(msg.data)
            features = self.FIRST_EXT(pkt)
            feats = self.NO_DDOS(pkt)
        except Exception:
            return
        if features is None:
            self.logger.error(cr(" [!!] Failed",'red','on_grey',['bold']))
            return
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arpp = pkt.get_protocol(arp.arp)
        ip_src = ip.src if ip else arpp.src_ip
        ip_dst = ip.dst if ip else arpp.dst_ip
        mac_src = eth_pkt.src
        mac_dst = eth_pkt.dst
        if ip_src in self.atck_ip:
            return
        if eth_pkt.src in self.atck_mac:
            return
        key =(mac_src,mac_dst)
        self.pkt_num[key] = self.pkt_num.get(key, 0) + 1
        cnt = self.pkt_num[key]
        if cnt==40:
            self.pkt_num[key]=0
            try:
                pred = self.anl_pkt_sure(feats)
            except Exception:
                return
        else:
            pred = self.analyze_packet(features)
            self.pkt_num[key]+=1
        
        if pred == 1:
            if ip or eth_pkt:
                if ip_src not in self.atck_ip:
                    t = """                            _,.-------.,_
                        ,;~'             '~;, 
                      ,;                     ;,
                     ;                         ;
                    ,'                         ',
                   ,;                           ;,
                   ; ;      .           .      ; ;
                   | ;   ______       ______   ; | 
                   |  `/~"     ~" . "~     "~\'  |
                   |  ~  ,-~~~^~, | ,~^~~~-,  ~  |
                    |   |        }:{        |   | 
                    |   l   o   / | \   o   !   |
                    .~  (__,.--" .^. "--.,__)  ~. 
                    |     ---;' / | \ `;---     |  
                     \__.       \/^\/       .__/  
                      V| \                 / |V  
                       | |T~\___!___!___/~T| |  
                       | |`IIII_I_I_I_IIII'| |  
                       |  \,III I I I III,/  |  
                        \   `~~~~~~~~~~'    /
                          \   .       .   /
                            \.    ^    ./   
                              ^~~~^~~~^   """
                    self.logger.info(cr(f" [X] Model Prediction Result: {pred}",'white','on_black',['bold','underline']))
                    self.logger.info(cr(f"\n{t}\n",'red','on_grey',['bold','blink']))
                    self.logger.info(cr(f" [!!] DDOS DETECTED FORM {ip_src} TARGETTING {ip_dst},ATTACKER BLOCKED",'cyan','on_grey',['bold']))
                    self.logger.info(cr(f" [X] ATTACKER INFO : \n [*] MAC ==> {eth_pkt.src}\n [*] IP ==> {ip_src}\n [*] SW ==> {dpid_to_str(datapath.id)}\n ",'yellow','on_grey',['bold']))
                    self.atck_ip.append(ip_src)
                    self.atck_mac.append(eth_pkt.src)
                    self.__block_mac_atk(datapath,eth_pkt.src)
                    self.__block_src_ip(datapath,ip_src)
            return
        elif pred == 0:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            if ip or eth_pkt:
                if ip_src not in self.atck_ip:
                    self.logger.info(cr(f" [++]--> NORMAL PACKET RECEIVED FROM : {ip_src}",'green','on_grey',['bold']))
                    self.logger.info(cr(f" [++]--> USING SWITCH : {dpid_to_str(datapath.id)}",'yellow','on_grey',['bold']))
                    self.logger.info(cr(f" [++]--> PACKET SENT TO :{ip_dst}\n",'blue','on_grey',['bold']))
    def calc_flow(self,flow_key,cur_tm):
        flow_data = self.flow_stats[flow_key]
        flow_duration = cur_tm - flow_data['start_time']
        flow_duration_nsec = flow_data['packet_count'] / flow_duration if flow_duration > 0 else 0
        packet_count = flow_data['packet_count']
        byte_count = flow_data['byte_count']
        byte_count_sec = flow_data['byte_count'] / flow_duration if flow_duration > 0 else 0
        brodcast_cnt = flow_data['broadcast_count']
        return flow_duration, flow_duration_nsec,packet_count,byte_count,byte_count_sec,brodcast_cnt

    def upd_flow(self,ip_src,ip_dst,proto,pkt_len,tm_stm):
        flow_key = (ip_src,ip_dst, proto)
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'start_time': tm_stm,
                'packet_count': 0,
                'byte_count': 0,
                'last_packet_time': tm_stm,
                'broadcast_count': 0
            }

        self.flow_stats[flow_key]['packet_count'] += 1
        self.flow_stats[flow_key]['byte_count'] += pkt_len
        self.flow_stats[flow_key]['last_packet_time'] = tm_stm

        if ip_dst == "ff:ff:ff:ff:ff:ff":
            self.flow_stats[flow_key]['broadcast_count'] += 1

    def NO_DDOS(self, pkt):
        try:
            eth = pkt.get_protocol(ethernet.ethernet)
            ip = pkt.get_protocol(ipv4.ipv4)
            time_st = time.time()
            ip_src = ip.src if ip else eth.src
            ip_dst = ip.dst if ip else eth.dst
            tcp_segment = pkt.get_protocol(tcp.tcp)
            udp_segment = pkt.get_protocol(udp.udp)
            tp_src = tcp_segment.src_port if tcp_segment else udp_segment.src_port if udp_segment else 0
            tp_dst = tcp_segment.dst_port if tcp_segment else udp_segment.dst_port if udp_segment else 0
            ethertype = eth.ethertype #1
            opcode = pkt.get_protocol(arp.arp).opcode if pkt.get_protocol(arp.arp) else 1  # 2
            protocol = ip.proto if ip else 1#3
            ttl = ip.ttl if ip else 64#4
            pkt_len = ip.total_length if ip else 80#5
            icm = pkt.get_protocol(icmp.icmp)
            icmp_type = icm.type if icm else 0 #7
            icmp_code = icm.code if icm else 0#8
            seq_num = icm.data.seq if icm else 0#9
            data_len = len(pkt.data)#10
            self.upd_flow(ip_src,ip_dst,protocol,pkt_len,time_st)
            flow_key = (ip_src,ip_dst,protocol)
            flow_duration, flow_duration_sec,packet_count,byte_count,byte_count_sec,brodcast_cnt = self.calc_flow(flow_key,time_st)#11,#12,#13,#14,#15
            flags = tcp_segment.bits if tcp_segment else 0
            FIN_Flag_Cnt = (flags & 0x01)#16
            SYN_Flag_Cnt = (flags & 0x02)#17
            RST_Flag_Cnt = (flags & 0x04)#18
            PSH_Flag_Cnt = (flags & 0x08)#19
            ACK_Flag_Cnt = (flags & 0x10)#20
            URG_Flag_Cnt = (flags & 0x20)#21
            CWE_Flag_Cnt = (flags & 0x40)#22
            ECE_Flag_Cnt = (flags & 0x80)#25
            features =np.array([tp_src,tp_dst,protocol,ttl,opcode,pkt_len,flow_duration,flow_duration_sec,brodcast_cnt,packet_count,byte_count,byte_count_sec,icmp_type,icmp_code,seq_num,data_len,ethertype,FIN_Flag_Cnt,SYN_Flag_Cnt,RST_Flag_Cnt,PSH_Flag_Cnt,ACK_Flag_Cnt,URG_Flag_Cnt,CWE_Flag_Cnt,ECE_Flag_Cnt])
            return features.reshape(1, -1)
        except Exception as e:
            self.logger.error(cr(f"[!!] Error At EXT : {e}",'red','on_grey',['bold']))
            return None
    def FIRST_EXT(self,pkt):
        try:
            eth = pkt.get_protocol(ethernet.ethernet)
            ip = pkt.get_protocol(ipv4.ipv4)
            tcp_segment = pkt.get_protocol(tcp.tcp)
            udp_segment = pkt.get_protocol(udp.udp)
            ip_proto = ip.proto if ip else 0
            tp_src = tcp_segment.src_port if tcp_segment else udp_segment.src_port if udp_segment else 0
            tp_dst = tcp_segment.dst_port if tcp_segment else udp_segment.dst_port if udp_segment else 0
            flow_duration_sec = 1
            flow_duration_nsec = 500000
            idle_timeout = 10
            hard_timeout = 300
            packet_count = 10
            byte_count = 1000
            packet_count_per_second = packet_count / flow_duration_sec
            packet_count_per_nsecond = packet_count / flow_duration_nsec
            byte_count_per_second = byte_count / flow_duration_sec
            byte_count_per_nsecond = byte_count / flow_duration_nsec
            flags = tcp_segment.bits if tcp_segment else 0
            FIN_Flag_Cnt = (flags & 0x01)
            SYN_Flag_Cnt = (flags & 0x02)
            RST_Flag_Cnt = (flags & 0x04)
            PSH_Flag_Cnt = (flags & 0x08)
            ACK_Flag_Cnt = (flags & 0x10)
            URG_Flag_Cnt = (flags & 0x20)
            CWE_Flag_Cnt = (flags & 0x40)
            ECE_Flag_Cnt = (flags & 0x80)
            features =np.array([tp_src,tp_dst,ip_proto,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,packet_count,byte_count,
                packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,
                FIN_Flag_Cnt,SYN_Flag_Cnt,RST_Flag_Cnt,PSH_Flag_Cnt,ACK_Flag_Cnt,URG_Flag_Cnt,CWE_Flag_Cnt,ECE_Flag_Cnt
                ])
            return features.reshape(1, -1)
        except Exception as e:
            self.logger.error("[!!] Error : {e}")
            return None
    def __block_src_ip(self, datapath, src_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []
        flow_mod = parser.OFPFlowMod(datapath=datapath,priority=100,match=match,instructions=[parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)])
        datapath.send_msg(flow_mod)
    def __block_mac_atk(self,datapath,mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac)
        self.logger.info(cr(f" [!!] ATTACKER MAC IS ==> {mac} > BLOCKED",'red','on_grey',['bold']))
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,priority=100,match=match,instructions=inst)
        datapath.send_msg(mod)
    def analyze_packet(self, pack):
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning, module='sklearn.base')
                scaled = self.scaler.transform(pack)
                res = self.model.predict(scaled)
                return res[0]
        except Exception as e:
            self.logger.error(cr(f"[!!] Can't Analyze Packet: {e}",'red','on_grey',['bold']))
            return "error"
    def anl_pkt_sure(self,pck):
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning, module='sklearn.base')
                res =self.det_model.predict(pck)
                return res[0]
        except Exception as e:
            self.logger.error(cr(f"[!!] Can't Analyze Packet: {e}",'red','on_grey',['bold']))
            return "error"
    def __add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        self.logger.info(cr(" ==> Flow-Mod Sent: {}".format(dpid_to_str(datapath.id)),'magenta','on_grey',['bold']))
        datapath.send_msg(mod)

