#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp=IPv4Address(blasteeIp)
        self.num=int(num)
        self.payload_length=int(length)
        self.senderWindow=int(senderWindow)
        self.timeout=float(timeout)/1000.0
        self.recvTimeout=float(recvTimeout)/1000.0
        self.LHS=1
        self.RHS=1
        self.acked=[]#acked 
        self.sent=[]#sent out
        self.time_cnt=time.time()
        self.finished=False#if task finished
        self.reTX=0#number of retransmitted packets
        self.coareseTOs=0#number of coarese time outs
        self.throughput=0
        self.goodput=0
        self.start_time=time.time()
        self.end_time=time.time()
        self.is_retransmitting=False
        self.retransmit_idx=0
        self.pkt_sent_flg=False# if this round has sent pkts



    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        if packet[Ethernet].ethertype!=EtherType.IPv4 or (packet[Ethernet].ethertype==EtherType.IPv4 and packet[IPv4].protocol != IPProtocol.UDP):
            log_info (f"\033[35mIt is not a UDP Packet\033[0m")
            self.handle_no_packet()
            return
        seq_num=int.from_bytes(packet[3].to_bytes()[0:4],"big")
        log_info (f"\033[35mReceive ACK {seq_num} from blastee\033[0m")
        self.acked[seq_num]=1
        if self.LHS==self.num+1:#task finished
            self.finished=True
            self.end_time=time.time()
            return True
        while self.acked[self.LHS]==1:
            if self.LHS+1>self.RHS or self.LHS+1>self.num+1:#make sure LHS is no larger than RHS
                break
            self.LHS+=1
            
            self.time_cnt=time.time()
            log_info (f"\033[35mLHS increased to {self.LHS} and RHS is {self.RHS}\033[0m")
            if self.LHS==self.num+1:#task finished
                break
        if self.LHS==self.num+1:#task finished
            self.finished=True
            self.end_time=time.time()
            return True
        self.handle_no_packet()
        return False

    def create_pkt(self, seq_num): 
        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[Ethernet].ethertype=EtherType.IPv4
        pkt[IPv4].protocol=IPProtocol.UDP
        pkt[IPv4].ttl=64
        pkt[Ethernet].src=EthAddr("10:00:00:00:00:01")
        pkt[Ethernet].dst=EthAddr("40:00:00:00:00:01")
        pkt[IPv4].src=IPv4Address("192.168.100.1")
        pkt[IPv4].dst=self.blasteeIp#IPv4Address("192.168.200.1")
        #pkt[UDP].src=seq_num
        pkt+=seq_num.to_bytes(4,"big")
        pkt+=self.payload_length.to_bytes(2,"big")
        pkt+=(0).to_bytes(self.payload_length,"big")
        return pkt

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        if self.LHS==self.num+1:#task finished
            self.finished=True
            self.end_time=time.time()
            return True
        if self.pkt_sent_flg:
            return False
        # Do other things here and send packet
        if (time.time()-self.time_cnt)>self.timeout and self.is_retransmitting==False:
            #timeout and need to retransmit
            # #start of retransmitting
            log_info (f"\033[35mCoarse time out\033[0m")
            self.coareseTOs+=1
            self.is_retransmitting=True
            self.retransmit_idx=self.LHS-1
            if self.retransmit_idx<self.RHS-1:
                for i in range(self.retransmit_idx+1, self.RHS):#find the foremost yet to ack packet&retransmit
                    self.retransmit_idx=i#the last retransmitted packet's index
                    if i==self.num+1:#the last packet is retransmitted
                        break
                    if self.acked[i]==0:
                        self.reTX+=1
                        log_info (f"\033[35mRetransmit packet with seq_num {i}\033[0m")
                        self.throughput+=self.payload_length
                        self.sent[i]=1
                        self.net.send_packet("blaster-eth0",self.create_pkt(i))#create packet and send
                        self.pkt_sent_flg=True
                        break
                    else:
                        log_info (f"\033[35mPacket with seq_num {i} needn't be retransmitted\033[0m")
            if self.retransmit_idx>=self.RHS-1 or self.retransmit_idx>=self.num:#retransmission finished
                self.is_retransmitting=False

        elif self.is_retransmitting==True:#still retransmitting
            if self.retransmit_idx<self.RHS:
                for i in range(self.retransmit_idx+1, self.RHS):#find the foremost yet to ack packet&retransmit
                    self.retransmit_idx=i#the last retransmitted packet's index
                    if i==self.num+1:#the last packet is retransmitted
                        break
                    if self.acked[i]==0:
                        self.reTX+=1
                        log_info (f"\033[35mRetransmit packet with seq_num {i}\033[0m")
                        self.throughput+=self.payload_length
                        self.sent[i]=1
                        self.retransmit_idx=i#the last retransmitted packet's index
                        self.net.send_packet("blaster-eth0",self.create_pkt(i))#create packet and send
                        self.pkt_sent_flg=True
                        break
                    else:
                        log_info (f"\033[35mPacket with seq_num {i} needn't be retransmitted\033[0m")
            if self.retransmit_idx>=self.RHS-1 or self.retransmit_idx>=self.num:#retransmission finished
                self.is_retransmitting=False
        if self.pkt_sent_flg==False:#can send new packet
            if self.RHS-self.LHS+1<=self.senderWindow and self.RHS<=self.num:
                if self.sent[self.RHS]==0:
                    if self.RHS==1:#start of task
                        self.start_time=time.time()
                    log_info (f"\033[35mTransmit packet with seq_num {self.RHS}\033[0m")
                    self.net.send_packet("blaster-eth0",self.create_pkt(self.RHS))#create packet and send
                    self.throughput+=self.payload_length
                    self.goodput+=self.payload_length
                    self.sent[self.RHS]=1
                    self.pkt_sent_flg=True
                if self.RHS+1-self.LHS<=self.senderWindow and self.RHS+1<=self.num+1:
                    self.RHS+=1
                    log_info (f"\033[35mLHS is {self.LHS} and RHS increased to {self.RHS}\033[0m")
        return False
                    

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        for i in range(self.num+3):
            self.acked.append(0)
        for i in range(self.num+3):
            self.sent.append(0)
        while True:
            self.pkt_sent_flg=False# if this round has sent pkts
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                if self.handle_no_packet():
                    break
                continue
            except Shutdown:
                break
            if self.handle_packet(recv):
                break
        self.shutdown()
        print("Total TX time:",self.end_time-self.start_time)
        print("Number of ReTX:",self.reTX)
        print("Number of Coarse TOs:",self.coareseTOs)
        print("Throughput(Bps):",self.throughput/(self.end_time-self.start_time))
        print("Goodput(Bps):",self.goodput/(self.end_time-self.start_time))
    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
