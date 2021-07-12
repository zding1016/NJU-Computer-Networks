#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp="0.0.0.0",
            num="0"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp=IPv4Address(blasterIp)
        self.num=int(num)
        self.received=[]#packets received

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_info(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}") 
        if packet[Ethernet].ethertype!=EtherType.IPv4 or (packet[Ethernet].ethertype==EtherType.IPv4 and packet[IPv4].protocol != IPProtocol.UDP):
            log_info (f"\033[35mIt is not a UDP Packet\033[0m")
            return
        ack=Ethernet()+IPv4()+UDP()
        ack[Ethernet].ethertype=EtherType.IPv4
        ack[IPv4].protocol=IPProtocol.UDP
        ack[IPv4].ttl=64
        ack[Ethernet].src=EthAddr("20:00:00:00:00:01")
        ack[Ethernet].dst=EthAddr("40:00:00:00:00:02")
        ack[IPv4].src=IPv4Address("192.168.200.1")
        ack[IPv4].dst=self.blasterIp#IPv4Address("192.168.100.1")
        seq_num=int.from_bytes((packet[3].to_bytes()[0:4]),"big")
        #ack[UDP].dst=seq_num
        ack+=(packet[3].to_bytes()[0:4])#set sequence number
        payload=packet[3].to_bytes()[6:]#set payload
        length=int.from_bytes((packet[3].to_bytes()[4:6]),"big")
        if length<8:
            payload+=(0).to_bytes(8-length,"big")
        ack+=payload[0:8]
        log_info (f"\033[35mReceived packet and Send ACK {seq_num} to blaster\033[0m")
        self.net.send_packet("blastee-eth0", ack)
        if self.received[seq_num]==0:
            self.received[seq_num]=1
            self.num-=1


    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        for i in range(self.num+1):
            self.received.append(0)
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            if self.num==0:
                log_info (f"\033[35mAll packets have been received.\033[0m")
                break

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
