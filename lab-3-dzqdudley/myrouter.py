#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.my_interfaces = net.interfaces()
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.mytable={}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        log_info (f"\033[36In {self.net.name} received packet {packet} on {ifaceName}\033[0m")
        for key in list(self.mytable):
             if time.time()-self.mytable[key][1]>10:
                log_info(f"\033[35mremove:[IP address:{key} MAC Address:{self.mytable[key][0]}] is removed\033[0m") 
                self.mytable.pop(key)#clear out of date data            
        arp=packet.get_header(Arp)
        if not arp is None:#ARP packet?
            if arp.operation==1: #ARP request?
                self.mytable[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]#update the table
                log_info(f"\033[35mrecord:[IP address:{arp.senderprotoaddr} MAC Address:{arp.senderhwaddr}] is recorded\033[0m") 
                print(self.mytable)
                for intf in self.my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:#interface matched
                        reply_packet=create_ip_arp_reply(intf.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,
                        arp.senderprotoaddr)
                        log_info (f"ARP Reply {reply_packet} to {arp.senderprotoaddr}")
                        self.net.send_packet(ifaceName,reply_packet)
                        break
            else:
                log_info(f"\033[35mThis is an ARP Reply Packet and it is ignored.\033[0m")      
        else:
             log_info(f"\033[35mThis is NOT an ARP Packet and it is ignored.\033[0m") 


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            
            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
