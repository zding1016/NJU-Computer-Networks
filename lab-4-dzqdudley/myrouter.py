#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class Pend:
    def __init__(self, packet, destipaddr, interface):
        self.packet=packet
        self.destipaddr=destipaddr
        self.request_cnt=0#times sending ARP request
        self.time=0#last time sending an ARP request
        self.interface=interface
        self.delete=0
    

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.my_interfaces = net.interfaces()
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.mytable={}#ARP Table
        self.forwarding_table={}
        self.pending_pkts=[]#to be forwarded

    def send_arp_request(self, pend):
        if not self.mytable.get(pend.destipaddr) is None:#dest mac found in the ARP Table
            pend.packet[0].dst=self.mytable[pend.destipaddr][0]
            log_info (f"\033[35mForward packet {pend.packet} to {pend.destipaddr}\033[0m")
            self.net.send_packet(pend.interface, pend.packet)#send packet directly
            pend.delete=1#found dest mac and sent
        elif time.time()-pend.time>1:
            if pend.request_cnt<5:
                request_need=1
                for item in self.pending_pkts:
                    if item!=pend and item.delete==0 and item.destipaddr==pend.destipaddr:
                        request_need=0
                        break
                if request_need==1:
                    request_packet=create_ip_arp_request(pend.packet[0].src, pend.interface.ipaddr, pend.destipaddr)
                    log_info (f"\033[35mSend ARP Request: {request_packet} to {pend.destipaddr}\033[0m")
                    self.net.send_packet(pend.interface,request_packet)
                    pend.time=time.time()
                    pend.request_cnt+=1
            else:
                pend.delete=-1#give up and abort

    def build_forwarding_table(self):
        
        for intf in self.my_interfaces:
            prefix=IPv4Address(int(intf.ipaddr)&int(intf.netmask))
            addr=IPv4Network(str(prefix)+'/'+str(intf.netmask))
            self.forwarding_table[addr]=[IPv4Address('0.0.0.0'), intf.name]
        
        #append items from the .txt
        file=open("forwarding_table.txt")
        line=file.readline()
        while line:
            line=line.strip('\n')#remove '/n'
            elements=line.split(" ")
            addr=IPv4Network(str(elements[0])+'/'+str(elements[1]))
            self.forwarding_table[addr]=[IPv4Address(elements[2]), elements[3]]
            line=file.readline()#pay attention to the types of key and element: string? IPv4Address?

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        
        for key in list(self.mytable):
             if time.time()-self.mytable[key][1]>100:
                log_info(f"\033[35mremove:[IP address:{key} MAC Address:{self.mytable[key][0]}] is removed\033[0m") 
                self.mytable.pop(key)#clear out of date data of ARP Table            
        
        arp=packet.get_header(Arp)
        ipv4=packet.get_header(IPv4)
        
        if not arp is None:#ARP packet received 
            if arp.operation==1: #it is an ARP request
                log_info(f"\033[35mThis is an ARP Request.\033[0m")
                self.mytable[IPv4Address(arp.senderprotoaddr)]=[arp.senderhwaddr,time.time()]#update the table
                log_info(f"\033[35mARP Table record:[IP address:{arp.senderprotoaddr} MAC Address:{arp.senderhwaddr}] is recorded\033[0m")  
                #print(self.mytable)
                for intf in self.my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:#interface matched
                        reply_packet=create_ip_arp_reply(intf.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,
                        arp.senderprotoaddr)
                        log_info (f"\033ARP Reply {reply_packet} to {arp.senderprotoaddr}")
                        self.net.send_packet(ifaceName,reply_packet)
                        break
            else:
                log_info(f"\033[35mThis is an ARP Reply Packet.\033[0m") 
                self.mytable[IPv4Address(arp.senderprotoaddr)]=[arp.senderhwaddr,time.time()]#update the table
                log_info(f"\033[35mARP Table record:[IP address:{arp.senderprotoaddr} MAC Address:{arp.senderhwaddr}] is recorded\033[0m")       
        
        elif not ipv4 is None:#IPv4 packet received

            log_info(f"\033[35mThis is an IPv4 Packet: {packet}\033[0m")
            packet[1].ttl-=1#decrememt ttl
            max_prefix_len=0
            max_prefix=IPv4Address('0.0.0.0')
            ignore_flag=0
            for intf in self.my_interfaces:
                if packet[1].dst == intf.ipaddr:#packet for the router
                    ignore_flag=1
                    break
            for key in list(self.forwarding_table):#longest prefix match
                if packet[1].dst in key:#prefix matched
                    if key.prefixlen>max_prefix_len:
                        max_prefix_len=key.prefixlen
                        max_prefix=key
            if ignore_flag!=1 and max_prefix_len!=0:#prefix matched and packet is not for the router
                #get next hop ip addr
                if self.forwarding_table[max_prefix][0] != IPv4Address('0.0.0.0'):
                    destipaddr=self.forwarding_table[max_prefix][0]
                elif self.forwarding_table[max_prefix][0] == IPv4Address('0.0.0.0'):#the nex hop is destination
                    destipaddr=IPv4Address(packet[1].dst)
                #get interface mac addr to forward the packet
                for intf in self.my_interfaces:
                    if self.forwarding_table[max_prefix][1] == intf.name:
                        packet[0].src=intf.ethaddr
                        out_interface=intf
                        break
                if not self.mytable.get(destipaddr) is None:#dest mac found in the ARP Table
                    packet[0].dst=self.mytable[destipaddr][0]
                    log_info (f"\033[35mForward packet {packet} to {destipaddr}\033[0m")
                    self.net.send_packet(out_interface, packet)#send packet directly    
                else:#need to send an ARP request
                    self.pending_pkts.append(Pend(packet, destipaddr, out_interface))

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        self.build_forwarding_table()

        while True:
            for pend in self.pending_pkts[:]:
                self.send_arp_request(pend)#trying sending
                if pend.delete!=0:
                    self.pending_pkts.remove(pend)
            #located here because of testcase 16
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue#no packet received, directly continue
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
