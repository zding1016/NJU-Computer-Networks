#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class Pend:
    def __init__(self, packet, destipaddr, interface, coming_intf):
        self.packet=packet
        self.destipaddr=destipaddr
        self.request_cnt=0#times sending ARP request
        self.time=0#last time sending an ARP request
        self.interface=interface
        self.delete=0
        self.coming_intf=coming_intf
    

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.my_interfaces = net.interfaces()
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.mytable={}#ARP Table
        self.forwarding_table={}
        self.pending_pkts=[]#to be forwarded
        self.to_delete=[]#to be deleted
        self.self_generated_icmp_error=[]#router self-generated icmp error message

    def send_arp_request(self, pend):
        if not self.mytable.get(pend.destipaddr) is None:#dest mac found in the ARP Table
            pend.packet[Ethernet].dst=self.mytable[pend.destipaddr][0]
            log_info (f"\033[35mForward packet {pend.packet} to {pend.destipaddr}\033[0m")
            self.net.send_packet(pend.interface, pend.packet)#send packet directly
            pend.delete=1#found dest mac and sent
        elif time.time()-pend.time>1:
            if pend.request_cnt<5:
                request_need=1
                for item in self.pending_pkts:#check if previous packet sent ARP request already
                    if item==pend:
                        break
                    if item.delete==0 and item.destipaddr==pend.destipaddr:
                        request_need=0
                        break#before pend, arp request for the same destipaddr was sent 
                for item in self.pending_pkts:#check if same dest, already received icmp message
                    if item==pend:
                        break
                    if item.delete==-1 and item.destipaddr==pend.destipaddr:
                        if item.packet[IPv4].src==pend.packet[IPv4].src:
                            pend.delete=-2#directly delete
                        else:
                            pend.delete=-1#need to send icmp message
                        request_need=0
                        break#before pend, arp request for the same destipaddr was sent
                if request_need==1:
                    request_packet=create_ip_arp_request(pend.packet[Ethernet].src, pend.interface.ipaddr, pend.destipaddr)
                    log_info (f"\033[35mSend ARP Request: {request_packet} to {pend.destipaddr}\033[0m")
                    self.net.send_packet(pend.interface,request_packet)
                    pend.time=time.time()
                    pend.request_cnt+=1
            else:
                pend.delete=-1#give up and abort, should send icmp message
                for item in self.pending_pkts:
                    if item==pend:
                        break
                    if item.delete==-1 and item.destipaddr==pend.destipaddr and item.packet[IPv4].src==pend.packet[IPv4].src:
                        #same source, same dest, already received icmp message
                        pend.delete=-2#directly delete
                        break#before pend, arp request for the same destipaddr was sent 
                

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
        #for key in list(self.forwarding_table):
        #    log_info(f"\033[35m{key} {self.forwarding_table[key]}\033[0m")

    def reply_icmp(self, packet, dstintf, coming_intf):#reply to the icmp request to the router
        
        packet[Ethernet].dst=packet[Ethernet].src#may be unnecessary but better to default it
        packet[Ethernet].src=coming_intf.ethaddr#may be unnecessary but better to default it
        packet[Ethernet].ethertype==EtherType.IPv4
        packet[IPv4].dst=packet[IPv4].src
        packet[IPv4].src=dstintf.ipaddr 
        packet[IPv4].ttl=64
        previous=packet.get_header(ICMP)
        reply=ICMP()
        reply.icmptype=ICMPType.EchoReply
        reply.icmpdata.sequence=previous.icmpdata.sequence
        reply.icmpdata.identifier=previous.icmpdata.identifier
        reply.icmpdata.data=previous.icmpdata.data
        index=packet.get_header_index(ICMP)
        packet[index]=reply#construct icmp reply packet
        return packet 

    def error_reply(self, origpkt, type, code, coming_intf):#error report

        log_info(f"\033[35mCreate error reply packet.\033[0m")
        ether=Ethernet()
        ether.src=coming_intf.ethaddr
        ether.dst=origpkt[Ethernet].src 
        ether.ethertype==EtherType.IPv4
        ip=IPv4()
        ip.src=coming_intf.ipaddr
        ip.dst=origpkt[IPv4].src
        ip.protocol=IPProtocol.ICMP
        ip.ttl=64
        i=origpkt.get_header_index(Ethernet)
        if i>=0:
            del origpkt[i]#remove ethernet header
        icmp=ICMP()
        icmp.icmptype=type
        icmp.icmpcode=code
        icmp.icmpdata.data=origpkt.to_bytes()[:28]
        #log_info(f"\033[35merror reply packet created.\033[0m") 
        packet=ether+ip+icmp
        log_info (f"\033[35mError Reply packet {packet} Created.\033[0m")
        return packet

    def forward_packet(self, packet, max_prefix, coming_intf):
        #get next hop ip addr
        log_info (f"\033[35mMax_prefix matches {max_prefix} in Forwarding Table.\033[0m")
        if self.forwarding_table[max_prefix][0] != IPv4Address('0.0.0.0'):
            destipaddr=self.forwarding_table[max_prefix][0]
        elif self.forwarding_table[max_prefix][0] == IPv4Address('0.0.0.0'):#the nex hop is destination
            destipaddr=IPv4Address(packet[IPv4].dst)
        #get interface mac addr to forward the packet
        for intf in self.my_interfaces:
            if self.forwarding_table[max_prefix][1] == intf.name:
                packet[Ethernet].src=intf.ethaddr
                out_interface=intf
                if packet in self.self_generated_icmp_error:
                    packet[IPv4].src=intf.ipaddr
                    self.self_generated_icmp_error.remove(packet)
                break
         
        if not self.mytable.get(destipaddr) is None:#dest mac found in the ARP Table
            packet[Ethernet].dst=self.mytable[destipaddr][0]
            log_info (f"\033[35mForward packet {packet} to {destipaddr}\033[0m")
            self.net.send_packet(out_interface, packet)#send packet directly    
        else:#need to send an ARP request
            log_info (f"\033[35mPacket {packet} Pended.\033[0m")
            self.pending_pkts.append(Pend(packet, destipaddr, out_interface, coming_intf))

    def arp_failure(self, pend):
        log_info(f"\033[35mARP Failure.\033[0m") 
        packet=self.error_reply(pend.packet,ICMPType.DestinationUnreachable,1,pend.coming_intf)
        self.self_generated_icmp_error.append(packet)
        self.handle_packet((0,pend.coming_intf.name,packet))
        return

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        
        for key in list(self.mytable):
             if time.time()-self.mytable[key][1]>100:
                log_info(f"\033[35mremove:[IP address:{key} MAC Address:{self.mytable[key][0]}] is removed\033[0m") 
                self.mytable.pop(key)#clear out of date data of ARP Table     
        eth=packet[Ethernet]
        if eth.ethertype==EtherType.ARP:#ARP packet received 
            arp=packet.get_header(Arp)
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
        
        elif eth.ethertype==EtherType.IPv4:#IPv4 packet received
            for intf in self.my_interfaces:#get the incoming interface
                    if ifaceName == intf.name:
                        coming_intf=intf
                        break
            log_info(f"\033[35mThis is an IPv4 Packet: {packet}, it came from {coming_intf}\033[0m")
            for intf in self.my_interfaces:
                if packet[IPv4].dst == intf.ipaddr:#packet for the router
                    if packet[IPv4].protocol == IPProtocol.ICMP and packet[ICMP].icmptype==ICMPType.EchoRequest:#icmp request
                        log_info (f"\033[35mICMP Request to the router received.\033[0m")
                        packet=self.reply_icmp(packet, intf, coming_intf)#construct icmp reply
                        self.handle_packet((timestamp,coming_intf.name,packet))
                        return
                    else:#not icmp request
                        if coming_intf.ipaddr==packet[IPv4].src:
                            log_info (f"\033[35mRouter sent a packet to itself.\033[0m")
                            return
                        log_info (f"\033[35mPacket to the router received, but it's not ICMP request.\033[0m")
                        packet=self.error_reply(packet,ICMPType.DestinationUnreachable,3, coming_intf)
                        self.self_generated_icmp_error.append(packet)
                        self.handle_packet((timestamp,coming_intf.name,packet))
                        return       
            max_prefix_len=0
            max_prefix=IPv4Network('0.0.0.0/0')
            for key in list(self.forwarding_table):#longest prefix match
                if packet[IPv4].dst in key:#prefix matched
                    if key.prefixlen>max_prefix_len:
                        max_prefix_len=key.prefixlen
                        max_prefix=key
            if max_prefix_len==0:#no matches in the forwarding table
                log_info(f"\033[35mNo matches in the forwarding table.\033[0m") 
                packet=self.error_reply(packet,ICMPType.DestinationUnreachable,0, coming_intf)
                self.self_generated_icmp_error.append(packet)
                self.handle_packet((timestamp,coming_intf.name,packet))
                return
            else:#forwarding table matched
                packet[IPv4].ttl-=1#decrememt ttl
                if packet[IPv4].ttl<=0:#ttl expired
                    log_info (f"\033[35mttl expired.\033[0m")
                    packet=self.error_reply(packet,ICMPType.TimeExceeded,0, coming_intf)
                    self.self_generated_icmp_error.append(packet)
                    self.handle_packet((timestamp,coming_intf.name,packet))
                    return
            self.forward_packet(packet,max_prefix,coming_intf)
            return 
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        self.build_forwarding_table()

        while True:
            for pend in self.pending_pkts:
                self.send_arp_request(pend)#trying sending
                if pend.delete!=0:
                    if pend.delete==-1:#arp failure and need to send icmp message
                        self.arp_failure(pend)
                    self.to_delete.append(pend)
            for pend in self.to_delete:
                self.pending_pkts.remove(pend)
            self.to_delete.clear()
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
