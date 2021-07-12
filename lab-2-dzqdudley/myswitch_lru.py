'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
from collections import OrderedDict


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mytable=OrderedDict()
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if mytable.get(eth.src) != None: 
           if fromIface!= mytable[eth.src]:
              mytable[eth.src]=fromIface#update the existing data
        else:#need to add to the table
            if len(mytable)==5:#table is full
                max_idx=mytable.popitem(False)#delete the oldest one
                log_info(f"\033[35mremove:[MAC address:{max_idx[0]} Interface:{max_idx[1]}] is removed\033[0m") 
            mytable[eth.src]=fromIface#add the src to the table
            log_info(f"\033[35mrecord:[MAC address:{eth.src} Age:{0}] is recorded\033[0m")
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if mytable.get(eth.dst) == None or eth.dst == 'ff:ff:ff:ff:ff:ff':
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                mytable.move_to_end(eth.dst,True)#set as the most recently used
                log_info (f"Send packet {packet} to {mytable[eth.dst]}")
                net.send_packet(mytable[eth.dst], packet)
                        
    net.shutdown()
