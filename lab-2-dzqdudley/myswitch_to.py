'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mytable={ }
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
        for key in list(mytable):#clear out of date data
            if time.time()-mytable[key][1]>10:
                mytable.pop(key)
        mytable[eth.src]=[fromIface,time.time()]#add the src to the table
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if mytable.get(eth.dst) == None or eth.dst == 'ff:ff:ff:ff:ff:ff':
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                log_info (f"Send packet {packet} to {mytable[eth.dst][0]}")
                net.send_packet(mytable[eth.dst][0], packet)
    net.shutdown()
