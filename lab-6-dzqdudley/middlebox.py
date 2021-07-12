#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if randint(0,100)>100*self.dropRate:#should not be dropped
                packet[Ethernet].src=EthAddr("40:00:00:00:00:02")
                packet[Ethernet].dst=EthAddr("20:00:00:00:00:01")
                #log_info (f"\033[35mForward packet {packet} to blastee\033[0m")
                self.net.send_packet("middlebox-eth1", packet)
            else:
                log_info (f"\033[35mDrop packet {packet}\033[0m")
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            packet[Ethernet].src="40:00:00:00:00:01"
            packet[Ethernet].dst="10:00:00:00:00:01"
            self.net.send_packet("middlebox-eth0", packet)
            #log_info (f"\033[35mForward packet {packet} to blaster\033[0m")
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
