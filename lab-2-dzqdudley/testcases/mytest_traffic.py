from switchyard.lib.userlib import *
import time
def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def switch_tests():
    s = TestScenario("switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')#30:00:00:00:00:01 192.168.100.1
    s.add_interface('eth1', '10:00:00:00:00:02')#30:00:00;00:00:02 192.168.100.2
    s.add_interface('eth2', '10:00:00:00:00:03')#30:00:00:00:00:03 192.168.100.3

   # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt("30:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", "192.168.100.1", "255.255.255.255")
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, display=Ethernet), "The Ethernet frame with a broadcast destination address should be forwarded out ports eth1 and eth2")

   # test case 2: a frame with unkown dst should be flooded to all port except ingress
    resppkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:02", '192.168.100.1', '192.168.100.2' )
    s.expect(PacketInputEvent("eth0", resppkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:01 to 30:00:00:00:00:02 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", resppkt,"eth2", resppkt, display=Ethernet), "Ethernet frame destined to 30:00:00:00:00:02 should be flood out eth1 and eth2")
    
    # test case 3: a frame with dst recorded should only be sent to one port
    reqpkt = mk_pkt("30:00:00:00:00:02", "30:00:00:00:00:01", '192.168.100.2','192.168.100.1')
    s.expect(PacketInputEvent("eth1", reqpkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:02 to 30:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "Ethernet frame destined for 30:00:00:00:00:01 should be sent out to eth0 because switch remembers it") 

    resppkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:02", '192.168.100.1', '192.168.100.2', reply=True)
    s.expect(PacketInputEvent("eth0", resppkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:01 to 30:00:00:00:00:02 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", resppkt, display=Ethernet), "Ethernet frame destined to 30:00:00:00:00:02 should be sent out to eth1 because switch remembers it")


   # test case 4: the third port send a packet and the table is updated
    reqpkt = mk_pkt("30:00:00:00:00:03", "30:00:00:00:00:01", '192.168.100.3','192.168.100.1')
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:03 to 30:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", reqpkt,"eth1", reqpkt, display=Ethernet), "Ethernet frame destined for 30:00:00:00:00:01 should be sent out to eth1 and eth0 because before sending the packet, eth2 replaced eth0") 
    

    return s

scenario = switch_tests()