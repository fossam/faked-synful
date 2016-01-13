from scapy.all import *
import argparse

def make_syn_ack(srcip, dstip, sport, dport, seq, ack, verbose = 0):
    '''Creates a SYN ACK packet with magic options'''
    magic_options='\x02\x04\x05\xb4\x01\x01\x04\x02\x01\x03\x03\x05'
    ip=IP(src=srcip, dst=dstip)
    syn=TCP(str(TCP(sport=sport, dport=dport, flags='SA', urgptr=1, seq=seq, ack=ack)) + magic_options)
    packet = Ether()/ip/syn
    return packet

def make_seq_ack(ack, delta = 0xC123E):
    '''Makes tcp.seq/tcp.ack values'''
    if ack < delta:
        return ack, ack + delta
    else:
        return ack, ack - delta

def sniffed_packet(pkt):
    '''Checks if a received packet is has the the right seq-ack delta and replies if it does'''
    if TCP in pkt:

        if pkt[TCP].flags & 0x04:
            pktinfo = "%s:%d - TCP Reset" %(pkt[IP].src, pkt[TCP].sport)
            print pktinfo
            return

        #check SEQ/ACK delta and go from there
        if (pkt[TCP].flags & 0x2 and
           ( ( pkt[TCP].ack - pkt[TCP].seq ) == 0xC123D or
           (   pkt[TCP].seq - pkt[TCP].ack ) == 0xC123D )):
            pktinfo = "Received: %s:%d correct SEQ/ACK delta seq: %08x ack: %08x" %\
                (pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq, pkt[TCP].ack)
            print pktinfo
            seq, ack = make_seq_ack( pkt[TCP].ack )
            #print pkt[TCP].ack, seq, ack
            pkt = make_syn_ack(pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport, seq, ack)
            pktinfo = "Sending Syn-Ack Packet: %s sport: %d dport: %d seq: %08x ack: %08x" %\
                    (pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, seq, ack)
            print pktinfo
            sendp(pkt, iface=iface, verbose=0)

#start
opts = argparse.ArgumentParser()
opts.add_argument("--filter", help="The BPF style filter to sniff with.")
opts.add_argument("--iface", action='store', help="Interface to sniff and send packets")

args = opts.parse_args()

if args.filter:
	filter = args.filter
else:
    filter = "tcp"
    print "Using default BPF filter 'tcp' to catch all SYN packets."

if args.iface:
    iface = args.iface
else:
    print "Using default network interface 'eth0'."
    iface = "eth0"

# Start sniffing some packets
sniff(filter=filter, prn=sniffed_packet, count=0, store=0)
