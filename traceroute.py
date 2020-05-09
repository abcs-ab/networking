#!/usr/bin/env/python3

""" Traceroute Python implementation almost from scratch.

Before the script is run, the following constant have to be set:
INTERFACE, SRC_IP, DEST_IP, SRC_MAC

UDP Header according to RFC 768 :

  0      7 8     15 16    23 24    31
   +--------+--------+--------+--------+
   |     Source      |   Destination   |
   |      Port       |      Port       |
   +--------+--------+--------+--------+
   |                 |                 |
   |     Length      |    Checksum     |
   +--------+--------+--------+--------+
   |                                   |
   |          data octets ...          |
   +-----------------------------------+

IP header
  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import socket
import struct
import sys
from time import time
from arp import get_target_mac, mac_to_byte


# Network environment settings for ARP request.
INTERFACE = None  # 'wlan0'
SRC_IP = None  # '192.168.1.192'
DEST_IP = None  # '192.168.1.1'
SRC_MAC = None  # '11:aa:6d:24:01:68'
DEST_MAC = 0 if not INTERFACE else get_target_mac(DEST_IP, SRC_IP, SRC_MAC, INTERFACE)  # ARP req


def get_checksum(data):
    """Checksum for UDP, IP and ICMP packages. The checksum field is the 16-bit
    one's complement of the one's complement sum of all 16-bit words in the header.
    """
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = sum(data[i] << 8 | data[i + 1] for i in range(0, len(data), 2))
    while checksum >> 16:
        # If shifting right by 16 places returns a result other than 0,
        # it means we've got more than 16bit number. So, according to RFC
        # specification we mask only the 16 bits and carry anything what's left
        # by adding it to the result.
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # Finally, switch bits by xoring with 0xffff.
    return checksum ^ 0xffff


def ethernet_construct():
    """Constructs ethernet header"""
    eth_dest_mac = mac_to_byte(DEST_MAC)
    eth_src_mac = mac_to_byte(SRC_MAC)
    eth_type = 0x0800  # IP
    return struct.pack('>6s6sH', eth_dest_mac, eth_src_mac, eth_type)


def udp_construct(src_ip, dest_ip, udp_port=33434, udp_mes=b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'):
    """Returns UDP packet."""
    src_port = 0  # (2B) when it's not used then set to 0.

    # Set non-existent port number to get ICMP(3) - „destination port unreachable” in return.
    dest_port = udp_port  # (2B)
    data = udp_mes
    data_len = len(data)
    udp_len = 8 + data_len  # (2B) Min 8 bytes (header), max 65527 bytes.
    # udp_checksum = 0

    # Udp checksum (2B) not only needs UDP fields, but also requires pseudo header built
    # on parts of IP protocol: source ip, destination ip and protocol id.
    # That's the reason for these 3 fields below, which are not part of UDP, but IP.
    udp_protocol = 17  # (1B) UDP
    src_ip = socket.inet_aton(src_ip)
    dest_ip = socket.inet_aton(dest_ip)

    ip_part = struct.pack('>4s4sBBH', dest_ip, src_ip, 0, udp_protocol, udp_len)
    udp_part = struct.pack('>HHH{}s'.format(data_len), src_port, dest_port, udp_len, data)
    udp_checksum = get_checksum(ip_part + udp_part)

    udp_pkt = struct.pack('>HHHH{}s'.format(data_len),
                          src_port, dest_port, udp_len, udp_checksum, data)
    return udp_pkt


class IpPacket:
    """get_pkt public instance method returns IP packet."""

    def __init__(self, src_ip, target_ip, data_len, proto=17):
        """All IP protocol fields. TTL is passed by the get_pkt method. """
        self.ver = 4  # IPv4 (4 bits field)

        # in 32 bit words. 32 Bit is 4 Bytes, so 20B header length is 20/4 = 5.
        self.head_len = 5  # (4 bits field)

        # Join version and head_len together into 1 byte value.
        self.ver_head_byte = self.ver << 4 | self.head_len
        self.tos = 0  # (1B)
        self.pkt_len = 20 + data_len  # (2B) len of full IP pkt, header + data (UDP in this case)
        self.ident = 0  # (16b)
        self.flags = 0b010  # (3b), unused, DF, MF
        self.offset = 0  # (13b)
        self.flags_offset = (self.flags << 13 | self.offset) & 0xffff
        # self.ttl = 1
        self.proto_id = proto  # (1B) 17 for UDP
        self.ip_checksum = 0  # (2B)
        self.src_ip = socket.inet_aton(src_ip)
        self.dest_ip = socket.inet_aton(target_ip)  # (32b)

    def _ip_struct(self, ttl, chsum):  # ttl is added by this method (1B)
        pkt = struct.pack('>BBHHHBBH4s4s',
                          self.ver_head_byte, self.tos, self.pkt_len, self.ident,
                          self.flags_offset, ttl, self.proto_id, chsum, self.src_ip, self.dest_ip)
        return pkt

    def get_pkt(self, ttl):
        """Packet is constructed twice. For checksum computation and as a final packet."""
        pkt = self._ip_struct(ttl, self.ip_checksum)
        ip_checksum = get_checksum(pkt)
        pkt = self._ip_struct(ttl, ip_checksum)
        return pkt


def traceroute(url, hops):
    """Takes url and number of max ttl (hops parameter).
    Output: ICMP type and code, rtt (ms), hop_time (ms) and route IP as raw address (no DNS name).
    Hop_time returns time between current and previous node. A packet may fly through the network
    via different paths in each run or may wait in a queue for a while.
    That's why hop_time can sometimes take negative value and rtt of the next run can be smaller
    than the previous one.
    """
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind((INTERFACE, 0x800))

    dest_ip = socket.gethostbyname(url)
    print('Traceroute to: %s (%s), %s hops max.\n' % (url, dest_ip, hops))

    ether = ethernet_construct()
    udp = udp_construct(SRC_IP, dest_ip)
    ip = IpPacket(SRC_IP, dest_ip, len(udp))

    last_rtt = 0
    for i in range(1, hops + 1):
        frame = ether + ip.get_pkt(i) + udp
        try:
            start = time()
            sock.send(frame)
            while True:
                resp = sock.recv(1024)
                sock.settimeout(2)
                if resp[23] == 1:  # looking for ICMP packets.
                    break

            rtt = round((time() - start) * 1000, 3)
            hop_time = round(rtt - last_rtt, 3)
            last_rtt = rtt
        except socket.timeout:
            print('{:<2} * * *'.format(i))
            continue

        target_ip = socket.inet_ntoa(resp[26:30])
        icmp_type = resp[34]
        icmp_code = resp[35]

        # TODO DNS resolver for target_ip for more informative output.
        print('{:<2} type/code={}/{}, rtt={:<8} hop_time={:<8} route IP: {}'
              .format(i, icmp_type, icmp_code, rtt, hop_time, target_ip))
        if icmp_type == 3:
            break


if __name__ == "__main__":
    if not (INTERFACE and SRC_IP and DEST_IP and SRC_MAC):
        print("Constant variables have to be set before running the script.\n"
              "These are: INTERFACE, SRC_IP, DEST_IP and SRC_MAC.")
        sys.exit(0)

    traceroute(sys.argv[-1], 20)
