#!/usr/bin/env/python3

"""Ping implementation in Python. RFC 792

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Identifier

      If code = 0, an identifier to aid in matching request and replies,
      may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching request and
      replies, may be zero.

In this implementation identifier is not set and timestamp is not included in ICMP packet..
"""

import socket
import struct
import sys
from time import time, sleep
from arp import get_target_mac, mac_to_byte
from traceroute import IpPacket, get_checksum


# Network environment settings for ARP request.
INTERFACE = None  # 'wlan0'
SRC_IP = None  # '192.168.1.192'
DEST_IP = None  # '192.168.1.1'
SRC_MAC = None  # '11:aa:6d:24:01:68'
DEST_MAC = 0 if not INTERFACE else get_target_mac(DEST_IP, SRC_IP, SRC_MAC, INTERFACE)  # ARP req


def ethernet_construct():
    """Constructs ethernet header"""
    eth_dest_mac = mac_to_byte(DEST_MAC)
    eth_src_mac = mac_to_byte(SRC_MAC)
    eth_type = 0x0800  # IP
    return struct.pack('>6s6sH', eth_dest_mac, eth_src_mac, eth_type)


def icmp_construct(seq=1):
    """Returns ICMP packet with all required fields.
    However, identifier is not set and timestamp might also be included.
    """
    icmp_type = 8  # (1B) Echo ping
    icmp_code = 0  # (1B)
    icmp_checksum = 0  # (2B)
    icmp_id = 0  # (2B)
    icmp_seq = seq  # (2B)
    icmp_data = b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'

    icmp_fmt = '>BBHHH{}s'.format(len(icmp_data))
    icmp_pkt = struct.pack(icmp_fmt, icmp_type, icmp_code, icmp_checksum,
                           icmp_id, icmp_seq, icmp_data)

    icmp_checksum = get_checksum(icmp_pkt)
    icmp_pkt = struct.pack(icmp_fmt, icmp_type, icmp_code, icmp_checksum,
                           icmp_id, icmp_seq, icmp_data)
    return icmp_pkt


def ping(url):
    """Sends echo request. In response gets echo replay."""
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((INTERFACE, 0x800))

    icmp = icmp_construct()
    ether = ethernet_construct()

    icmp_len = len(icmp)
    dest_ip = socket.gethostbyname(url)
    ip = IpPacket(SRC_IP, dest_ip, icmp_len, 1)  # 1 - protocol ID for ICMP
    ip_pkt = ip.get_pkt(64)

    base_frame = ether + ip_pkt

    seq_num = 1
    for _ in range(100):
        resp = ''
        icmp = icmp_construct(seq_num)
        frame = base_frame + icmp
        try:
            start = time()
            sock.send(frame)
            while True:
                resp = sock.recv(1024)
                sock.settimeout(10)
                if resp[23] == 1:
                    break

            rtt = round((time() - start) * 1000, 3)
        except socket.timeout:
            print('Request timed out.')
            continue

        unpacked = struct.unpack('>6s6sHBBHHBBBBH4s4sBBHHH{}s'.format(icmp_len - 8), resp)
        ip_data_size = unpacked[5] - 20  # size of ip packet - ip header
        seqnum = unpacked[-2]
        src = unpacked[-8]
        src = socket.inet_ntoa(src)

        print('{} bytes from {} ({}): icmp_seq={}, time={}ms'
              .format(ip_data_size, url, src, seqnum, rtt))

        seq_num += 1
        sleep(1)


if __name__ == "__main__":
    if not (INTERFACE and SRC_IP and DEST_IP and SRC_MAC):
        print("Constant variables have to be set before running the script.\n"
              "These are: INTERFACE, SRC_IP, DEST_IP and SRC_MAC.")
        sys.exit(0)

    ping(sys.argv[-1])
