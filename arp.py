#!/usr/bin/env/python3

""" Python ARP request implementation.

Ethernet Frame (64 - 1518 bytes):
    1. Ethernet header (6 + 6 + 2 bytes): ('>6s6sH')
        +------------------+--------------------+---------------+
        | Dest MAC address | Source MAC address | Ethernet Type |
        +------------------+--------------------+---------------+
    2. Ether payload (46 - 1500 bytes):
        IP, ARP, etc.
    3 .CRC Checksum (4 bytes).

ARP format (RFC 826): ('>HHBBH6s4s6s4s')
    +-----------------------------------+-------------------------+
    |            Hardware (2B)          |       Protocol (2B)     |
    +-----------------+-----------------+-------------------------+
    | Hardware length | Protocol length |       Opcode (2B)       |
    +-----------------+-----------------+-------------------------+
    |                     Source MAC address                      |
    +-------------------------------------------------------------+
    |                     Source IP address                       |
    +-------------------------------------------------------------+
    |                     Destination MAC address                 |
    +-------------------------------------------------------------+
    |                     Destination IP address                  |
    +-------------------------------------------------------------+
    |                             Data                            |
    +-------------------------------------------------------------+
"""

import socket
import struct
import binascii

BROADCAST = 'ff:ff:ff:ff:ff:ff'


def mac_to_byte(mac_str):
    """Takes hex string, returns byte MAC address."""
    mac = mac_str.replace(':', '')
    mac = binascii.unhexlify(mac)
    return mac


def byte_to_mac(byte_string):
    """Takes byte MAC address, returns hex string."""
    return ':'.join('%02x' % b for b in byte_string)


def get_target_mac(target_ip, src_ip, src_mac, iface):
    """Sends ARP requests, gets ARP response in return."""
    # ETHERNET HEADER
    eth_dest_mac = mac_to_byte(BROADCAST)
    eth_src_mac = mac_to_byte(src_mac)
    eth_type = 0x0806  # ARP 2054, b'\x08\x06'

    # ARP HEADER
    arp_hardware_type = 0x0001  # Ethernet 1 (2 bytes)
    arp_protocol_type = 0x0800  # IPv4 2048 (2 bytes)
    arp_hardware_len = 0x06     # MAC length (1 byte)
    arp_protocol_len = 0x04     # IP length (1 byte)
    arp_opcode = 0x0001         # ARP request 1 (2 bytes)
    arp_source_mac = mac_to_byte(src_mac)
    arp_source_ip = socket.inet_aton(src_ip)
    arp_dest_mac = mac_to_byte(BROADCAST)
    arp_dest_ip = socket.inet_aton(target_ip)

    ethernet = struct.pack('>6s6sH', eth_dest_mac, eth_src_mac, eth_type)
    arp = struct.pack('>HHBBH6s4s6s4s', arp_hardware_type, arp_protocol_type,
                      arp_hardware_len, arp_protocol_len, arp_opcode,
                      arp_source_mac, arp_source_ip, arp_dest_mac, arp_dest_ip)

    packet = ethernet + arp

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)

    sock.bind((iface, 0x0806))
    sock.send(packet)

    r = sock.recv(42)
    unpacked = struct.unpack('>6s6sHHHBBH6s4s6s4s', r)
    return byte_to_mac(unpacked[-4])


if __name__ == "__main__":
    # target_ip, source_ip, source_mac, interface
    target_mac = get_target_mac('192.168.1.1', '192.168.1.192', '11:aa:6d:24:01:68', 'wlan0')
    print(target_mac)
