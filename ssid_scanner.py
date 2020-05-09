#!/usr/bin/env/python3

"""
The script scans a network and returns info about SSID, BSSID, MACs,
signal, channels and counter of received packets. It takes advantage of Linux
networking tools in order to change interface modes and channels.

The output is "grouped by" unique packets and contains "Pkts" counter field.
It's ready for further analysis and may be helpful for choosing the best
channel or just getting insight into surrounding network traffic.

3 types of frames are examined: Beacon, Probe request and Probe response.
While beacon frames are broadcast quite frequently (~10 times per second),
probe frames are less common and depend on direct communication between NIC and AP.

Examining probe frames is useful if we want to learn hidden networks SSID.
Such networks have an empty SSID field in their beacon frames. However, when there's
an active node in such a network, its NIC and AP exchange probe frames where
SSID is apparent.

Output example:
Channel  Src MAC            Dest MAC           BSSID              Signal   Type     Pkts   SSID
8        11:22:33:44:55:66  ff:ff:ff:ff:ff:ff  11:22:33:44:55:66  -54dBm   Beacon   413
8        11:22:33:44:55:66  ff:ff:ff:ff:ff:ff  11:22:33:44:55:66  -57dBm   Beacon   318
8        11:22:33:44:55:66  ff:ff:ff:ff:ff:ff  11:22:33:44:55:66  -61dBm   Beacon   1
8        22:22:22:22:22:22  ff:ff:ff:ff:ff:ff  ff:ff:ff:ff:ff:ff  -36dBm   Preq     2
8        88:88:88:88:88:88  22:22:22:22:22:22  88:88:88:88:88:88  -57dBm   Presp    2      test_ssid
8        88:88:88:88:88:88  ff:ff:ff:ff:ff:ff  88:88:88:88:88:88  -43dBm   Beacon   3      test_ssid
8        88:88:88:88:88:88  ff:ff:ff:ff:ff:ff  88:88:88:88:88:88  -46dBm   Beacon   2      test_ssid
8        88:88:88:88:88:88  ff:ff:ff:ff:ff:ff  88:88:88:88:88:88  -48dBm   Beacon   3      test_ssid

Usage example:
sudo python3 ssid_scanner.py wlan0 0.5

"""

import subprocess
import sys
import re
import socket
from time import time


# Radiotap first 6 masks: TSFT, flags, rate, channel, fhss, dbm_signal.
# The tuple below informs about number of bytes a field occupies when present.
# The script is interested in dbm_signal only, but all the remaining fields can
# be found under this link:
# https://github.com/radiotap/python-radiotap/blob/master/radiotap/radiotap.py

RADIOTAP_BYTES = (8, 1, 1, 4, 2, 1)
FRAMES = {4: "Preq", 5: "Presp", 8: "Beacon"}


def byte_to_mac(byte_string):
    """Takes byte string and converts it into MAC address string."""
    return ':'.join('%02x' % b for b in byte_string)


def flatten_list(alist, howdeep=1):
    """Flattens nested sequences."""
    if howdeep > 0:
        newlist = []
        for nested in alist:
            try:
                newlist.extend(nested)
            except TypeError:
                newlist.append(nested)
        howdeep -= 1
        alist = flatten_list(newlist, howdeep)
    return alist


def print_out(result):
    """Takes dictionary and prints out table-like output with all
    received unique packets and their quantity under the "Pkts" field.
    """
    results = [flatten_list(i) for i in result.items()]
    header = ["Channel", "SSID", "Src MAC", "Dest MAC", "BSSID", "Signal", "Type", "Pkts"]
    print_fmt = '{0:<9}{2:19}{3:<19}{4:<19}{5:<9}{6:<9}{7:<7}{1}'

    print('\n' + print_fmt.format(*header))
    for row in sorted(results):
        print(print_fmt.format(*row))


def do_shell(cmd):
    """Wraps Popen to execute shell commands. Returncode, stdout and stderr are returned."""
    output = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    std_out, std_err = output.communicate()
    if std_err:
        print(std_err.decode())
    return output.returncode, std_out, std_err


class Wlan(object):
    """Changes wlan mode and channel and returns current mode and channel."""
    def __init__(self, iface):
        self.iface = iface

    def get_channels_number(self):
        """Get total number of available channels the interface is able to work on."""
        channels = do_shell(['iwlist', self.iface, 'channel'])[1]
        channels = int(re.search(r'(\d+) chann', str(channels)).group(1))
        return channels

    def set_channel(self, chnl):
        """Set channel."""
        set_chnl = ['iwconfig', self.iface, 'channel', str(chnl)]
        return_code = do_shell(set_chnl)[0]
        if return_code != 0:
            print("Channel {} hasn't been set properly. Script exits.".format(chnl))
            sys.exit(1)
        else:
            print("[+] Interface '{}' set to channel {}. OK.".format(self.iface, chnl))

    def get_iface_mode(self):
        """Extracts interface mode from stdout of 'iwconfig iface' command."""
        check_mode = ['iwconfig', self.iface]
        sout = do_shell(check_mode)[1]
        sout = sout.decode()
        is_mode = re.findall(r'Mode:([-/\w]+\s?[-/\w]+)', sout)
        if not is_mode:
            print("Error: iwconfig mode string extraction failed. Script exits.")
            sys.exit(1)
        return is_mode[0]

    def set_iface_mode(self, mode):
        """Sets interface into specific mode."""
        iface_down = ['ifconfig', self.iface, 'down']
        set_mode = ['iwconfig', self.iface, 'mode', mode]
        iface_up = ['ifconfig', self.iface, 'up']

        do_shell(iface_down)
        do_shell(set_mode)
        do_shell(iface_up)

        current_mode = self.get_iface_mode()
        if current_mode.lower() != mode.strip().lower():
            print(current_mode, mode)
            print("Interface {} hasn't been set to {} mode properly. "
                  "Script exits. Try again.".format(self.iface, mode))
            sys.exit(1)

        print("[+] Interface '{}' in {} mode. OK.".format(self.iface, current_mode))

    @staticmethod
    def switch_net_man(switch):
        """Network-manager start, stop or restart."""
        net_man = ['service', 'network-manager', switch]
        do_shell(net_man)
        print("[+] Network-manager: {}.".format(switch))


def read_frame(pkt, chnl):
    """Radiotap header differs between various NICs. It's injected into the frame and
    depending on its length, correct data bytes have to be computed accordingly.
    """
    rhl = pkt[2]  # Radiotap header length.

    # First byte of IEEE 802.11 carries info about subtype (4 bits), type (2 bits)
    # and a version (2 bits). 3 subtypes will be checked: beacon (8), probe response (5)
    # and probe request (4). Null probe request (subtype 4, type 2) is omitted.
    # That's why the type is expected to be 0.
    pkt_subtype = pkt[rhl] >> 4
    pkt_type = pkt[rhl] >> 2 & 3
    if pkt_type == 0 and pkt_subtype in (8, 5, 4):
        # Location of SSID differs between probe request frame and the other 2 frames.
        if pkt_subtype == 4:
            # Probe request.
            ssid_len = pkt[rhl + 25]
            ssid = pkt[rhl + 26:rhl + 26 + ssid_len]
        else:
            # Beacon and probe resp.
            ssid_len = pkt[rhl + 37]
            ssid = pkt[rhl + 38:rhl + 38 + ssid_len]

        try:
            ssid = ssid.decode('utf-8')
        except UnicodeDecodeError:
            return None

        bssid = byte_to_mac(pkt[rhl + 16:rhl + 22])
        src_haddr = byte_to_mac(pkt[rhl + 10:rhl + 16])
        dest_haddr = byte_to_mac(pkt[rhl + 4:rhl + 10])

        # Checks Radiotap bit indicating if antenna signal info is present.
        # It's 6th bit in radiotap mask first byte.
        is_signal = pkt[4] >> 5 & 1

        # If signal info is present, we need to compute its location, which is related with
        # presence or absence of preceding fields. Sizes of first 6 fields are hardcoded
        # in RADIOTAP_BYTES tuple.
        if is_signal:
            sig_byte = 7 + sum([RADIOTAP_BYTES[i] if pkt[4] >> i & 1 else 0 for i in range(6)])
            # Signal value is negative in a form of signed bin. -63 as 193 (0b11000001) unsigned.
            signal = str(-(256 - pkt[sig_byte])) + 'dBm'
        else:
            signal = 'No data'

        return chnl, ssid, src_haddr, dest_haddr, bssid, signal, FRAMES[pkt_subtype]
    return None


def scan(iface, time_interval):
    """Scans all channels focusing on 3 types of packets: Beacon, probe request and probe response.
    INPUT:  :iface = interface name.
            :time_interval - time in seconds, the scanner is going to spend on each channel.
            For hidden SSID it's recommended to scan for a little longer.

    The script stops network-manager before scanning, since it seems important for smooth capture.
    Otherwise a lot of malformed WLAN frames appear and break the script. It may happen when
    the same NIC is connected with AP in managed mode and then switched to the monitor mode.
    """
    wlan = Wlan(iface)

    # Initial interface mode will be brought back after scan is done.
    initial_mode = wlan.get_iface_mode()

    # Turn off network-manager
    wlan.switch_net_man('stop')

    # Set interface into monitor mode.
    wlan.set_iface_mode('Monitor')
    total_channels = wlan.get_channels_number()

    # Create and bind socket
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0x0003))

    # Scan all channels beginning from channel 1.
    results = dict()
    for chnl in range(1, total_channels + 1):
        wlan.set_channel(chnl)

        # Scan each channel during the given time interval.
        print('[+] Scanning channel: {}'.format(chnl))
        st_time = time()
        while time() < st_time + time_interval:
            try:
                pkt = sock.recv(512)
                sock.settimeout(30)
            except socket.timeout:
                continue

            data_tup = read_frame(pkt, chnl)
            if data_tup:
                results[data_tup] = results.get(data_tup, 0) + 1

    # Bring back initial interface mode and turn on network-manager.
    wlan.set_iface_mode(initial_mode)
    wlan.switch_net_man('start')
    print_out(results)


if __name__ == "__main__":
    try:
        # pylint: disable=unbalanced-tuple-unpacking
        interface, t_interval = sys.argv[1:3]
    except ValueError:
        print('Not enough arguments given. Interface name and time interval needed.\n'
              'Example: SSID_scanner.py wlan0 1.5')
        sys.exit(1)

    try:
        t_interval = float(t_interval)
    except ValueError:
        print("Wrong time interval value: '{}'. A number is expected.".format(t_interval))
        sys.exit(1)

    scan(interface, t_interval)
