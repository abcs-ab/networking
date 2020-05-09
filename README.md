## Python implementation of Ping, Traceroute and SSID scanner.

### Environment:

* Linux (*root privileges*)
* Python 3

### What's inside?

The repository contains implementations of the following networking tools:

* Ping
* Traceroute
* SSID scanner
* ARP requester

All the below frames are written from scratch according to RFC specifications:

* Ethernet
* ARP
* ICMP
* IP
* UDP



### Usage:

All the tools need root privileges to run. **Ping** and **Traceroute** require network settings for **ARP** request to be filled, before they can start working. <br/>These are: `INTERFACE`, `SRC_IP`, `DEST_IP`, `SRC_MAC`<br/>
When it's done, they work in a similar manner to their standard OS counterparts.
* ##### Ping
```bash
sudo python3 ping.py github.com
```

* ##### Traceroute
```bash
sudo python3 traceroute.py github.com
```

* ##### SSID scanner
```bash
sudo python3 ssid_scanner.py wlan0 0.5
```
  SSID scanner takes *interface name* and *time interval* as an input. *Interface* has to be able to work in **`monitor`** mode. <br/>*Time* argument determines how long the script should sniff each channel. 

  IEEE 802.11 frames are examined in order to figure out if there are any **beacon**, **probe requests** or **probe response** frames inside. If so, then such a frame is further processed and SSID info is extracted.

  The script prints out info about **SID**, **BSSID**, **MACs**, **signal**, **channels** and **counter of received packets**. The output is "grouped" by unique packets and contains "Pkts" counter field. It's ready for further analysis and may be helpful in choosing the best channel or just getting insight into surrounding network traffic.
  
  ```shell
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
  ```


### Contact
If you find a bug, typo or have any questions, please feel free to contact me.
#### abcs.luk@gmail.com

### License
[MIT](https://choosealicense.com/licenses/mit/)
