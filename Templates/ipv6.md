| |Ipv4|Ipv6|
|-|-|-|
|Loopback|127.0.0.1|::1/128|
|LinkLocal|169.254.0.0/16|fe80::/10|
|Global Unicast|Any routable addr|2000::3, 3000::|
|Ipv4-Mapped|N/A|::ffff/96|
|Ipv6 to Ipv4|N/A|2002::/16|
|Documentation   198.18.0.0/15|2001:0db8::/32|
|Multicast|224.0.0.0/4|ff00::8|
|Teredo|N/A|2001:0000::/32|
|Private|10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16|fc00::/7|
|IP Header Length|20+ bytes|40 bytes|
|IP Addr Length|32 bits|128 bits|
||TTL|Hop|
||Type of Service|Traffic class|
||Protocol|Next Header|
||No checksums|
|ICMP NH Value|1|58|
|Unreachable|type 1|type 3|
|Echo request|type 8|type 128|
|Echo reply|type 0|type 129|
|Router solicit|type 130|
|Router advertise|type 131|
|Router solicit|DHCP|type 133 to ff02::2 all routers|
|Router Adver|DHCP|type 134|to ff02::1 all hosts|
|Neighbor Solicit|ARP req|type 135 to ff02::1 all hosts|
|Neighbor Adver|ARP reply|type 136 to neighbor|