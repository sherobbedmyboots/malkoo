#!/bin/bash
# Static map a MAC Address to an IP


echo "Enter host: "
read host_name

echo "Enter MAC Address: "
read mac_addr

echo "Enter IP Address: "
read ip_addr



ssh userone@10.0.0.1

# Enter pass for key


configure

# Edit dhcp-server
edit service dhcp-server shared-network-name LAN subnet 10.0.0.1/24

set static-mapping $host_name mac-address $mac_addr

set static-mapping $host_name ip-address $ip_addr

# Delete

delete  static-mapping $host_name



# Save and exit
commit
save
exit


# type --show configuration all--- to see config

exit
echo "$host_name was mapped to $ip_addr"
