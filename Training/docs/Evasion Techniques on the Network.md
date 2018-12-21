# Evasion Techniques on the Network 

A user who wishes to evade monitoring will use different techniques to operate over an untrusted network.  To better understand the goals of a user like this, let's look at a diagram of a basic network with security monitoring.  There is a proxy at the gateway inspecting the contents and destinations of external traffic and flows and logging is enabled on the internal switches and routers to gather information about all the systems on the network. 

A normal connection from a user to an external web server looks like this:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image001.png)<br><br>

Here are a few common techniques that can be used to avoid monitoring:

|Technique|Description|
|-|-|
|[Encryption](#encryption)|Used to hide the contents of traffic|
|[Proxy Tunnels](#proxy-tunnels)|Used to hide the true destination of an application's traffic|
|[VPN Tunnels](#vpn-tunnels)|Used to hide the true destination of all traffic|
|[VPN With Cloaking Device](#vpn-with-cloaking-device)|Used to hide the true source of the traffic|

<br>

## Encryption

Encrypted traffic prevents unauthorized parties from accessing the contents of traffic passed over a network.  Using encrypted protocols such as HTTPS and SSH are best practices and are used all over our network, but even when encryption is used, the destinations of the traffic can still be observed:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image002.png)<br><br>

Tunnels can be used to hide the true destination of the traffic.  An encrypted connection is made to an external system which serves as a proxy. Then traffic is tunneled through this encrypted connection in order to access any system on the Internet, for example a web server.  This way the untrusted network sees the proxy server as the destination and cannot see the user's actual destination:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image003.png)<br><br>


## Proxy Tunnels

Capturing traffic to and from a system on the network normally identifies the true destination of the traffic. To demonstrate, fire up the REMnux VM (or any VM), put it in bridged mode, and visit www.example.com while capturing traffic on the host machine using Wireshark.  

You can see the DNS request followed by the TCP handshake and the GET request for `/`:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image004.png)<br><br>

Same thing with HTTPS---but since it's encrypted, you can't see the requested page or passed parameters.  Still, the IP address of the actual destination can be identified as `93.184.216.34`:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image005.png)<br><br>

Now we will use a proxy tunnel to visit the same site while hiding the actual destination of our traffic.  When monitoring the network, the actual destination appears to be the proxy when in reality it is just a hop point.

Stand up an EC2 from Amazon or any other provider and connect to it via SSH:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image006.png)<br><br>

This creates an encrypted SSH connection to the proxy:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image007.png)<br><br>


We will use this host as a proxy to evade monitoring on the network.

First let's look at two types of port forwarding:

- [SSH Local Port Forwarding](#ssh-local-port-forwarding)
- [SSH Dynamic Port Forwarding](#ssh-dynamic-port-forwarding)

### SSH Local Port Forwarding

An SSH connection can be used to map a local port to any system and port the SSH Server host can reach.  Log in to the EC2 server again and this time use the following to establish local port forwarding: 

```
ssh ubuntu@54.88.199.37 -L 8080:93.184.216.34:80
```

Now all traffic sent to local port 8080 will be forwarded through the SSH connection to the proxy Server and on to 93.184.216.34 (www.example.com) on port 80:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image008.png)<br><br>

So we can send an HTTP request specifying the host and page to our local machine on port 8080 and get back an HTTP response containing the contents of the webpage at www.example.com:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image009.png)<br><br>

Watching this traffic from the network shows only an SSH connection to the proxy server.

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image010.png)<br><br>



### SSH Dynamic Port Forwarding

An SSH connection can also be used to create a SOCKS proxy which will allow applications to use the local port to connect to any system and port from the proxy server. 

The following command creates an SSH connection with the proxy server using dynamic port forwarding with compression enabled:

```
ssh ubuntu@54.88.199.37 -D 9090
```

Now all traffic sent to local port 9090 will be forwarded through the SSH connection to the proxy and on to any arbitrary IP address and port:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image011.png)<br><br>

First test the tunnel out from the command line with `curl --socks5 localhost:9090 http://www.example.com`:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image012.png)<br><br>

You should see the DNS request go to the router (192.168.2.254) and the web traffic go through the SSH tunnel to the proxy (54.88.199.37):

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image013.png)<br><br>

To set up browsing through this tunnel, go to `Preferences` --> `Network Proxy` --> `Settings` to configure Firefox to use port 9090 as a SOCKS5 proxy:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image014.png)<br><br>

At the bottom, check the box that will include DNS queries:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image015.png)<br><br>

After the connection settings are changed, browse to www.example.com and watch in Wireshark as all DNS queries and web requests/responses are tunneled through the SSH connection to the proxy server:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image016.png)<br><br>

We can see the IP of the user (192.168.2.92) and the IP of the external server used for tunneling (54.88.199.37), but not the true destination of the traffic which is www.example.com (93.184.216.34).

VPN tunnels are used to ensure all applications behave this way.

## VPN Tunnels

When a VPN tunnel is used, a network interface is created on the local machine that is bridged to the interface on the external server.  This allows the local machine to send and receive all external traffic through the VPN tunnel:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image017.png)<br><br>

There are several types of VPNs:

- [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol) - Uses GRE protocol and UDP port 1723, Encryption is not strong
- [L2TP/IPSec](https://en.wikipedia.org/wiki/IPsec) - Uses UDP ports 50, 500, 1701, and 4500, more secure than PPTP
- [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN) - Open source, uses any port, 443/tcp blends in with HTTPS

We'll use [WireGuard](https://github.com/WireGuard/WireGuard) and run it over port 443 for this example using the following steps:

- [Configure VPN Server](#configure-vpn-server)
- [Configure VPN Client](#configure-vpn-client)
- [Harden the VPN Tunnel](#harden-the-vpn-tunnel)


### Configure VPN Server

On the EC2 instance, do the following:

1. **Install Wireguard**

```
sudo add-apt-repository ppa:wireguard/wireguard
sudo apt-get update
sudo apt-get install wireguard-dkms wireguard-tools linux-headers-$(uname -r)
```

2. **Generate Server and Client Keys**

```
umask 077
wg genkey | tee server_private_key | wg pubkey > server_public_key
wg genkey | tee client_private_key | wg pubkey > client_public_key
```

3. **Create a Configuration File**

```
sudo nano /etc/wireguard/wg0.conf

# Add the following to the file:
[Interface]
Address = 10.10.10.1/24
PrivateKey = <server_private_key>
ListenPort = 443

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.10.10.2/32
```

4. **Enable IP Forwarding**

```
sudo sed -i 's/#net.ipv4.ip_for/net.ipv4.ip_for/g' /etc/sysctl.conf
sysctl -p
echo 1 | sudo tee --append /proc/sys/net/ipv4/ip_forward
```

5. **Configure Iptables**

```
# These commands will create rules to accept and forward traffic from the VPN client and make them persistent across reboots with iptables-persistent

sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A INPUT -s 10.10.10.0/24 -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A INPUT -s 10.10.10.0/24 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
sudo apt-get install iptables-persistent
sudo systemctl enable netfilter-persistent
sudo netfilter-persistent save
```


6. **Configure DNS**

```
sudo apt-get install unbound ubound-host
curl -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache


# Edit /etc/unbound/unbound.conf and make it look like the following:

server:
  num-threads: 4
  verbosity: 1
  root-hints: "/var/lib/unbound/root.hints"
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  interface: 0.0.0.0
  max-udp-size: 3072
  access-control: 0.0.0.0/0             refuse
  access-control: 127.0.0.1             allow
  access-control: 10.10.10.0/24         allow
  private-address: 10.10.10.0/24
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-referral-path: yes
  unwanted-reply-threshold: 10000000
  val-log-level: 1
  cache-min-ttl: 1800 
  cache-max-ttl: 14400
  prefetch: yes
  prefetch-key: yes
```

```
# Set permissions and enable

sudo chown -R unbound:unbound /var/lib/unbound
sudo systemctl enable unbound
```

7. **Enable WireGuard Interface**

```
# Enable the VPN server interface wg0 and configure it to start on boot

sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0.service
```

You should now have a new `wg0` interface which you can confirm is up and running with `ifconfig`.

*NOTE: You will most likely need to add a rule to allow UDP traffic to port 443 on the EC2 server*

### Configure VPN Client

Download a Linux image---Ubuntu [from here](https://www.osboxes.org/ubuntu) for example. Stand up a VM with it and run the following commands to make it a WireGuard VPN client:

1. **Install Wireguard**

```
sudo add-apt-repository ppa:wireguard/wireguard
sudo apt-get update
sudo apt-get install wireguard-dkms wireguard-tools linux-headers-$(uname -r)
```

2. **Create a Configuration File**

```
sudo nano /etc/wireguard/wg0-client.conf

# Enter the following:
[Interface]
Address = 10.10.10.2/32
PrivateKey = <insert client_private_key>
DNS = 10.10.10.1

[Peer]
PublicKey = <insert server_public_key>
Endpoint = 54.88.199.37:443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
```

3. **Enable WireGuard Interface**

```
sudo wg-quick up wg0-client
```

You should now have a new `wg0-client` interface which you can confirm is up and running with `ifconfig`.  Once this interface is up, all pings, DNS requests, and web traffic should go through the tunnel.  



### Test VPN Tunnel Operation

Fire up Wireshark and watch the traffic on the host interface your VM is bridged to (`eth0` in this example).  Verify the tunnel is operational by making a DNS query for www.example.com from the VPN client. When you do this, you should only see traffic to the VPN server (54.88.199.37) and the DNS request should get resolved by the VPN Server 10.10.10.1:

```
nslookup www.example.com

# Server:	10.10.10.1
# Address:	10.10.10.1#53
#
# Non-authoritive answer:
# Name:		www.example.com
# Address:	93.184.216.34
```

Now try the following on the VPN client: 

- Install [curl](https://curl.haxx.se/) with `sudo apt-get install curl`.  You should only see UDP traffic to the VPN server on port 443.
- Type `curl ifconfig.co`. You should get back the IP address of your VPN server.
- Type `traceroute www.google.com`. Your first hop should be the VPN server (10.10.10.1) instead of the gateway router of the local network (192.168.2.254).
- Watch in Wireshark as you open a browser and visit several different web pages.  You should see nothing but UDP traffic to the VPN server on port 443.


<br>

To see if any traffic is not being routed through the VPN, use the Wireshark filter `!(ip.addr == 54.88.199.37)`. You may find:

- ipv4 traffic to and from the host---if any ipv4 traffic is not tunneled, it will be visible on the network
- ipv6 traffic to and from the host---if ipv6 is not disabled or tunneled, it will be visible on the network
- ARP traffic to and from the host---this is necessary for the system to route packets on the local network

Fixes for the ipv4/ipv6 leakage could include changing DNS configurations, disabling ipv6, or implementing iptables rules to block all IP traffic not destined for `54.88.199.37`.

Once this is complete, you can use the browser on that host to visit any page on the Internet and the only destination address that can be identified by capturing the traffic is the VPN server (54.88.199.37).  With this in place, we cannot see the destination or content of the traffic, but we can still interact with the user's device.  This changes when a cloaking device is used...

## VPN With Cloaking Device

A cloaking device is a system, usually Linux, that sits between a user's system and the network's router acting as both a VPN client and a router.  This allows a user to only connect their system to the cloaking device (via Ethernet, wireless, USB, etc.) creating a trusted, unmonitored network.  

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image000.png)<br><br>

In this scenario, all monitoring tools and systems on the untrusted network are unable to interact directly with the user's system.  They are only able to see and gather information about the cloaking device which is specifically designed to hide information about the systems behind it. 

All the user's traffic is sent to the cloaking device which sends it through the VPN tunnel to the VPN Server which passes it on to its true destination. Return traffic takes the same path back, through the VPN tunnel to the cloaking device, and back to the user's system over the trusted network. 

To simulate this, we need to:

- [Stand Up A Trusted Network](#stand-up-a-trusted-network)
- [Configure Cloaking Device](#configure-cloaking-device)
- [Route Traffic Through VPN Tunnel](#route-traffic-through-vpn-tunnel)

### Stand Up A Trusted Network

This is usually performed by joining a private Wireless network or connecting directly via USB or Ethernet.  Here we'll simulate by creating a virtual private network with VirtualBox.

On the host machine, type:

```
vboxmanage dhcpserver add --netname intnet --ip 10.2.0.1 --netmask 255.255.0.0 --lowerip 10.2.2.2 --upperip 10.2.2.255 --enable
```
This creates a virtual network named `intnet` which we can use to connect our user's device (Windows host) to our cloaking device (the Linux VPN Client).

Power down the Linux box, go to Settings --> Network and set up Adapter 2 to attach to the intnet network:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image022.png)<br><br>

Do the same for the Windows box you're going to use.

When you bring up the Windows box, it should already have acquired an IP address on that interface:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image023.png)<br><br>

On the Linux host, you need to add a line to `/etc/network/interfaces` before typing `ifup eth1` to acquire an IP address.

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image024.png)<br><br>

Once both interfaces are up, ping the Linux host from the Windows host to ensure you have connectivity:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image025.png)<br><br>


### Configure Cloaking Device

Many times this is a small Linux device such as a [Raspberry Pi](https://www.raspberrypi.org/products/raspberry-pi-3-model-b/) or [ODROID-C2](https://wiki.odroid.com/odroid-c2/odroid-c2) designed to host one or more clients on a trusted network, connect to an untrusted network, establish a VPN tunnel, and route all traffic from its clients through the VPN tunnel.

The following steps are required:

- Set up DNS/DHCP
- Set up IP Forwarding/NAT
- Set up VPN Client 

<br>

**Set up DNS/DHCP**

We would normally use `dnsmasq` for both DHCP and DNS but since Virtualbox is handing out addresses in this example, we only need to use it for DNS.

Use the following to install and start `dnsmasq`:

```
sudo apt-get install dnsmasq
sudo service dnsmasq start
```

Do a DNS lookup using localhost to test:

```
nslookup www.example.com localhost

# Server: localhost
# Address:  ::1#53
#
# Non-authoritive answer:
# Name:   www.example.com
# Address:  93.184.216.34
```

Make sure the Windows host can use it to resolve names as well:

```
nslookup www.example.com 10.2.2.2

# Server: UnKnown
# Address:  10.2.2.2
#
# Non-authoritive answer:
# Name:   www.example.com
# Address:  2606:2800:220:1:248:1893:25c8:1946
            93.184.216.34
```


**Set up IP Forwarding/NAT**

The following enables IP forwarding, creates forwarding rules, and makes them persistent:

```
# Enable forwarding
sed -i 's/#net.ipv4.ip_for/net.ipv4.ip_for/g' /etc/sysctl.conf
sudo sysctl -p
echo 1 | sudo tee --append /proc/sys/net/ipv4/ip_forward

# Create rules
sudo iptables -t nat -A POSTROUTING -o wg0-client -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o wg0-client -j ACCEPT
sudo iptables -A FORWARD -i wg0-client -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Make persistent
sudo apt-get install iptables-persistent
sudo systemctl enable netfilter-persistent
sudo netfilter-persistent save
```

**Set up VPN Client**

This is where we would download and install WireGuard, create a configuration file pointing to our VPN server, and enable the WireGuard interface using the steps described above in [Configure VPN Client](#configure-vpn-client).

You should now have a new `wg0-client` interface which you can confirm is up and running with `ifconfig`.  Once this interface is up, all pings, DNS requests, and web traffic should go through the tunnel.

### Route Traffic Through VPN Tunnel

Now, with the VPN client operational and a trusted network in place, we just need to route all traffic from the Windows host through the VPN tunnel.

Do the following to configure the cloaking device as the Default Gateway and the VPN Server as the DNS Server for the Windows host:

```
# Disable adapter one
netsh interface set interface "Ethernet" disable

# Set IP address and default gateway
netsh interface ip set address "Ethernet 2" static 10.2.2.3 255.255.255.0 10.2.2.2

# Set DNS server
netsh interface ip set dns "Ethernet 2" static 10.10.10.1
```

You should now be tunneling all Windows system traffic through the VPN tunnel via the cloaking device.

To test, open Wireshark on the host running VirtualBox and capture traffic on the interface the cloaking device is bridged to---(`eth0` in this example).  First filter for DNS traffic with `dns` and make a DNS query.  Then try without the filter to see all the traffic that hits the network when a DNS request is made from the Windows host:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image026.png)<br><br>

The VPN server (10.10.10.1) responds and no DNS traffic was observed on the network, only UDP traffic to and from the cloaking device and 54.88.199.37:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image027.png)<br><br>

Now perform another test by filtering for HTTP using `http`, making a web request, and watching the network.  Then make the same request and watch using Wireshark without any filters applied. You should see similar behavior:

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image028.png)<br><br>

The page contents are received but no HTTP traffic was observed on the network, only UDP traffic to and from the VPN server from the cloaking device.

![](images/Evasion%20Techniques%20Used%20on%20the%20Network/image029.png)<br><br>

So with this setup in place, the Windows host can talk to any host on the web using any protocol and all that can be observed on the network is encrypted 443/udp traffic between an unknown device and a VPN server. 

## Summary

Combining a VPN tunnel with a cloaking device presents several problems for network montoring:

- Encryption - Cannot see contents of traffic
- VPN/Proxy - Cannot see true destinations of traffic
- Cloaking Device - Cannot see true sources of traffic

With this in mind, we now have an idea of what to look for when monitoring the network for these techniques being used:

- Hosts creating large amounts of traffic with little or no DNS requests 
- Hosts that make the majority of connections to one or several external servers on specific ports
- Hosts that are using protocols that are unusual for the ports being used (UDP on 443 in this example)
- Hosts having little or no listening ports and services