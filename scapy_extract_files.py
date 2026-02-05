import collections
import os
import scapy.all as scapy
from scapy.all import TCP, IP, PcapReader

OUTDIR = r'C:\Users\User\Downloads\extracted_print_jobs'
PCAPS = r'C:\Users\User\Downloads'
os.makedirs(OUTDIR, exist_ok=True)

class Recapper:
    def __init__(self, fname):
        self.fname = fname
        self.sessions = collections.defaultdict(list)

    def get_sessions(self):
        print(f"[*] Reading {self.fname}...")
        with PcapReader(self.fname) as reader:
            for pkt in reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    if pkt[TCP].dport == 9100 or pkt[TCP].sport == 9100 or \
                       pkt[TCP].dport == 515 or pkt[TCP].sport == 515:
                        
                        ident = tuple(sorted((pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)))
                        self.sessions[ident].append(pkt)

        print(f"[*] Found {len(self.sessions)} print-related streams.")
        return self.sessions

    def write_jobs(self):
        count = 0
        for ident, packets in self.sessions.items():
            packets.sort(key=lambda p: p[TCP].seq)
            raw_payload = b''.join(bytes(p[TCP].payload) for p in packets)

            if not raw_payload:
                continue

            ext = 'bin'
            if b'%!PS' in raw_payload:
                ext = 'ps'
            elif b'\x1b%-12345X' in raw_payload or b'\x1bE' in raw_payload:
                ext = 'pcl'

            fname = f'job_stream_{count}.{ext}'
            path = os.path.join(OUTDIR, fname)
            
            with open(path, 'wb') as f:
                f.write(raw_payload)
            
            print(f"[+] Extracted {len(raw_payload)} bytes to: {path}")
            count += 1
        
        print(f"\n[!] Done. Extracted {count} print data files.")

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'captured.pcap') 
    
    if os.path.exists(pfile):
        recapper = Recapper(pfile)
        recapper.get_sessions()
        recapper.write_jobs()
    else:
        print(f"[!] File not found: {pfile}")