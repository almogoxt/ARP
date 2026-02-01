import collections
import os
import re
import zlib
from scapy.all import TCP, IP, PcapReader

# Use raw strings for Windows paths to avoid escape character errors
OUTDIR = r'C:\Users\User\Downloads\extracted_images'
PCAPS = r'C:\Users\User\Downloads'
os.makedirs(OUTDIR, exist_ok=True)

Response = collections.namedtuple('Response', ['header', 'payload'])

def get_header(payload):
    try:
        header_end = payload.index(b'\r\n\r\n')
        header_raw = payload[:header_end].decode('utf-8', errors='ignore')
    except ValueError:
        return None
    return dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw))

def extract_content(response):
    header = response.header
    payload = response.payload
    
    try:
        body_start = payload.index(b'\r\n\r\n') + 4
        content = payload[body_start:]
    except ValueError:
        return None, None

    ctype = header.get('Content-Type', '')
    if 'image' not in ctype:
        return None, None
    
    ext = ctype.split('/')[-1].split(';')[0].strip()
    if ext == 'jpeg': ext = 'jpg'

    encoding = header.get('Content-Encoding', '')
    try:
        if encoding == "gzip":
            content = zlib.decompress(content, zlib.MAX_WBITS | 32)
        elif encoding == "deflate":
            content = zlib.decompress(content)
    except Exception:
        return None, None

    return content, ext

class Recapper:
    def __init__(self, fname):
        self.fname = fname
        self.sessions = collections.defaultdict(list)

    def get_responses(self):
        print(f"[*] Streaming {self.fname}...")
        # PcapReader reads one packet at a time
        with PcapReader(self.fname) as reader:
            for pkt in reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                        # Create a session identifier (src_ip, src_port, dst_ip, dst_port)
                        ident = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                        self.sessions[ident].append(pkt)

        print(f"[*] Processing {len(self.sessions)} streams...")
        responses = []
        for ident, packets in self.sessions.items():
            # Sort by sequence number to fix corruption
            packets.sort(key=lambda p: p[TCP].seq)
            payload = b''.join(bytes(p[TCP].payload) for p in packets)

            if b'HTTP/' in payload:
                header = get_header(payload)
                if header:
                    responses.append(Response(header=header, payload=payload))
        return responses

    def write(self, responses):
        count = 0
        for i, resp in enumerate(responses):
            content, ext = extract_content(resp)
            if content:
                fname = os.path.join(OUTDIR, f'visual_{i}.{ext}')
                with open(fname, 'wb') as f:
                    f.write(content)
                print(f"[+] Saved: {fname}")
                count += 1
        print(f"\n[!] Done. Extracted {count} visual files.")

    def live_extract(self, pkt):
        if TCP in pkt and pkt[TCP].payload:
            ident = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            self.sessions[ident].append(pkt)
            
            if b'\r\n\r\n' in bytes(pkt[TCP].payload) or len(self.sessions[ident]) > 100:
                self.process_single_session(ident)

    def process_single_session(self, ident):
        packets = sorted(self.sessions[ident], key=lambda p: p[TCP].seq)
        payload = b''.join(bytes(p[TCP].payload) for p in packets)
        header = get_header(payload)
        if header:
            resp = Response(header=header, payload=payload)
            content, ext = extract_content(resp)
            if content:
                fname = os.path.join(OUTDIR, f'live_{hash(ident)}.{ext}')
                with open(fname, 'wb') as f:
                    f.write(content)
                print(f"[*] Caught image in real-time: {fname}")
        del self.sessions[ident]

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'captured.pcap')
    if os.path.exists(pfile):
        recapper = Recapper(pfile)
        resps = recapper.get_responses()
        recapper.write(resps)
    else:
        print("File not found.")