import argparse
import re
import gzip
import io
import base64
from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import PcapReader, TCP, IP
except ImportError:
    raise SystemExit("Scapy is required. Install with: pip install scapy")

def canonical_session(pkt):
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)
    return (a, b) if a <= b else (b, a)

def decode_chunked(b):
    out = bytearray()
    idx = 0
    while True:
        m = re.match(rb"([0-9A-Fa-f]+)\r\n", b[idx:])
        if not m: break
        length = int(m.group(1), 16)
        idx += m.end()
        if length == 0: break
        out += b[idx:idx+length]
        idx += length + 2
    return bytes(out)

def find_http_responses(bytes_data):
    results = []
    idx = 0
    while True:
        m = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[idx:])
        if not m: break
        start = idx + m.start()
        hdr_end = bytes_data.find(b"\r\n\r\n", start)
        if hdr_end == -1: break
        headers_block = bytes_data[start:hdr_end].decode('latin1', errors='replace')
        lines = headers_block.split('\r\n')
        headers = {'status': lines[0]}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        body_start = hdr_end + 4
        if headers.get('transfer-encoding') == 'chunked':
            body = decode_chunked(bytes_data[body_start:])
        elif 'content-length' in headers:
            try:
                body = bytes_data[body_start:body_start+int(headers['content-length'])]
            except:
                body = bytes_data[body_start:]
        else:
            next_http = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[body_start:])
            body = bytes_data[body_start:body_start+next_http.start()] if next_http else bytes_data[body_start:]
        results.append((headers, body))
        idx = body_start + max(1, len(body))
    return results

def carve_files(data, outdir, sess_id):
    # REMOVED: b'MZ' (exe) and b'\x7fELF' (linux)
    signatures = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'%PDF': '.pdf',
        b'\x47\x49\x46\x38': '.gif'
    }
    carved_count = 0
    for sig, ext in signatures.items():
        for match in re.finditer(re.escape(sig), data):
            start = match.start()
            carved_data = data[start:start + 10000000] 
            fname = f"carved_{sess_id}_{carved_count}{ext}"
            with open(Path(outdir) / fname, 'wb') as f:
                f.write(carved_data)
            carved_count += 1
    return carved_count

def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|\?\*]', '_', name)[:200]

def process_and_save(headers, body, outdir, sess_id):
    if headers.get('content-encoding') == 'gzip':
        try: body = gzip.decompress(body)
        except: pass
    
    # REMOVED executable checks here as well
    signatures = {b'\x89PNG': '.png', b'\xff\xd8\xff': '.jpg', b'%PDF': '.pdf', b'\x47\x49\x46\x38': '.gif'}
    ext = '.bin'
    for sig, e in signatures.items():
        if body.startswith(sig): ext = e; break
            
    fname = f"extracted_{sess_id}_{hash(body) % 1000}{ext}"
    path = Path(outdir) / sanitize_filename(fname)
    with open(path, 'wb') as f: f.write(body)
    return path.name

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap'); parser.add_argument('outdir')
    args = parser.parse_args()
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    raw_streams = defaultdict(lambda: {'A->B': [], 'B->A': []})
    
    with PcapReader(args.pcap) as pcap_reader:
        for pkt in pcap_reader:
            if IP in pkt and TCP in pkt and pkt[TCP].payload:
                sess = canonical_session(pkt)
                direction = 'A->B' if (pkt[IP].src, pkt[TCP].sport) == sess[0] else 'B->A'
                raw_streams[sess][direction].append((pkt[TCP].seq, bytes(pkt[TCP].payload)))

    for sess, dirs in raw_streams.items():
        sess_id = sanitize_filename(f"{sess[0][0]}_{sess[0][1]}")
        for dname, chunks in dirs.items():
            if not chunks: continue
            chunks.sort(key=lambda x: x[0])
            min_seq = chunks[0][0]
            max_end = max(s + len(b) for s, b in chunks)
            stream_data = bytearray(max_end - min_seq)
            for seq, b in chunks: stream_data[seq - min_seq:seq - min_seq + len(b)] = b
            
            responses = find_http_responses(bytes(stream_data))
            if responses:
                for h, b in responses: process_and_save(h, b, outdir, sess_id)
            else:
                num = carve_files(bytes(stream_data), outdir, sess_id)
                if num > 0: print(f"Carved {num} files from raw stream {sess_id}")

if __name__ == '__main__':
    main()