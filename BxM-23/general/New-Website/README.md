# New Website

## Brief

I made a new site at https://bxmgen2.jonathanw.dev, but my browser gave me this cryptic error code: DNS_PROBE_FINISHED_NXDOMAIN

# Solution

Network steganography with DNS records usually in TXT record
Using dig tools
we can specify dig type for this challenge

```bash
dig bxmgen2.jonathanw.dev txt to revealed the txt record
```

```bash
; <<>> DiG 9.18.1-1ubuntu1.3-Ubuntu <<>> bxmgen2.jonathanw.dev txt
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52756
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;bxmgen2.jonathanw.dev.     IN  TXT

;; ANSWER SECTION:
bxmgen2.jonathanw.dev.  1584    IN  TXT "ctf{w41t_wh4ts_4_txt_r3c0rd}"

;; AUTHORITY SECTION:
jonathanw.dev.      1584    IN  NS  dns2.registrar-servers.com.
jonathanw.dev.      1584    IN  NS  dns1.registrar-servers.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Fri Jun 02 11:41:54 WIB 2023
;; MSG SIZE  rcvd: 150
```

**ctf{w41t_wh4ts_4_txt_r3c0rd}**
