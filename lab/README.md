# NetSleuth practice lab

A self-contained, **legal** target you control — never point NetSleuth at
machines you don't own or aren't authorized to test.

## Option A — Docker (quick)

```bash
docker compose -f lab/docker-compose.yml up -d
python ../main.py 127.0.0.1 -p 2121,8080
docker compose -f lab/docker-compose.yml down
```

Exposes nginx (HTTP on 8080) and an FTP server (on 2121), both bound to
`127.0.0.1` so nothing is reachable off-host.

## Option B — VirtualBox + Metasploitable

For a richer target, run [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/)
in a **host-only network** in VirtualBox and scan its private IP. Keep it on a
host-only adapter so it is never exposed to the internet.

## Option C — sample malicious captures (no privileges, no network)

The best way to exercise NetSleuth's **detection** is to analyze capture files.
Generate deterministic samples that contain the exact patterns the analyzer
detects — these are crafted packets written to `.pcap` files, **nothing is sent
on the wire**:

```bash
python lab/generate_samples.py        # writes lab/samples/*.pcap
python main.py --pcap lab/samples/port_scan.pcap
python main.py --pcap lab/samples/syn_flood.pcap
python main.py --pcap lab/samples/arp_spoof.pcap   # try --gateway 10.0.0.1
python main.py --pcap lab/samples/icmp_flood.pcap
python main.py --pcap lab/samples/dns_tunnel.pcap
python main.py --pcap lab/samples/beacon.pcap
python main.py --pcap lab/samples/benign.pcap      # should flag nothing
```

### Real-world captures (legal sources)

To run the analyzer over genuine adversarial traffic, download a capture from a
public dataset and pass it to `--pcap`. You are only *reading a file* — no
scanning or capturing of anyone's network:

- **Wireshark SampleCaptures** — <https://wiki.wireshark.org/SampleCaptures>
- **malware-traffic-analysis.net** — real malware PCAPs (with write-ups)
- **CTF / challenge PCAPs** — e.g. from past CTFs and security courses
- **CIC datasets (CICIDS)** — labeled intrusion-detection captures

```bash
python main.py --pcap ~/Downloads/some-capture.pcap --report-dir reports
```
