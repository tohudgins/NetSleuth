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
