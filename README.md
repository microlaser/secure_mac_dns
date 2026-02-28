# 🔒 macOS DNS Privacy Setup

**Stop your Mac from leaking every website you visit — in one command.**

Every time you type a URL, your computer sends a DNS query that translates it to an IP address. By default on macOS, these queries are sent in **plain text** — your ISP, your router, anyone on your network can see every site you look up. This script fixes that.

---

## What it does

It installs and configures a chain of tools that encrypts all your DNS traffic before it leaves your Mac:

```
Your apps  →  dnsmasq (port 53)  →  stubby (port 5300)  →  Quad9 (port 853, TLS encrypted)
```

| Tool | Role |
|---|---|
| **stubby** | Encrypts DNS queries using DNS-over-TLS (DoT) and sends them to Quad9 |
| **dnsmasq** | Sits between macOS and stubby, bridging the system DNS port |
| **pf firewall rules** | Blocks any app from leaking plaintext DNS, even accidentally |
| **Quad9** | A non-profit, privacy-respecting resolver that also blocks malware domains |

Everything is configured to **survive reboots automatically**.

---

## Requirements

- macOS (Apple Silicon or Intel)
- An internet connection
- That's it

---

## Installation

Open **Terminal** (press `⌘ Space`, type `Terminal`, press Enter) and paste this:

```bash
curl -fsSL https://github.com/microlaser/main/setup_dns_privacy.sh -o setup_dns_privacy.sh
sudo bash setup_dns_privacy.sh
```

> You'll be asked for your Mac password. This is normal — the script needs admin access to configure network settings and the firewall.

The script will walk you through each step and tell you exactly what it's doing. A full install takes about 2–5 minutes depending on your internet speed.

---

## What to expect

The script runs through 7 phases and then verifies everything is working:

```
Phase 1 — Checks for Homebrew (installs it if missing)
Phase 2 — Installs stubby and dnsmasq
Phase 3 — Configures stubby (DNS-over-TLS → Quad9)
Phase 4 — Configures dnsmasq (bridges port 53 → stubby)
Phase 5 — Starts both services
Phase 6 — Locks every network interface to the local encrypted resolver
Phase 7 — Installs firewall rules to permanently block plaintext DNS leaks
```

At the end you'll see a summary like this:

```
  ✔ System resolver is 127.0.0.1
  ✔ stubby is running (DNS-over-TLS daemon)
  ✔ dnsmasq is running (local DNS bridge)
  ✔ stubby resolves queries on 127.0.0.1:5300
  ✔ System resolver resolves queries on 127.0.0.1:53
  ✔ Quad9 confirmed as upstream resolver (res121.qdub1.on.quad9.net)
  ✔ Outbound port 853 (DoT) is open to Quad9
  ✔ No plaintext DNS leaks detected on port 53
  ✔ All network interfaces locked to 127.0.0.1
```

**The script is safe to run more than once.** If something goes wrong mid-run, just run it again — every step checks what's already done before changing anything.

---

## Will this slow down my internet?

No. Stubby keeps TLS connections to Quad9 open and reuses them, so after the first query the overhead is negligible. dnsmasq caches up to 1,000 responses locally, so repeated lookups are faster than before.

---

## What is Quad9?

[Quad9](https://quad9.net) (`9.9.9.9`) is a non-profit DNS resolver based in Switzerland, operated by a public benefit organisation. It:

- **Does not log** your personal IP address or sell your data
- **Blocks** known malware and phishing domains automatically
- **Supports** DNS-over-TLS and DNSSEC
- Is used by millions of people as a privacy-first alternative to ISP DNS

---

## Will this affect anything connected to my Mac?

No. This only changes how **your Mac** resolves DNS. It does not affect your router, other devices on your network, or your internet traffic in any other way.

---

## Does this work with a VPN?

It depends on your VPN. Most VPNs push their own DNS settings when you connect, which may override these settings temporarily while the VPN is active (that's normal and expected — your VPN's DNS is handled by the VPN tunnel). When you disconnect, your settings will return to this encrypted configuration automatically.

---

## Uninstalling

To remove everything and return to default macOS DNS:

```bash
# Stop and uninstall services
brew services stop stubby
brew services stop dnsmasq
brew uninstall stubby dnsmasq

# Remove the dnsmasq LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist
sudo rm -f /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist

# Remove the firewall LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.dns-privacy.pf-anchor.plist
sudo rm -f /Library/LaunchDaemons/com.dns-privacy.pf-anchor.plist

# Remove firewall rules
sudo sed -i '' '/dns_privacy/d' /etc/pf.conf
sudo rm -f /etc/pf.anchors/dns_privacy
sudo pfctl -f /etc/pf.conf

# Reset each network interface to DHCP DNS (repeat for each interface name)
sudo networksetup -setdnsservers "Wi-Fi" "Empty"
sudo networksetup -setdnsservers "Thunderbolt Bridge" "Empty"

# Flush DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

---

## Troubleshooting

**DNS stops working after running the script**
```bash
sudo stubby -l          # check stubby for errors
cat /var/log/dnsmasq_err.log   # check dnsmasq for errors
sudo bash setup_dns_privacy.sh  # re-run the script
```

**"Address already in use" error**
Something else grabbed the port before the script could. Running the script again will clear it.

**Brew permission errors**
Make sure you're running `sudo bash setup_dns_privacy.sh` and not `sudo su` first.

**Queries timing out but stubby is running**
Your router or ISP may be blocking outbound port 853. Try rebooting your router. If it persists, open an issue.

---

## How to verify it's working

After installation, you can verify your DNS is going through Quad9 encrypted:

```bash
# Confirm Quad9 is answering your queries
dig +short id.server.on.quad9.net txt

# Confirm no plaintext DNS is leaking (run for 10 seconds, should show nothing)
sudo tcpdump -i any -nn udp port 53 or tcp port 53 2>/dev/null &
sleep 10 && sudo kill %1
```

If the `tcpdump` command produces no output — your DNS is leak-free.

---

## Files installed

| Path | Purpose |
|---|---|
| `/opt/homebrew/etc/stubby/stubby.yml` | stubby configuration |
| `/opt/homebrew/etc/dnsmasq.conf` | dnsmasq configuration |
| `/etc/pf.anchors/dns_privacy` | pf firewall rules |
| `/Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist` | Keeps dnsmasq running on boot |
| `/Library/LaunchDaemons/com.dns-privacy.pf-anchor.plist` | Reloads firewall rules on boot |
| `/var/backups/dns_privacy_*` | Backups of your original settings |

---

## License

MIT — do whatever you want with it.
