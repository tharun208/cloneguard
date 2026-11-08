# Changelog

## v0.1.2

Fixes a detection gap where cloud credential paths built from separate strings were missed.

- **Fixed: split-path cloud credentials were not flagged.** `reads-cloud-credentials` only matched
  paths written as one string (`'.aws/credentials'`). Code such as
  `path.join(os.homedir(), '.aws', 'credentials')` or
  `os.path.join(os.path.expanduser("~"), ".aws", "credentials")` scanned as clean with exit code 0.
  It is now flagged as suspicious (exit 2), the same as the equivalent SSH key paths. This also covers the
  split forms of `.config/gcloud`, `.azure`, `.kube/config` and `.docker/config.json`.
  Thanks to the reviewer who reported it.
- Plain code such as `config.aws.region` is still not flagged.
- **Known limit:** a path split across lines, or assembled from variables, can still be missed.

## v0.1.1

Fixes a detection gap where credential theft over a raw network socket was rated too low.

- **Fixed: stealers using raw sockets were only "suspicious".** A file that reads `~/.ssh/id_rsa` and sends it
  with `net.connect(4444, '203.0.113.7')` (Node) or `socket.create_connection(('203.0.113.7', 4444))` (Python)
  produced a single high finding and exit code 2. The scanner only recognised `http(s)://` addresses as a
  suspicious destination. Such files are now rated **dangerous** (exit 3).
- New rule `connects-by-socket-to-ip` (medium) flags a socket call to a public IP address in Node, Python,
  Go, Rust and Ruby. Loopback and private ranges (127.x, 10.x, 172.16-31.x, 192.168.x) are ignored.
- Socket calls now count as network code for the "reads credentials and can send data out" check.
- **Known limit:** addresses built from parts, SOCKS proxies, DNS-over-HTTPS and hostnames resolved at
  runtime can still get past it.

## v0.1.0

First release: scans a folder or fresh clone for credential theft, suspicious network calls,
download-and-run code, auto-run hooks, obfuscation and checked-in binaries.
