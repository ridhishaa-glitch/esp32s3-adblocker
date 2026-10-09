# ESP32-S3 AdBlock

A network-wide DNS ad/tracker blocker (Pi-hole / AdGuard style) for the
**ESP32-S3 N16R8** (16 MB flash, 8 MB octal PSRAM). It intercepts DNS queries
on your LAN, sinkholes blocked domains, forwards everything else to an upstream
resolver, and ships with a web dashboard.

Inspired by [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock),
reworked for the S3: the compiled blocklist is loaded into **PSRAM** for
microsecond lookups instead of binary-searching flash.

## Features

- **DNS sinkhole** on UDP :53 — answers `0.0.0.0` / `::` (or NXDOMAIN) for
  blocked domains, forwards the rest to your upstream resolver (non-blocking
  proxy with a pending-query table).
- **Subdomain matching** — blocking `doubleclick.net` also blocks
  `ad.doubleclick.net`.
- **In-PSRAM hash table** — sorted 40-bit FNV-1a hashes, packed 5 bytes/entry.
  ~250k domains ≈ 1.2 MB PSRAM; the N16R8 can hold far larger lists.
- **Automatic blocklist updates** — downloads a pre-compiled `.bin` from a URL
  on a schedule (default every 24 h).
- **Custom block / allow lists** — allowlist overrides blocks.
- **Dashboard** — live stats, 24-hour chart, query log, per-client stats,
  top blocked domains, settings, client banning, blocklist refresh, OTA.
- **Captive-portal WiFi setup** — no hardcoded credentials.
- **OTA firmware updates** over WiFi (dual-app partition layout).

## Hardware

- ESP32-S3 **N16R8** DevKitC-1 (or compatible). The `qio_opi` memory type in
  `platformio.ini` assumes **octal** PSRAM (the `R8` variant).
- USB-C cable. The board usually has two USB ports — this config routes
  `Serial` to the **native USB** port (`-DARDUINO_USB_CDC_ON_BOOT=1`). If your
  serial monitor stays blank, either use the other port or set that flag to `0`.

## Build & flash

Uses [PlatformIO](https://platformio.org/).

```bash
# 1. Build and flash the firmware
pio run -t upload

# 2. Watch the serial log
pio device monitor
```

On first boot it creates an open WiFi AP named `ESP32S3-AdBlock-XXXX`.
Connect to it, the captive portal opens, pick your network, enter the password,
and (optionally) a blocklist URL. The device reboots and joins your LAN.

Find it at `http://adblock.local` (mDNS) or at the IP shown in the serial log.

## Point your network at it

Set the device's IP as the **DNS server** either:
- in your **router's DHCP settings** (covers the whole network), or
- on an individual device's network settings (to test first).

## Blocklist

The device loads a pre-compiled binary (`ADBK` format: sorted 40-bit FNV-1a
hashes). Produce one with the included tool:

```bash
pip install -r tools/requirements.txt

# Default sources (StevenBlack hosts + Hagezi light):
python tools/build_blocklist.py -o data/blocklist.bin

# Or your own mix of URLs / local files:
python tools/build_blocklist.py -o data/blocklist.bin \
    https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
    my-extra-domains.txt
```

Supported input formats: hosts files, plain domain lists, and basic
Adblock/AdGuard rules (`||domain^` to block, `@@||domain^` to allow).
Unsupported rules (regex, wildcards, cosmetic `##`) are skipped and counted.

**Getting the `.bin` onto the device — two ways:**

1. **Auto-download (recommended).** Host the `.bin` at a URL and set it in the
   dashboard (*Settings → Blocklist .bin URL*). The included GitHub Action
   (`.github/workflows/build-blocklist.yml`) rebuilds it weekly and publishes
   it to a rolling release — point the device at:
   `https://github.com/<you>/<repo>/releases/download/blocklist-latest/blocklist.bin`
2. **Pre-load over USB.** Put the file at `data/blocklist.bin` and run
   `pio run -t uploadfs`.

## Dashboard API

Read-only (open): `GET /api/stats`, `/api/clients`, `/api/log?n=`, `/api/hist`,
`/api/top?n=`, `/api/config`, `/api/custom?allow=`.

State-changing (HTTP Basic auth + `X-Requested-With` header): `POST /api/config`,
`/api/custom`, `/api/toggle`, `/api/ban`, `/api/update-now`, `/api/reset-stats`,
`/api/reboot`, `/api/forget-wifi`, and `/update` (firmware OTA).

## Security notes

- The dashboard ships with default credentials **`admin` / `admin`** — change
  them in *Settings* immediately. This device sits in the path of every DNS
  query on your network.
- The web UI is plain **HTTP** (no TLS). Basic Auth here is a LAN trust-boundary
  control, not encryption; credentials are sniffable on a shared network.
- Blocklist downloads use HTTPS with certificate validation **disabled**
  (`setInsecure()`), which is a pragmatic choice for a headless LAN device.
- The DNS server answers any client on the LAN — keep it off untrusted networks.

## Project layout

```
platformio.ini              build config (board, PSRAM, partitions, libs)
partitions.csv              16MB: dual 3MB OTA apps + ~10MB LittleFS
src/
  main.cpp                  boot + orchestration
  config.{h,cpp}            NVS-backed settings
  wifi_portal.{h,cpp}       connect / captive-portal setup
  dns_server.{h,cpp}        UDP DNS sinkhole + forwarder
  blocklist.{h,cpp}         PSRAM hash table + custom lists
  stats.{h,cpp}             counters, clients, query log, histogram
  updater.{h,cpp}           scheduled blocklist download
  web_server.{h,cpp}        dashboard + REST API
  web_ui.h                  embedded HTML/JS dashboard
tools/build_blocklist.py    blocklist compiler (-> ADBK .bin)
.github/workflows/          weekly blocklist rebuild
```

## Status

Firmware compiles cleanly (PlatformIO, Arduino-ESP32 3.x). It has **not** yet
been run on hardware — flash it and watch the serial log for first boot.
