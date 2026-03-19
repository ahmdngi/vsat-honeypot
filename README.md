# VSAT Honeypot - SAILOR 900 VSAT Ka Emulation

A maritime VSAT honeypot designed to emulate the Cobham SAILOR 900 VSAT Ka Installation Manager interface for authorized security research and threat intelligence gathering.

**For authorized research purposes only. Deploy in isolated lab environments.**

## Description

This honeypot mimics the SAILOR 900 VSAT Ka terminal web interface, capturing attacker interactions, credentials, and exploration patterns. It is designed to appear authentic to casual scanning and basic fingerprinting attempts.

## Features

- SAILOR 900 VSAT Ka web interface emulation
- Simulated RF telemetry and vessel navigation data
- Login capture with multiple credential sets
- Fake configuration pages that log all changes
- Diagnostic console for command capture
- File upload capture for payload collection
- Zero-dependency Perl HTTP server

## Quick Start

```sh
cd vsat-honeypot
perl server.pl
```

Open `http://127.0.0.1:8080`.

## Default Credentials

The honeypot accepts these credentials (all attempts are logged):

| Username | Password | Access Level |
|----------|----------|--------------|
| admin | 1234 | Administrator |
| service | service | Service |

## Configuration

The server creates `config/honeypot.json` automatically on first run.

Edit these fields:

- `navigation.mode`: `honeypot` or `scrape`
- `navigation.refreshSeconds`: polling interval
- `navigation.vesseltracker.shipName`: vessel name used to build the Vesseltracker URL
- `navigation.vesseltracker.imo`: IMO number used to build the Vesseltracker URL
- `navigation.vesseltracker.url`: optional explicit URL override

Example honeypot config:

```json
{
  "server": {
    "bind": "127.0.0.1",
    "port": 8080,
    "trustProxyHeaders": false,
    "rateLimit": {
      "windowSeconds": 60,
      "maxRequestsPerWindow": 180
    }
  },
  "navigation": {
    "mode": "honeypot",
    "refreshSeconds": 30,
    "vesseltracker": {
      "shipName": "Honeypot",
      "imo": "0000000",
      "url": ""
    }
  }
}
```

Example scrape config:

```json
{
  "server": {
    "bind": "127.0.0.1",
    "port": 8080,
    "trustProxyHeaders": true,
    "rateLimit": {
      "windowSeconds": 60,
      "maxRequestsPerWindow": 120
    }
  },
  "navigation": {
    "mode": "scrape",
    "refreshSeconds": 30,
    "vesseltracker": {
      "shipName": "SHIP_NAME",
      "imo": "IMO_NUMBER",
      "url": ""
    }
  }
}
```

## Logs

- `logs/requests.log` - All HTTP requests with metadata
- `logs/auth.log` - Authentication attempts and sessions
- `data/state.json` - Current simulated device state

## Deployment Notes

- Use behind a reverse proxy for TLS termination
- Isolate in a DMZ or honeypot network segment
- Block outbound internet access from the honeypot host
- Consider using an IP in maritime ASN ranges for realism

## OpSec

The honeypot returns realistic indicators:
- Server header: `Allegro-WebServer/3.2.1` (matches real SAILOR devices)
- Navigation data uses realistic maritime coordinates
- Firmware version matches known SAILOR releases
- Serial numbers follow SAILOR naming conventions

## References

- SAILOR 900 VSAT Ka: https://cobham-satcom.com/product/sailor-900-vsat-ka
- Installation Manager Reference: https://www.linksystems-uk.com/wp-content/uploads/support/SAILOR900IM-98-133400-F-var-A-screen.pdf

## License

See LICENSE file. 
