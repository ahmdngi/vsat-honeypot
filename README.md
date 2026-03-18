# VSAT Honeybot

This repository contains a maritime VSAT administration decoy: a self-contained web UI with synthetic telemetry, fake configuration writes, and request logging intended for controlled honeypot research.

It is intentionally inspired by marine terminal dashboards, but it is not a vendor-exact clone and it does not control real hardware.

## Features

- Read-only dashboard with live-looking RF and vessel telemetry
- Operator login flow that accepts credentials and stores session attempts in local logs
- Fake antenna and network configuration pages with persistent simulated state
- Event log and maintenance console surfaces for interaction capture
- Zero-dependency Perl HTTP server

## Run

```sh
perl server.pl
```

Then open `http://127.0.0.1:8080`.

## Config File

The server now creates [config/honeypot.json](/home/ahmed/maritime/vsat/config/honeypot.json) automatically on first run.

Edit these fields:

- `navigation.mode`: `honeypot` or `scrape`
- `navigation.refreshSeconds`: polling interval
- `navigation.vesseltracker.shipName`: vessel name used to build the Vesseltracker URL
- `navigation.vesseltracker.imo`: IMO number used to build the Vesseltracker URL
- `navigation.vesseltracker.url`: optional explicit URL override

Example `honeypot` config:

```json
{
  "server": {
    "bind": "127.0.0.1",
    "port": 8080
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

Example `scrape` config:

```json
{
  "server": {
    "bind": "127.0.0.1",
    "port": 8080
  },
  "navigation": {
    "mode": "scrape",
    "refreshSeconds": 30,
    "vesseltracker": {
      "shipName": "Megastar",
      "imo": "9773064",
      "url": ""
    }
  }
}
```

Notes for scraper mode:

- It is best-effort and depends on public HTML that may change.
- Some fields on Vesseltracker are gated for logged-in users, so the decoy falls back to local synthetic GPS and motion when fields are missing.
- Public scraping may be subject to the website's terms and anti-bot controls.

## Files

- `server.pl` serves the UI and stores decoy state in `data/state.json`
- `config/honeypot.json` controls the nav mode and optional Vesseltracker target
- `public/` contains the frontend
- `logs/requests.log` captures inbound requests
- `logs/auth.log` captures submitted credentials and accepted sessions

## References

- SAILOR 900 installation manager screen reference: https://www.linksystems-uk.com/wp-content/uploads/support/SAILOR900IM-98-133400-F-var-A-screen.pdf
- SAILOR 900 VSAT Ka product sheet: https://res.cloudinary.com/cobhamsatcom/image/upload/v1646049818/71_147400_A03_SAILOR_900_VSAT_Ka_web_a8ba6ae647.pdf
- SAILOR 900 VSAT Ka product page: https://cobham-satcom.com/product/sailor-900-vsat-ka

## Safety Notes

- Deploy only inside an isolated lab, sinkhole, or controlled deception environment.
- Do not expose this on production management networks.
- The UI accepts writes for research purposes only; all actions remain inside the local decoy state store.
