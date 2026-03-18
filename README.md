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

Optional environment variables:

- `VSAT_BIND` to change the bind address
- `VSAT_PORT` to change the listen port

## Files

- `server.pl` serves the UI and stores decoy state in `data/state.json`
- `public/` contains the frontend
- `logs/requests.log` captures inbound requests
- `logs/auth.log` captures submitted credentials and accepted sessions

## Safety Notes

- Deploy only inside an isolated lab, sinkhole, or controlled deception environment.
- Do not expose this on production management networks.
- The UI accepts writes for research purposes only; all actions remain inside the local decoy state store.
