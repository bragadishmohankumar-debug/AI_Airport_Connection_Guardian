# AI Airport Connection Guardian — Unified Live Edition

This project combines the feature-rich **Fully Working** airport guardian interface with the live-data/provider architecture from the **Live** project.

## Important

The existing login/register screen is preserved from the Fully Working project. It was not replaced with a different authentication UI.

## Included

- Secure login/register with HTTP-only session cookies and CSRF protection
- Existing airport guardian dashboard, connection setup, airport digital twin and rescue plan
- Animated light professional UI
- Live flight search and flight-status adapter through Aviationstack
- OpenSky live aircraft/airspace data around the configured airport region
- Open-Meteo live weather
- Live WebSocket heartbeat/event stream
- Last-known-data fallback when a provider temporarily fails
- Explicit LIVE / DEMO / cached-provider source labels
- Cross-midnight-safe connection-time calculation
- Explainable connection-risk calculation
- Dynamic indoor route calculation with Dijkstra
- Disruption simulation for testing rescue logic
- Responsive browser/PWA interface
- Provider adapters kept separate from UI/business logic

## Real-data limits

Public free APIs do not provide private airport systems such as airline baggage scans, security queue telemetry, passenger BLE/UWB positioning, gate-control events, or airline rebooking inventory. Those areas remain clearly labelled as digital-twin/demo inputs and are isolated behind replaceable adapters.

## Configure live flights

Create an Aviationstack account and put the API key in `.env`:

```env
AVIATIONSTACK_API_KEY=YOUR_KEY
OPEN_SKY_ENABLED=1
OPEN_METEO_ENABLED=1
REFRESH_SECONDS=60
```

The application never stores the key in frontend JavaScript.

## Run

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000`.

Demo account:

```text
Email: demo@guardian.ai
Password: Guardian@123
```

## Live flow

1. Sign in using the existing login page.
2. Open **Connection Setup**.
3. Search a flight number using **Search live flights**.
4. Select inbound and outbound flights.
5. Start monitoring.
6. Open **Airport Twin** to view the connection route.
7. Dashboard receives live WebSocket heartbeats.
8. OpenSky aircraft observations and Open-Meteo weather are refreshed with the live cycle.
9. Use the transparent control-room scenario only for testing disruption/recovery behavior.

## Production path

For a real airport deployment, connect authorized airport/airline feeds through the provider adapter layer, then replace the demo indoor, baggage and ground-transport adapters without changing the passenger UI.
