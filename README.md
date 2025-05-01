#ATmosphere Authentication, Identity, and Permission Proxy

### Running Locally
http://localhost:8080/internal/api/resolve?subject=ngerakines.me&subject=mattie.thegem.city

1. Install `pdm install` (Note that `pdm install` may require `sudo apt install -y clang libpq-dev python3-dev build-essential` to build for postgres requirements!)
2. Start up a postgres server, `export DATABASE_URL=address` for that server
3. Run migrations `pdm run alembic upgrade head`
4. Populate signing keys: `OUT=$(pdm run aiputil gen-jwk)` and then `echo "{\"keys\":[$OUT]}" > signing_keys.json`

5. Set hostname: `export EXTERNAL_HOSTNAME=grazeaip.tunn.dev`
6. Set plc hostname: `export PLC_HOSTNAME=plc.bowfin-woodpecker.ts.net`
7. Set active signing keys: `export ACTIVE_SIGNING_KEYS='["{KEY_ID}"]'`
8. Start service `pdm run aipserver`
9. Generate a handle: https://pdsdns.bowfin-woodpecker.ts.net
10. Verify resolution: `pdm run resolve --plc-hostname ${PLC_HOSTNAME} enabling-boxer.pyroclastic.cloud`
11. Auth with it: https://grazeaip.tunn.dev/auth/atproto

### Running via Docker

1. Install `pdm install` (Note that `pdm install` may require `sudo apt install -y clang libpq-dev python3-dev build-essential` to build for postgres requirements!)
2. Populate signing keys: `OUT=$(pdm run aiputil gen-jwk)` and then `echo "{\"keys\":[$OUT]}" > signing_keys.json`
3. `docker compose build && docker compose up`
