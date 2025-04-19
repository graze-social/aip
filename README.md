ATmosphere Authentication, Identity, and Permission Proxy

# Scratch
http://localhost:8080/internal/api/resolve?subject=ngerakines.me&subject=mattie.thegem.city

1. Install `pdm install`
2. Run migrations `pdm run alembic upgrade head`
3. Populate signing keys: `pdm run aiputil gen-jwk` -> `echo '{"keys":[$OUT]}' > signing_keys.json`
4. Set hostname: `export EXTERNAL_HOSTNAME=grazeaip.tunn.dev`
5. Set plc hostname: `export PLC_HOSTNAME=plc.bowfin-woodpecker.ts.net`
6. Set active signing keys: `export ACTIVE_SIGNING_KEYS='["{KEY_ID}"]'`
7. Start service `pdm run aipserver`
8. Generate a handle: https://pdsdns.bowfin-woodpecker.ts.net
9. Verify resolution: `pdm run resolve --plc-hostname ${PLC_HOSTNAME} enabling-boxer.pyroclastic.cloud`
10. Auth with it: https://grazeaip.tunn.dev/auth/atproto
