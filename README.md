# ATmosphere Authentication, Identity, and Permission Proxy

![Image from 391 Vol 1– 19 by Francis Picabia, https://archive.org/details/391-vol-1-19/page/n98/mode/1up](./aip.png)
## Running Locally
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

## Running via Docker

1. Install `pdm install` (Note that `pdm install` may require `sudo apt install -y clang libpq-dev python3-dev build-essential` to build for postgres requirements!)
2. Populate signing keys: `OUT=$(pdm run aiputil gen-jwk)` and then `echo "{\"keys\":[$OUT]}" > signing_keys.json`
3. Add `EXTERNAL_HOSTNAME: your-host` to the `x-environment` section of the docker compose file[1].
4. Set active signing keys in the `x-environment` section of the docker compose file: `ACTIVE_SIGNING_KEYS='["{KEY_ID}"]'` where `{KEY_ID}` is the `"kid"` value in your generated `signing_keys.json` file.
5. `docker compose up --build`
6. Then navigate to your host at the path /auth/atproto. This is your login page!
7. Note that in the config you can change colors, text, display image, and default post-login destination. You can *also* forward the response to *any* URL with a ?destination={URL} parameter on the sign-in page

[1]: This must match the URL this service is running on. For development purposes, you can install ngrok then run `ngrok http 8080` which will forward traffic on https to a specified ngrok URL. You would then take that host (without https) and put it in your docker compose before starting up.

## How to Use AIP tokens to access ATProto / Bluesky:

Please see this [example usage file in python](https://gist.github.com/DGaffney/99f209e5ff9bb01cc50c4202c9c46554) and port to your use case!
