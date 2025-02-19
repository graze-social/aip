import argparse
import asyncio
import logging
from typing import Any, Dict, Optional
import aiohttp
from jwcrypto import jwk
from ulid import ULID
import base64
from cryptography.fernet import Fernet

from social.graze.aip.resolve.handle import resolve_subject

logger = logging.getLogger(__name__)


async def genAppPassword(
    handle: str,
    password: str,
    label: str,
    plc_hostname: str,
    auth_token: Optional[str] = None,
) -> None:
    async with aiohttp.ClientSession() as http_session:
        resolved_handle = await resolve_subject(http_session, plc_hostname, handle)
        assert resolved_handle is not None

        async with aiohttp.ClientSession() as http_session:
            create_session_url = (
                f"{resolved_handle.pds}/xrpc/com.atproto.server.createSession"
            )
            create_session_body = {
                "identifier": resolved_handle.did,
                "password": password,
            }
            if auth_token is not None:
                create_session_body["authToken"] = auth_token

            async with http_session.post(
                create_session_url, json=create_session_body
            ) as resp:
                assert resp.status == 200

                created_session: Dict[str, Any] = await resp.json()

                assert created_session.get("did", str) == resolved_handle.did
                assert created_session.get("handle", str) == handle

            create_app_password_url = (
                f"{resolved_handle.pds}/xrpc/com.atproto.server.createAppPassword"
            )
            create_app_password_body = {"name": label}
            create_app_password_headers = {
                "Authorization": f"Bearer {created_session['accessJwt']}"
            }

            async with http_session.post(
                create_app_password_url,
                headers=create_app_password_headers,
                json=create_app_password_body,
            ) as resp:
                if resp.status != 200:
                    print("Error creating app password: %s", await resp.text())
                    return
                app_password = await resp.json()
                print(
                    f"{app_password["name"]} created {app_password["createdAt"]}: {app_password["password"]}"
                )


async def genJwk() -> None:
    key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    print(key.export(private_key=True))


async def genCryptoKey() -> None:
    key = Fernet.generate_key()
    print(base64.b64encode(key).decode("utf-8"))


async def realMain() -> None:
    parser = argparse.ArgumentParser(prog="aiputil", description="AIP utilities")

    parser.add_argument(
        "--plc-hostname",
        default="plc.directory",
        help="The PLC hostname to use for resolving did-method-plc DIDs.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    _ = subparsers.add_parser("gen-jwk", help="Generate a JWK")
    _ = subparsers.add_parser("gen-crypto", help="Generate an encryption key")
    gen_app_password = subparsers.add_parser(
        "gen-app-password", help="Generate an app-password"
    )

    gen_app_password.add_argument("handle", help="The handle to authenticate with.")
    gen_app_password.add_argument("password", help="The password to authenticate with.")
    gen_app_password.add_argument("label", help="The label for the app-password.")

    args = vars(parser.parse_args())
    command = args.get("command", None)

    if command == "gen-jwk":
        await genJwk()
    elif command == "gen-crypto":
        await genCryptoKey()
    elif command == "gen-app-password":
        handle: str = args.get("handle", str)
        password: str = args.get("password", str)
        label: str = args.get("label", str)
        plc_hostname: str = args.get("plc_hostname", str)
        await genAppPassword(handle, password, label, plc_hostname)


def main() -> None:
    asyncio.run(realMain())


if __name__ == "__main__":
    main()
