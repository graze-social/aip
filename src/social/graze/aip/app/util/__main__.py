import argparse
import asyncio
import logging
from jwcrypto import jwk
from ulid import ULID
import base64
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


async def genJwk() -> None:
    key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    print(key.export(private_key=True))


async def genCryptoKey() -> None:
    key = Fernet.generate_key()
    print(base64.b64encode(key).decode("utf-8"))


async def realMain() -> None:
    parser = argparse.ArgumentParser(prog="aiputil", description="AIP utilities")

    subparsers = parser.add_subparsers(dest="command", required=True)

    _ = subparsers.add_parser("gen-jwk", help="Generate a JWK")
    _ = subparsers.add_parser("gen-crypto", help="Generate an encryption key")

    args = vars(parser.parse_args())
    command = args.get("command", None)

    if command == "gen-jwk":
        await genJwk()
    elif command == "gen-crypto":
        await genCryptoKey()


def main() -> None:
    asyncio.run(realMain())


if __name__ == "__main__":
    main()
