import argparse
import aiohttp
import asyncio
import logging
from jwcrypto import jwk
from ulid import ULID

logger = logging.getLogger(__name__)

async def genJwk() -> None:
    key = jwk.JWK.generate(kty='EC', crv='P-256', kid = str(ULID()), alg = "ES256")
    print(key.export(private_key=True))

async def realMain() -> None:
    parser = argparse.ArgumentParser(prog="aiputil", description="AIP utilities")

    subparsers = parser.add_subparsers(dest='command', required=True)

    gen_jwk_command = subparsers.add_parser('gen-jwk', help='Generate a JWK')

    args = vars(parser.parse_args())
    command = args.get("command", None)

    if command == 'gen-jwk':
        await genJwk()


def main() -> None:
    asyncio.run(realMain())


if __name__ == "__main__":
    main()
