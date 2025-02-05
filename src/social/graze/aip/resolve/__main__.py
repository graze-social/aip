from typing import List
import argparse
import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)

from social.graze.aip.resolve.handle import resolve_subject


async def realMain() -> None:
    parser = argparse.ArgumentParser(prog="resolve", description="Resolve handles")
    parser.add_argument("subject", nargs="+", help="The subject(s) to resolve.")
    parser.add_argument(
        "--plc-hostname",
        default="plc.directory",
        help="The PLC hostname to use for resolving did-method-plc DIDs.",
    )

    args = vars(parser.parse_args())

    subjects: List[str] = args.get("subject", [])

    async with aiohttp.ClientSession() as session:
        for subject in subjects:
            try:
                resolved_handle = await resolve_subject(
                    session, args.get("plc_hostname"), subject
                )
                print(f"resolved_handle {resolved_handle}")
            except Exception:
                logging.exception("Exception resolving subject %s", subject)


def main() -> None:
    asyncio.run(realMain())


if __name__ == "__main__":
    main()
