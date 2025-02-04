from typing import Optional, Any
from aiohttp import ClientSession


async def oauth_protected_resource(session: ClientSession, pds: str) -> Optional[Any]:
    async with session.get(f"{pds}/.well-known/oauth-protected-resource") as resp:
        if resp.status != 200:
            return None
        return await resp.json()
    return None


async def oauth_authorization_server(
    session: ClientSession, authorization_server: str
) -> Optional[Any]:
    async with session.get(
        f"{authorization_server}/.well-known/oauth-authorization-server"
    ) as resp:
        if resp.status != 200:
            return None
        return await resp.json()
    return None
