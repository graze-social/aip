from typing import Optional, Any, Dict
from aiohttp import ClientSession
from jwcrypto import jwt, jwk


async def dpop_request(
    session: ClientSession,
    dpop_key: jwk.JWK,
    dop_assertion_header: Dict[str, Any],
    dop_assertion_claims: Dict[str, Any],
    *args,
    **kwargs,
):
    attempts = 3

    print(f"args: {args}")
    print(f"kwargs: {kwargs}")

    request_kwargs = {**kwargs}

    # print(f"dpop_assertation = {dpop_assertation}")

    while attempts > 0:
        attempts -= 1

        async with session.request(*args, **kwargs) as resp:
            # print(f"status: {resp.status} {resp}")

            if resp.status == 401:
                body = await resp.json()
                if body.get("error", None) == "invalid_dpop_proof":

                    dop_assertion_claims["nonce"] = resp.headers.get("DPoP-Nonce", "")

                    dpop_assertation = jwt.JWT(
                        header=dop_assertion_header,
                        claims=dop_assertion_claims,
                    )
                    dpop_assertation.make_signed_token(dpop_key)
                    dpop_assertation_token = dpop_assertation.serialize()

                    # dpop_assertation.claims["nonce"] = resp.headers.get("DPoP-Nonce", "")
                    # dpop_assertation.make_signed_token(dpop_key)
                    # dpop_assertation_token = dpop_assertation.serialize()

                    request_kwargs["headers"]["DPoP"] = dpop_assertation_token
                    
                    continue

            return await resp.json()

    raise Exception("Failed to execute request")
