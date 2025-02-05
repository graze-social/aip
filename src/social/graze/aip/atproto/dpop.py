import secrets
from typing import Any, Dict
from aiohttp import ClientSession, FormData
from jwcrypto import jwt, jwk


async def dpop_request(
    session: ClientSession,
    url: str,
    dpop_key: jwk.JWK,
    dop_assertion_header: Dict[str, Any],
    dop_assertion_claims: Dict[str, Any],
    signing_key: jwk.JWK,
    client_assertion_header: Dict[str, Any],
    client_assertion_claims: Dict[str, Any],
    data: FormData,
):
    attempts = 3

    headers = {}

    while attempts > 0:
        attempts -= 1

        dop_assertion_claims["jti"] = secrets.token_urlsafe(32)

        dpop_assertation = jwt.JWT(
            header=dop_assertion_header,
            claims=dop_assertion_claims,
        )
        dpop_assertation.make_signed_token(dpop_key)
        dpop_assertation_token = dpop_assertation.serialize()

        client_assertion_claims["jti"] = secrets.token_urlsafe(32)
        claims_assertation = jwt.JWT(
            header=client_assertion_header,
            claims=client_assertion_claims,
        )
        claims_assertation.make_signed_token(signing_key)
        claims_assertation_token = claims_assertation.serialize()

        data.add_field("client_assertion", claims_assertation_token)

        headers["DPoP"] = dpop_assertation_token

        async with session.request("POST", url, headers=headers, data=data) as resp:
            body = await resp.json()

            if resp.status == 401 or resp.status == 400:
                if (
                    body.get("error", None) == "invalid_dpop_proof"
                    or body.get("error", None) == "use_dpop_nonce"
                ):

                    dop_assertion_claims["nonce"] = resp.headers.get("DPoP-Nonce", "")

                    continue

            return body

    raise Exception("Failed to execute request")
