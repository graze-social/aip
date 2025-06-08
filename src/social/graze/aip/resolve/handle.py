"""AT Protocol handle and DID resolution utilities.

Resolves AT Protocol handles to DIDs using DNS TXT records and HTTPS well-known endpoints.
Supports both did:plc and did:web DID methods for complete subject resolution.
"""

import asyncio
from enum import IntEnum
from aiohttp import ClientSession
from pydantic import BaseModel
from aiodns import DNSResolver
from typing import Optional, Any, Dict
import sentry_sdk


class SubjectType(IntEnum):
    """AT Protocol subject type enumeration.

    Identifies whether a subject is a DID or handle requiring resolution.
    """

    did_method_plc = 1
    did_method_web = 2
    hostname = 3


class ParsedSubject(BaseModel):
    """Parsed AT Protocol subject input.

    Contains the classified subject type and normalized subject string.
    """

    subject_type: SubjectType
    subject: str


class ResolvedSubject(BaseModel):
    """Resolved AT Protocol subject with all identifiers.

    Contains DID, handle, and PDS endpoint for a fully resolved subject.
    """

    did: str
    handle: str
    pds: str


async def resolve_handle_dns(handle: str) -> Optional[str]:
    """Resolve AT Protocol handle to DID using DNS TXT record.

    Queries _atproto.{handle} TXT record and extracts DID from did= prefix.

    Args:
        handle: AT Protocol handle to resolve

    Returns:
        DID string if found, None if resolution fails
    """
    # TODO: Wrap hickory-dns and use that
    resolver = DNSResolver()
    try:
        results = await resolver.query(f"_atproto.{handle}", "TXT")
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return None
    first_result = next(iter(results or []), None)
    if first_result is not None:
        return first_result.text.removeprefix("did=")
    return None


async def resolve_handle_http(session: ClientSession, handle: str) -> Optional[str]:
    """Resolve AT Protocol handle to DID using HTTPS well-known endpoint.

    Fetches DID from https://{handle}/.well-known/atproto-did endpoint.

    Args:
        session: HTTP client session
        handle: AT Protocol handle to resolve

    Returns:
        DID string if found, None if resolution fails
    """
    try:
        async with session.get(f"https://{handle}/.well-known/atproto-did") as resp:
            if resp.status != 200:
                return None
            body = await resp.text()
            if body is not None:
                return body
            return None
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return None


async def resolve_handle(session: ClientSession, handle: str) -> Optional[str]:
    """Resolve AT Protocol handle to DID using DNS and HTTPS concurrently.

    Attempts both DNS TXT and HTTPS well-known resolution, preferring DNS.

    Args:
        session: HTTP client session
        handle: AT Protocol handle to resolve

    Returns:
        DID string if found via either method, None if both fail
    """
    async with asyncio.TaskGroup() as tg:
        dns_result = tg.create_task(resolve_handle_dns(handle))
        http_result = tg.create_task(resolve_handle_http(session, handle))
    dns_result = dns_result.result()
    http_result = http_result.result()
    if dns_result is not None:
        return dns_result
    return http_result


def handle_predicate(value: str) -> bool:
    """Check if value is an AT Protocol handle reference.

    Args:
        value: String to check

    Returns:
        True if value starts with at:// prefix
    """
    return value is not None and value.startswith("at://")


def pds_predicate(value: Dict[str, Any]) -> bool:
    """Check if service entry is an AT Protocol PDS.

    Args:
        value: Service dictionary from DID document

    Returns:
        True if service is AtprotoPersonalDataServer with endpoint
    """
    return (
        value is not None
        and value.get("type", None) == "AtprotoPersonalDataServer"
        and "serviceEndpoint" in value
    )


async def resolve_did_method_plc(
    plc_directory: str, session: ClientSession, did: str
) -> Optional[ResolvedSubject]:
    """Resolve did:plc DID to complete subject information.

    Fetches DID document from PLC directory and extracts handle and PDS.

    Args:
        plc_directory: PLC directory hostname
        session: HTTP client session
        did: did:plc DID to resolve

    Returns:
        ResolvedSubject if successful, None if resolution fails
    """
    async with session.get(f"https://{plc_directory}/{did}") as resp:
        if resp.status != 200:
            return None
        body = await resp.json()
        if body is None:
            return None
        handle = next(filter(handle_predicate, body.get("alsoKnownAs", [])), None)
        pds = next(filter(pds_predicate, body.get("service", [])), None)
        if handle is not None and pds is not None:
            return ResolvedSubject(
                did=did,
                handle=handle.removeprefix("at://"),
                pds=pds.get("serviceEndpoint"),
            )
    return None


async def resolve_did_method_web(
    session: ClientSession, did: str
) -> Optional[ResolvedSubject]:
    """Resolve did:web DID to complete subject information.

    Constructs did.json URL from DID and extracts handle and PDS.

    Args:
        session: HTTP client session
        did: did:web DID to resolve

    Returns:
        ResolvedSubject if successful, None if resolution fails
    """

    parts = did.removeprefix("did:web:").split(":")
    if len(parts) == 0:
        return None

    if len(parts) == 1:
        parts.append(".well-known")

    url = "https://{inner}/did.json".format(inner="/".join(parts))

    async with session.get(url) as resp:
        if resp.status != 200:
            return None
        body = await resp.json()
        if body is None:
            return None
        handle = next(filter(handle_predicate, body.get("alsoKnownAs", [])), None)
        pds = next(filter(pds_predicate, body.get("service", [])), None)
        if handle is not None and pds is not None:
            return ResolvedSubject(
                did=did,
                handle=handle.removeprefix("at://"),
                pds=pds.get("serviceEndpoint"),
            )
    return None


async def resolve_did(
    session: ClientSession, plc_hostname: str, did: str
) -> Optional[ResolvedSubject]:
    """Resolve DID to complete subject information.

    Routes to appropriate resolver based on DID method (plc or web).

    Args:
        session: HTTP client session
        plc_hostname: PLC directory hostname for did:plc resolution
        did: DID to resolve

    Returns:
        ResolvedSubject if successful, None if unsupported or failed
    """
    if did.startswith("did:plc:"):
        return await resolve_did_method_plc(plc_hostname, session, did)
    elif did.startswith("did:web:"):
        return await resolve_did_method_web(session, did)
    return None


async def resolve_subject(
    session: ClientSession, plc_hostname: str, subject: str
) -> Optional[ResolvedSubject]:
    """Resolve AT Protocol subject (handle or DID) to complete information.

    Parses input, resolves handle to DID if needed, then resolves DID.

    Args:
        session: HTTP client session
        plc_hostname: PLC directory hostname
        subject: Handle or DID to resolve

    Returns:
        ResolvedSubject if successful, None if resolution fails
    """
    parsed_subject = parse_input(subject)
    if parsed_subject is None:
        return None

    did: Optional[str] = None
    if parsed_subject.subject_type == SubjectType.hostname:
        did = await resolve_handle(session, parsed_subject.subject)
    elif parsed_subject.subject_type == SubjectType.did_method_plc:
        did = parsed_subject.subject
    elif parsed_subject.subject_type == SubjectType.did_method_web:
        did = parsed_subject.subject

    if did is None:
        return None

    return await resolve_did(session, plc_hostname, did)


def parse_input(subject: str) -> Optional[ParsedSubject]:
    """Parse and classify AT Protocol subject input.

    Normalizes input by removing prefixes and classifies as DID or handle.

    Args:
        subject: Raw subject string (handle, DID, or prefixed)

    Returns:
        ParsedSubject with type and normalized string
    """
    subject = subject.strip()
    subject = subject.removeprefix("at://")
    subject = subject.removeprefix("@")

    if subject.startswith("did:plc:"):
        return ParsedSubject(subject_type=SubjectType.did_method_plc, subject=subject)
    elif subject.startswith("did:web:"):
        return ParsedSubject(subject_type=SubjectType.did_method_web, subject=subject)

    # TODO: Validate this hostname
    return ParsedSubject(subject_type=SubjectType.hostname, subject=subject)
