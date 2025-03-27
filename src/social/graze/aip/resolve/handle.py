from enum import IntEnum
from aiohttp import ClientSession
from pydantic import BaseModel
from aiodns import DNSResolver
from typing import Optional, Any, Dict
import sentry_sdk


class SubjectType(IntEnum):
    did_method_plc = 1
    did_method_web = 2
    hostname = 3


class ParsedSubject(BaseModel):
    subject_type: SubjectType
    subject: str


class ResolvedSubject(BaseModel):
    did: str
    handle: str
    pds: str

    # @model_validator(mode='after')
    # def validate_also_known_as(self) -> 'ResolvedSubject':
    #     for value in self.also_known_as:
    #         if subject.startswith("at://did:")
    #             continue
    #         if subject.startswith("at://")
    #             return value
    #         elif subject.startswith("https://")
    #             continue
    #     raise ValueError("No handles returned")


async def resolve_handle_dns(handle: str) -> Optional[str]:
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
    async with session.get(f"https://{handle}/.well-known/atproto-did") as resp:
        if resp.status != 200:
            return None
        body = await resp.text()
        if body is not None:
            return body
        return None


async def resolve_handle(session: ClientSession, handle: str) -> Optional[str]:
    did: Optional[str] = None

    did = await resolve_handle_dns(handle)
    if did is not None:
        return did

    return await resolve_handle_http(session, handle)

    # Nick: Alternatively, we could use an async task group to do these in parallel.
    #
    # async with asyncio.TaskGroup() as tg:
    #     dns_result = tg.create_task(resolve_handle_dns(handle))
    #     http_result = tg.create_task(resolve_handle_http(session, handle))
    # dns_result = dns_result.result()
    # http_result = http_result.result()
    # if dns_result is not None:
    #     return dns_result
    # return http_result


def handle_predicate(value: str) -> bool:
    return value.startswith("at://")


def pds_predicate(value: Dict[str, Any]) -> bool:
    return (
        value.get("type", None) == "AtprotoPersonalDataServer"
        and "serviceEndpoint" in value
    )


async def resolve_did_method_plc(
    plc_directory: str, session: ClientSession, did: str
) -> Optional[ResolvedSubject]:
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
    if did.startswith("did:plc:"):
        return await resolve_did_method_plc(plc_hostname, session, did)
    elif did.startswith("did:web:"):
        return await resolve_did_method_web(session, did)
    return None


async def resolve_subject(
    session: ClientSession, plc_hostname: str, subject: str
) -> Optional[ResolvedSubject]:
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
    subject = subject.strip()
    subject = subject.removeprefix("at://")
    subject = subject.removeprefix("@")

    if subject.startswith("did:plc:"):
        return ParsedSubject(subject_type=SubjectType.did_method_plc, subject=subject)
    elif subject.startswith("did:web:"):
        return ParsedSubject(subject_type=SubjectType.did_method_web, subject=subject)

    # TODO: Validate this hostname
    return ParsedSubject(subject_type=SubjectType.hostname, subject=subject)
