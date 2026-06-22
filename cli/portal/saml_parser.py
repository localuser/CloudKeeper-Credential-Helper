from __future__ import annotations

import base64
import dataclasses
from datetime import datetime, timezone
from typing import Optional

from lxml import etree

# XML namespace map used in AWS IAM Identity Center SAML assertions
_NS = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2":  "urn:oasis:names:tc:SAML:2.0:assertion",
}

# AWS SAML attribute URNs
_ATTR_ROLE         = "https://aws.amazon.com/SAML/Attributes/Role"
_ATTR_SESSION_NAME = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"


class SamlParseError(Exception):
    """Raised when required fields are missing from the SAML assertion."""


@dataclasses.dataclass
class ParsedRole:
    role_arn: str
    principal_arn: str        # the saml-provider ARN
    session_name: str
    not_on_or_after: datetime  # SubjectConfirmationData/@NotOnOrAfter
    session_not_on_or_after: Optional[datetime]  # AuthnStatement/@SessionNotOnOrAfter

    @property
    def duration_seconds(self) -> int:
        """Seconds until SAML assertion expires — pass directly to STS DurationSeconds.

        Clamped to [900, 43200] (AWS STS hard limits).
        """
        delta = self.not_on_or_after - datetime.now(tz=timezone.utc)
        seconds = max(900, min(43200, int(delta.total_seconds())))
        return seconds


def parse_saml_assertion(encoded_response: str) -> list[ParsedRole]:
    """Decode and parse an IAM Identity Center SAML assertion.

    Args:
        encoded_response: The base64-encoded SAML XML from
            :attr:`cli.portal.portal_client.SamlAssertion.encoded_response`.

    Returns:
        A list of :class:`ParsedRole` objects — one per ``Role`` attribute
        value.  Most apps have exactly one role, but multi-role assertions are
        supported.

    Raises:
        SamlParseError: If required fields (Role, RoleSessionName,
            NotOnOrAfter) are absent.
    """
    try:
        xml_bytes = base64.b64decode(encoded_response)
    except Exception as exc:
        raise SamlParseError(f"Failed to base64-decode SAML response: {exc}") from exc

    try:
        root = etree.fromstring(xml_bytes)  # noqa: S320 (trusted IdP payload)
    except etree.XMLSyntaxError as exc:
        raise SamlParseError(f"Invalid SAML XML: {exc}") from exc

    # ------------------------------------------------------------------ #
    # RoleSessionName
    # ------------------------------------------------------------------ #
    session_name = _get_attribute_value(root, _ATTR_SESSION_NAME)
    if not session_name:
        raise SamlParseError("SAML assertion missing RoleSessionName attribute")

    # ------------------------------------------------------------------ #
    # NotOnOrAfter (SubjectConfirmationData)
    # ------------------------------------------------------------------ #
    nooa_elements = root.xpath(
        "//saml2:SubjectConfirmationData/@NotOnOrAfter",
        namespaces=_NS,
    )
    if not nooa_elements:
        raise SamlParseError(
            "SAML assertion missing SubjectConfirmationData/@NotOnOrAfter"
        )
    not_on_or_after = _parse_dt(str(nooa_elements[0]))

    # ------------------------------------------------------------------ #
    # SessionNotOnOrAfter (optional, from AuthnStatement)
    # ------------------------------------------------------------------ #
    session_nooa_elements = root.xpath(
        "//saml2:AuthnStatement/@SessionNotOnOrAfter",
        namespaces=_NS,
    )
    session_not_on_or_after: Optional[datetime] = None
    if session_nooa_elements:
        session_not_on_or_after = _parse_dt(str(session_nooa_elements[0]))

    # ------------------------------------------------------------------ #
    # Role attribute values  (comma-separated "saml-provider,...,role/..." pairs)
    # ------------------------------------------------------------------ #
    role_values = _get_all_attribute_values(root, _ATTR_ROLE)
    if not role_values:
        raise SamlParseError("SAML assertion missing Role attribute")

    roles: list[ParsedRole] = []
    for raw in role_values:
        role_arn, principal_arn = _split_role_pair(raw)
        roles.append(
            ParsedRole(
                role_arn=role_arn,
                principal_arn=principal_arn,
                session_name=session_name,
                not_on_or_after=not_on_or_after,
                session_not_on_or_after=session_not_on_or_after,
            )
        )

    return roles


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #

def _get_attribute_value(root: etree._Element, name: str) -> Optional[str]:
    """Return the first AttributeValue text for a named Attribute."""
    values = _get_all_attribute_values(root, name)
    return values[0] if values else None


def _get_all_attribute_values(root: etree._Element, name: str) -> list[str]:
    """Return all AttributeValue texts for a named Attribute."""
    xpath = (
        f"//saml2:Attribute[@Name='{name}']/saml2:AttributeValue"
    )
    elements = root.xpath(xpath, namespaces=_NS)
    return [el.text.strip() for el in elements if el.text]


def _split_role_pair(raw: str) -> tuple[str, str]:
    """Split a comma-separated role+provider pair into (role_arn, principal_arn).

    The IAM Identity Center SAML assertion puts both ARNs in a single
    AttributeValue separated by a comma.  The order is not guaranteed —
    either the role or the provider may come first.
    """
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 2:
        raise SamlParseError(
            f"Expected 2 ARNs in Role attribute value, got {len(parts)}: {raw!r}"
        )
    role_arn = next((p for p in parts if ":role/" in p), None)
    principal_arn = next((p for p in parts if ":saml-provider/" in p), None)
    if not role_arn or not principal_arn:
        raise SamlParseError(
            f"Could not identify role/provider ARNs in: {raw!r}"
        )
    return role_arn, principal_arn


def _parse_dt(value: str) -> datetime:
    """Parse an ISO-8601 UTC datetime string into an aware datetime."""
    # Python 3.11+ handles trailing Z; older versions need the replace trick
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
