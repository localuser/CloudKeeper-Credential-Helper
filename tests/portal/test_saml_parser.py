"""Tests for cli.portal.saml_parser."""
from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from cli.portal.saml_parser import ParsedRole, SamlParseError, parse_saml_assertion

# ---------------------------------------------------------------------------
# Sample SAML assertion — SYNTHETIC, structurally faithful to a real AWS IAM
# Identity Center assertion but with all account IDs, emails, role names and
# signature material replaced by documentation-safe placeholders
# (123456789012 is AWS's reserved example account; example.com is the reserved
# example domain).  The parser does not validate the XML signature, so the
# EXAMPLE* signature values are sufficient to exercise the full parse path.
# ---------------------------------------------------------------------------
SAMPLE_SAML_XML = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML"
    ":2.0:protocol\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml2=\"urn:oasis:names:tc"
    ":SAML:2.0:assertion\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" Destination=\"https://signi"
    "n.aws.amazon.com/saml\" ID=\"_00000000-0000-0000-0000-000000000000\" IssueInstant=\"2026-06-10T1"
    "2:25:22.187Z\" Version=\"2.0\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:"
    "entity\">https://portal.sso.eu-west-1.amazonaws.com/saml/assertion/EXAMPLEISSUERID</saml2:Iss"
    "uer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/200"
    "1/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#r"
    "sa-sha256\"/><ds:Reference URI=\"#_00000000-0000-0000-0000-000000000000\"><ds:DigestValue>EXAMP"
    "LEDIGEST=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EXAMPLESIGNATURE"
    "=</ds:SignatureValue></ds:Signature><saml2:Assertion ID=\"_11111111-1111-1111-1111-1111111111"
    "11\" IssueInstant=\"2026-06-10T12:25:22.187Z\" Version=\"2.0\"><saml2:Subject><saml2:SubjectConfi"
    "rmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData NotOnO"
    "rAfter=\"2026-06-10T13:25:22.187Z\" Recipient=\"https://signin.aws.amazon.com/saml\"/></saml2:Su"
    "bjectConfirmation></saml2:Subject><saml2:AuthnStatement AuthnInstant=\"2026-06-10T12:25:22.18"
    "7Z\" SessionIndex=\"_22222222-2222-2222-2222-222222222222\" SessionNotOnOrAfter=\"2026-06-11T00:"
    "25:22.187Z\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:c"
    "lasses:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:A"
    "uthnStatement><saml2:AttributeStatement><saml2:Attribute Name=\"https://aws.amazon.com/SAML/A"
    "ttributes/Role\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\"><saml2:"
    "AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">a"
    "rn:aws:iam::123456789012:saml-provider/Example-AdministratorAccess-idp,arn:aws:iam::12345678"
    "9012:role/Example-AdministratorAccess-SSO-Role</saml2:AttributeValue></saml2:Attribute><saml"
    "2:Attribute Name=\"https://aws.amazon.com/SAML/Attributes/RoleSessionName\" NameFormat=\"urn:oa"
    "sis:names:tc:SAML:2.0:attrname-format:unspecified\"><saml2:AttributeValue xmlns:xsi=\"http://w"
    "ww.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">user@example.com</saml2:AttributeVa"
    "lue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>"
)
SAMPLE_ENCODED = base64.b64encode(SAMPLE_SAML_XML.encode()).decode()


def _make_minimal_saml(
    *,
    role_value: str = (
        "arn:aws:iam::123456789012:saml-provider/MyIdp,"
        "arn:aws:iam::123456789012:role/MyRole"
    ),
    session_name: str = "user@example.com",
    not_on_or_after: str = "2099-01-01T00:00:00.000Z",
    session_not_on_or_after: str | None = "2099-01-02T00:00:00.000Z",
    include_role: bool = True,
    include_session_name: bool = True,
    include_nooa: bool = True,
) -> str:
    """Build a minimal SAML response and return it base64-encoded."""
    session_nooa_attr = (
        f' SessionNotOnOrAfter="{session_not_on_or_after}"' if session_not_on_or_after else ""
    )
    role_attr = f"""
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"
        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
      <saml2:AttributeValue>{role_value}</saml2:AttributeValue>
    </saml2:Attribute>""" if include_role else ""

    sn_attr = f"""
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"
        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
      <saml2:AttributeValue>{session_name}</saml2:AttributeValue>
    </saml2:Attribute>""" if include_session_name else ""

    nooa_attr = f'NotOnOrAfter="{not_on_or_after}"' if include_nooa else ""

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    Destination="https://signin.aws.amazon.com/saml">
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion>
    <saml2:Subject>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData {nooa_attr}
            Recipient="https://signin.aws.amazon.com/saml"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"{session_nooa_attr}>
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>{role_attr}{sn_attr}
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>"""
    return base64.b64encode(xml.encode()).decode()


# ---------------------------------------------------------------------------
# Happy-path: sample SAML
# ---------------------------------------------------------------------------


def test_parse_sample_saml_returns_one_role() -> None:
    roles = parse_saml_assertion(SAMPLE_ENCODED)
    assert len(roles) == 1


def test_parse_sample_saml_role_arn() -> None:
    role = parse_saml_assertion(SAMPLE_ENCODED)[0]
    assert role.role_arn == (
        "arn:aws:iam::123456789012:role/Example-AdministratorAccess-SSO-Role"
    )


def test_parse_sample_saml_principal_arn() -> None:
    role = parse_saml_assertion(SAMPLE_ENCODED)[0]
    assert role.principal_arn == (
        "arn:aws:iam::123456789012:saml-provider/Example-AdministratorAccess-idp"
    )


def test_parse_sample_saml_session_name() -> None:
    role = parse_saml_assertion(SAMPLE_ENCODED)[0]
    assert role.session_name == "user@example.com"


def test_parse_sample_saml_not_on_or_after() -> None:
    role = parse_saml_assertion(SAMPLE_ENCODED)[0]
    assert role.not_on_or_after == datetime(2026, 6, 10, 13, 25, 22, 187000, tzinfo=timezone.utc)


def test_parse_sample_saml_session_not_on_or_after() -> None:
    role = parse_saml_assertion(SAMPLE_ENCODED)[0]
    assert role.session_not_on_or_after == datetime(2026, 6, 11, 0, 25, 22, 187000, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Role ARN order invariance (provider first, role second)
# ---------------------------------------------------------------------------


def test_parse_provider_first_order() -> None:
    encoded = _make_minimal_saml(
        role_value=(
            "arn:aws:iam::111122223333:saml-provider/MyIdp,"
            "arn:aws:iam::111122223333:role/MyRole"
        )
    )
    role = parse_saml_assertion(encoded)[0]
    assert role.role_arn == "arn:aws:iam::111122223333:role/MyRole"
    assert role.principal_arn == "arn:aws:iam::111122223333:saml-provider/MyIdp"


def test_parse_role_first_order() -> None:
    encoded = _make_minimal_saml(
        role_value=(
            "arn:aws:iam::111122223333:role/MyRole,"
            "arn:aws:iam::111122223333:saml-provider/MyIdp"
        )
    )
    role = parse_saml_assertion(encoded)[0]
    assert role.role_arn == "arn:aws:iam::111122223333:role/MyRole"
    assert role.principal_arn == "arn:aws:iam::111122223333:saml-provider/MyIdp"


# ---------------------------------------------------------------------------
# duration_seconds clamping
# ---------------------------------------------------------------------------


def test_duration_seconds_clamped_to_min() -> None:
    # already expired → clamp to 900
    encoded = _make_minimal_saml(not_on_or_after="2000-01-01T00:00:00.000Z")
    role = parse_saml_assertion(encoded)[0]
    assert role.duration_seconds == 900


def test_duration_seconds_clamped_to_max() -> None:
    # far future → clamp to 43200
    encoded = _make_minimal_saml(not_on_or_after="2099-01-01T00:00:00.000Z")
    role = parse_saml_assertion(encoded)[0]
    assert role.duration_seconds == 43200


# ---------------------------------------------------------------------------
# Optional SessionNotOnOrAfter
# ---------------------------------------------------------------------------


def test_no_session_not_on_or_after_is_none() -> None:
    encoded = _make_minimal_saml(session_not_on_or_after=None)
    role = parse_saml_assertion(encoded)[0]
    assert role.session_not_on_or_after is None


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_raises_on_invalid_base64() -> None:
    with pytest.raises(SamlParseError, match="base64"):
        parse_saml_assertion("not-valid-base64!!!")


def test_raises_on_invalid_xml() -> None:
    with pytest.raises(SamlParseError, match="XML"):
        parse_saml_assertion(base64.b64encode(b"<not><valid xml").decode())


def test_raises_on_missing_role() -> None:
    encoded = _make_minimal_saml(include_role=False)
    with pytest.raises(SamlParseError, match="Role"):
        parse_saml_assertion(encoded)


def test_raises_on_missing_session_name() -> None:
    encoded = _make_minimal_saml(include_session_name=False)
    with pytest.raises(SamlParseError, match="RoleSessionName"):
        parse_saml_assertion(encoded)


def test_raises_on_missing_not_on_or_after() -> None:
    encoded = _make_minimal_saml(include_nooa=False)
    with pytest.raises(SamlParseError, match="NotOnOrAfter"):
        parse_saml_assertion(encoded)


def test_raises_on_malformed_role_pair() -> None:
    encoded = _make_minimal_saml(role_value="arn:aws:iam::123:role/OnlyOne")
    with pytest.raises(SamlParseError, match="2 ARNs"):
        parse_saml_assertion(encoded)
