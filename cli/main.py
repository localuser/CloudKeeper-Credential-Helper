from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import click
import requests
from rich.console import Console

from cli.auth.env_auth import get_env_authenticator
from cli.auth.msal_auth import AuthConfig, MsalAuthenticator
from cli.auth.oidc_auth import OidcAuthenticator, OidcConfig
from cli.auth.token_cache import DEFAULT_CACHE_DIR, TokenCache
from cli.aws.credentials_writer import CredentialsWriter
from cli.aws.sso_client import AccountRole, SsoClient
from cli.aws.sts_client import StsClient
from cli.portal.portal_client import AppInstance, AppProfile, PortalClient, SamlAssertion
from cli.portal.saml_exchange import ExchangeConfig, SamlExchanger
from cli.portal.saml_parser import ParsedRole, SamlParseError, parse_saml_assertion
from cli.ui.picker import PickCancelled, pick_from_list

console = Console(stderr=True)  # status/prompt on stderr; JSON output stays clean on stdout

CONFIG_PATH = DEFAULT_CACHE_DIR / "config.json"

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_config() -> dict:
    """Load ~/.ck_creds/config.json, return empty dict if absent."""
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as fh:
            return json.load(fh)
    return {}


def _save_config(cfg: dict) -> None:
    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def _require_config(cfg: dict, *keys: str) -> None:
    missing = [k for k in keys if not cfg.get(k)]
    if missing:
        raise click.ClickException(
            f"Missing config key(s): {', '.join(missing)}. "
            "Run `ck-creds configure` first."
        )


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _get_portal_token(cfg: dict, path2: bool = False) -> str:
    """Obtain a portal bearer token via Path 1 (MSAL) or Path 2 (OIDC).

    Path 1 auth priority:
      1. CK_CREDS_USERNAME + CK_CREDS_PASSWORD env vars → ROPC → TOTP prompt if MFA needed
      2. MSAL device-code (browser/phone) as fallback
    """
    if path2:
        _require_config(cfg, "sso_start_url", "region")
        console.print("[dim]Path 2: AWS SSO OIDC device flow[/dim]")
        oidc = OidcAuthenticator(
            OidcConfig(sso_start_url=cfg["sso_start_url"], region=cfg["region"])
        )
        return oidc.get_access_token(
            prompt_callback=lambda msg: console.print(f"\n[bold cyan]{msg}[/bold cyan]\n")
        )

    _require_config(cfg, "tenant_id", "iic_app_id_uri")
    auth_config = AuthConfig(
        tenant_id=cfg["tenant_id"],
        client_id=cfg.get("client_id", "04b07795-8ddb-461a-bbee-02f9e1bf7b46"),
        iic_app_id_uri=cfg["iic_app_id_uri"],
    )

    # Try env-var authenticator first (non-interactive username/password)
    env_auth = get_env_authenticator(auth_config, cfg_username=cfg.get("username"))
    if env_auth:
        console.print("[dim]Using CK_CREDS_USERNAME/PASSWORD for authentication[/dim]")

        def _totp_callback() -> str:
            """Called by EnvAuthenticator when MFA is required."""
            console.print(
                "\n[bold yellow]MFA required.[/bold yellow] "
                "Open your authenticator app and enter the 6-digit code below."
            )
            import getpass
            return getpass.getpass("TOTP code: ").strip()

        access_token = env_auth.get_access_token(
            prompt_callback=lambda msg: console.print(msg),
            totp_callback=_totp_callback,
        )
    else:
        # No env vars — fall back to device-code (original behaviour)
        msal_auth = MsalAuthenticator(auth_config)
        access_token = msal_auth.get_access_token(
            prompt_callback=lambda msg: console.print(f"\n[bold cyan]{msg}[/bold cyan]\n")
        )

    exchanger = SamlExchanger(
        ExchangeConfig(
            tenant_id=cfg["tenant_id"],
            iic_app_id=cfg.get("iic_azure_app_id", ""),
        )
    )
    console.print("[dim]Exchanging M365 token for IAM Identity Center session...[/dim]")
    return exchanger.exchange(access_token)


def _get_oidc_token(cfg: dict) -> str:
    """Return a cached (or freshly acquired) OIDC access token."""
    _require_config(cfg, "sso_start_url", "region")
    oidc = OidcAuthenticator(
        OidcConfig(sso_start_url=cfg["sso_start_url"], region=cfg["region"])
    )
    return oidc.get_access_token(
        prompt_callback=lambda msg: console.print(f"\n[bold cyan]{msg}[/bold cyan]\n")
    )


PORTAL_TOKEN_ENV = "CK_CREDS_PORTAL_TOKEN"
PORTAL_BROWSER_ENV = "CK_CREDS_BROWSER"


def _capture_portal_token_via_browser(cfg: dict) -> str:
    """Option A: drive a real browser to scrape the x-amz-sso_authn cookie.

    Reuses a persistent browser profile so the M365 session survives across
    runs (mostly-silent after first login). Feeds the same seam as Option B.
    """
    _require_config(cfg, "sso_start_url")
    # Imported here so Playwright stays an optional dependency — importing this
    # module must never hard-require the browser stack.
    from cli.portal.browser_capture import BrowserCapture, BrowserCaptureConfig, BrowserCaptureError

    console.print(
        "[dim]Opening a browser to the AWS access portal — complete M365 "
        "sign-in (incl. MFA) in the window…[/dim]"
    )
    capture = BrowserCapture(
        BrowserCaptureConfig(sso_start_url=cfg["sso_start_url"])
    )
    try:
        token = capture.capture()
    except BrowserCaptureError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print("[dim]Captured portal session cookie (x-amz-sso_authn).[/dim]")
    return token


def _capture_assertion_via_saml_intercept(
    cfg: dict,
    saml_url: Optional[str] = None,
    timeout: Optional[int] = None,
) -> "SamlAssertion":
    """Option A-prime: intercept the browser's SAML POST and wrap the assertion.

    Drives :class:`~cli.portal.saml_capture.SamlCapture` to sign in via M365 in
    a real browser and grab the base64 ``SAMLResponse`` in-flight, then wraps it
    in a :class:`~cli.portal.portal_client.SamlAssertion` so the *unchanged*
    ``_pick_role`` → ``_assume`` path consumes it exactly like a portal-fetched
    assertion.  Bypasses the portal API entirely (no ``x-amz-sso_authn`` cookie,
    no app-list call) — the most change-resistant path, at the cost of one app
    per sign-in.

    The start URL is taken from *saml_url* (the ``--saml-url`` flag) when given,
    else from the ``saml_start_url`` config key, else the ``sso_start_url`` key
    (an IdP-initiated app-launch URL works for either).  *timeout* (seconds)
    overrides the default interactive wait — raise it when MFA takes a while.
    """
    start_url = saml_url or cfg.get("saml_start_url") or cfg.get("sso_start_url")
    if not start_url:
        raise click.ClickException(
            "Direct SAML capture needs a start URL. Pass --saml-url <app-launch "
            "URL>, or set 'saml_start_url' (or 'sso_start_url') in your config "
            "(run `ck-creds configure`)."
        )
    # Imported here so Playwright stays an optional dependency — importing this
    # module must never hard-require the browser stack.
    from cli.portal import saml_capture as _saml_capture

    acs_url = cfg.get("saml_acs_url", _saml_capture.DEFAULT_ACS_URL)
    config = _saml_capture.SamlCaptureConfig(start_url=start_url, acs_url=acs_url)
    if timeout is not None:
        config.timeout_seconds = timeout
    console.print(
        "[dim]Opening a browser to sign in via M365 — the AWS SAML assertion "
        "will be captured in-flight (Option A-prime)…[/dim]"
    )
    capture = _saml_capture.SamlCapture(config)
    try:
        encoded = capture.capture()
    except _saml_capture.SamlCaptureError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print("[dim]Captured AWS SAML assertion.[/dim]")
    return SamlAssertion(
        encoded_response=encoded,
        destination=acs_url,
        relay_state=None,
    )


def _resolve_portal_token(
    cfg: dict,
    portal_token: Optional[str] = None,
    use_browser: bool = False,
) -> str:
    """Return a portal session token, preferring an injected cookie over live auth.

    Injection precedence (the Option B "manual cookie" seam and the Option A
    "headless-browser scraped cookie" seam both land here):

      1. ``--portal-token`` CLI flag
      2. ``CK_CREDS_PORTAL_TOKEN`` environment variable
      3. ``--browser`` flag / ``CK_CREDS_BROWSER=1`` → Option A browser capture
      4. live Path 1 (MSAL → SAML exchange)

    When a token is injected (1/2), the M365/OIDC + SAML-exchange legs are
    skipped entirely and the supplied ``x-amz-sso_authn`` value is handed
    straight to :class:`~cli.portal.portal_client.PortalClient`.  A pasted value
    of the form ``x-amz-sso_authn=<value>`` (or a leading ``Bearer ``) is
    normalised to the bare token.  Option A (3) produces the same kind of token
    via a real browser sign-in.  Falls back to the normal Path 1 flow when
    nothing is injected.
    """
    token = portal_token or os.environ.get(PORTAL_TOKEN_ENV)
    if token:
        token = token.strip()
        # Tolerate a pasted cookie pair or Authorization header value.
        if token.lower().startswith("bearer "):
            token = token[len("bearer "):].strip()
        if token.startswith("x-amz-sso_authn="):
            token = token.split("=", 1)[1].strip()
        token = token.strip('"').strip("'")
        if not token:
            raise click.ClickException(
                "Injected portal token is empty after normalisation. "
                f"Check --portal-token / {PORTAL_TOKEN_ENV}."
            )
        console.print(
            "[dim]Using injected portal token (x-amz-sso_authn) — "
            "skipping M365/OIDC auth[/dim]"
        )
        return token
    if use_browser or os.environ.get(PORTAL_BROWSER_ENV) == "1":
        return _capture_portal_token_via_browser(cfg)
    return _get_portal_token(cfg, path2=False)


# ---------------------------------------------------------------------------
# Portal helpers
# ---------------------------------------------------------------------------


def _make_portal_client(cfg: dict, portal_token: str) -> PortalClient:
    _require_config(cfg, "region")
    return PortalClient(
        token=portal_token,
        region=cfg["region"],
    )


def _portal_guard(fn, *args, **kwargs):
    """Run a PortalClient call, translating HTTP errors into clean messages.

    A 401 here almost always means the portal session token (the injected
    ``x-amz-sso_authn`` cookie, or a freshly-exchanged one that has since
    expired) is no longer valid — surface that as actionable guidance rather
    than a raw ``requests`` traceback.
    """
    try:
        return fn(*args, **kwargs)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 401:
            raise click.ClickException(
                "Portal session rejected (HTTP 401). The x-amz-sso_authn token "
                "is invalid or expired — grab a fresh cookie from your browser "
                "(DevTools → Application → Cookies on the AWS access portal) and "
                "retry with --portal-token / CK_CREDS_PORTAL_TOKEN."
            ) from exc
        raise click.ClickException(
            f"Portal API error (HTTP {status}). {exc}"
        ) from exc


def _pick_app(
    client: PortalClient,
    app_filter: Optional[str],
) -> tuple[AppInstance, AppProfile]:
    """List all apps + profiles; let user pick one app+profile pair."""
    console.print("[dim]Fetching your AWS applications...[/dim]")
    instances = _portal_guard(client.list_all_app_instances)
    if not instances:
        raise click.ClickException(
            "No SAML applications found. Check your IAM Identity Center assignments."
        )

    # Flatten instances → profiles into a single list of (instance, profile) pairs
    pairs: list[tuple[AppInstance, AppProfile]] = []
    for inst in instances:
        profiles = _portal_guard(client.list_profiles, inst.id)
        for prof in profiles:
            pairs.append((inst, prof))

    if not pairs:
        raise click.ClickException("No application profiles found.")

    def _label(pair: tuple[AppInstance, AppProfile]) -> str:
        inst, prof = pair
        return f"{inst.name} / {prof.name}" if prof.name != "Default" else inst.name

    try:
        chosen = pick_from_list(
            pairs,
            prompt="Select an AWS application",
            display_fn=_label,
            filter_name=app_filter,
            auto_select=bool(app_filter),
            console=console,
        )
    except PickCancelled:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(1)

    return chosen


def _pick_role(assertion: SamlAssertion, role_filter: Optional[str]) -> ParsedRole:
    """Parse SAML assertion and let user pick a role (auto if only one)."""
    try:
        roles = parse_saml_assertion(assertion.encoded_response)
    except SamlParseError as exc:
        raise click.ClickException(f"Failed to parse SAML assertion: {exc}") from exc

    if not roles:
        raise click.ClickException("No roles found in SAML assertion.")

    try:
        return pick_from_list(
            roles,
            prompt="Select a role",
            display_fn=lambda r: r.role_arn.split("/")[-1],
            filter_name=role_filter,
            auto_select=len(roles) == 1 or bool(role_filter),
            console=console,
        )
    except PickCancelled:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(1)


def _assume(cfg: dict, role: ParsedRole, assertion: SamlAssertion) -> "AwsCredentials":  # noqa: F821  # type: ignore[name-defined]
    return StsClient(region=cfg.get("region", "us-east-1")).assume_role_with_saml(
        role, assertion
    )


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="ck-creds")
def cli() -> None:
    """ck-creds — seamless AWS SAML credentials via M365 SSO."""


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--tenant-id", prompt="Azure AD Tenant ID", help="Azure AD / Entra tenant ID")
@click.option(
    "--client-id",
    default="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    prompt="Azure App Client ID (press Enter for default MS CLI app)",
    help="MSAL public-client app ID",
)
@click.option(
    "--iic-app-id-uri",
    prompt="IAM Identity Center App ID URI (Azure enterprise app, e.g. https://signin.aws.amazon.com/saml/...)",
    help="Application ID URI of the IAM Identity Center enterprise app in Azure",
)
@click.option(
    "--iic-azure-app-id",
    default="",
    prompt="IAM Identity Center Azure App Object/Client ID (optional)",
    help="Client/object ID used by SamlExchanger to request the IdP-initiated SAML page",
)
@click.option(
    "--sso-start-url",
    default="",
    prompt="AWS SSO Start URL (optional, for --path2 fallback)",
    help="e.g. https://myorg.awsapps.com/start",
)
@click.option(
    "--region",
    default="us-east-1",
    prompt="AWS / IAM Identity Center region",
    help="Region your IAM Identity Center portal is deployed in",
)
@click.option(
    "--username",
    default="",
    prompt="M365 username / UPN for ROPC auth (optional — leave blank to use env var or device-code)",
    help="Saves M365 UPN to config so you don't have to set CK_CREDS_USERNAME every time",
)
def configure(
    tenant_id: str,
    client_id: str,
    iic_app_id_uri: str,
    iic_azure_app_id: str,
    sso_start_url: str,
    region: str,
    username: str,
) -> None:
    """Interactive first-time setup — writes ~/.ck_creds/config.json."""
    cfg = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "iic_app_id_uri": iic_app_id_uri,
        "iic_azure_app_id": iic_azure_app_id,
        "sso_start_url": sso_start_url,
        "region": region,
    }
    if username:
        cfg["username"] = username
    _save_config(cfg)
    console.print(f"\n✅ [green]Config saved to [bold]{CONFIG_PATH}[/bold][/green]")
    if username:
        console.print(
            "   [dim]Username saved. Set [bold]CK_CREDS_PASSWORD[/bold] in your .env "
            "to enable non-interactive ROPC login.[/dim]"
        )


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--app", "-a", default=None, help="Filter app by name substring")
@click.option("--role", "-r", default=None, help="Filter role by name substring")
@click.option("--profile", "-p", default="default", show_default=True, help="~/.aws/credentials profile name")
@click.option("--path2", is_flag=True, default=False, help="Use AWS SSO OIDC instead of M365")
@click.option(
    "--portal-token",
    default=None,
    help="Inject an x-amz-sso_authn portal cookie directly (Option B); "
    "skips M365/OIDC auth. Or set CK_CREDS_PORTAL_TOKEN.",
)
@click.option(
    "--browser",
    "use_browser",
    is_flag=True,
    default=False,
    help="Option A: open a browser to the AWS access portal, sign in via "
    "M365, and auto-capture the x-amz-sso_authn cookie. Or set CK_CREDS_BROWSER=1.",
)
@click.option(
    "--browser-saml",
    "browser_saml",
    is_flag=True,
    default=False,
    help="Option A-prime: sign in via M365 in a browser and intercept the AWS "
    "SAML assertion directly (no portal API). Authenticates one app per "
    "sign-in — the app your --saml-url / saml_start_url lands on.",
)
@click.option(
    "--saml-url",
    "saml_url",
    default=None,
    help="App-launch URL for --browser-saml (overrides saml_start_url config).",
)
@click.option(
    "--saml-timeout",
    "saml_timeout",
    type=int,
    default=None,
    help="Seconds to wait for the SAML sign-in with --browser-saml "
    "(default 180). Raise it if MFA takes a while.",
)
def login(app: Optional[str], role: Optional[str], profile: str, path2: bool, portal_token: Optional[str], use_browser: bool, browser_saml: bool, saml_url: Optional[str], saml_timeout: Optional[int]) -> None:
    """Authenticate and write STS credentials to ~/.aws/credentials."""
    cfg = _load_config()

    if path2:
        access_token = _get_oidc_token(cfg)
        sso = SsoClient(access_token=access_token, region=cfg["region"])
        console.print("[dim]Fetching your AWS account/role assignments...[/dim]")
        entries = sso.list_account_roles()
        if not entries:
            console.print("[yellow]No accounts found.[/yellow]")
            sys.exit(1)

        filtered = [e for e in entries if not app or app.lower() in e.account_name.lower()]
        if not filtered:
            console.print(f"[red]No accounts matching '{app}'[/red]")
            sys.exit(1)

        chosen: AccountRole = pick_from_list(filtered, prompt="Select account/role", display_fn=lambda e: e.display_name, auto_select=len(filtered) == 1)
        console.print(f"[dim]Fetching credentials for [bold]{chosen.display_name}[/bold]...[/dim]")
        creds = sso.get_credentials(chosen.account_id, chosen.role_name)
    elif browser_saml:
        # Option A-prime: grab the SAML assertion in-flight, skip the portal
        # API entirely (no token, no client, no app picker — one app per
        # sign-in, chosen by the launch URL).
        assertion = _capture_assertion_via_saml_intercept(cfg, saml_url, saml_timeout)
        chosen_role = _pick_role(assertion, role)
        creds = _assume(cfg, chosen_role, assertion)
    else:
        portal_session = _resolve_portal_token(cfg, portal_token, use_browser=use_browser)
        client = _make_portal_client(cfg, portal_session)
        inst, prof = _pick_app(client, app)

        console.print(f"[dim]Fetching SAML assertion for [bold]{inst.name}[/bold]...[/dim]")
        assertion = _portal_guard(client.get_saml_assertion, prof.url)
        chosen_role = _pick_role(assertion, role)
        creds = _assume(cfg, chosen_role, assertion)

    path = CredentialsWriter().write(creds, profile=profile)
    console.print(
        f"\n✅ [green]Credentials written → [bold]{path} [{profile}][/bold][/green]\n"
        f"   Role:    [cyan]{creds.role_arn.split('/')[-1]}[/cyan]\n"
        f"   Expires: [yellow]{creds.expiration.isoformat()}[/yellow]"
    )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@cli.command("list")
@click.option("--path2", is_flag=True, default=False)
@click.option(
    "--portal-token",
    default=None,
    help="Inject an x-amz-sso_authn portal cookie directly (Option B); "
    "skips M365/OIDC auth. Or set CK_CREDS_PORTAL_TOKEN.",
)
@click.option(
    "--browser",
    "use_browser",
    is_flag=True,
    default=False,
    help="Option A: open a browser to the AWS access portal, sign in via "
    "M365, and auto-capture the x-amz-sso_authn cookie. Or set CK_CREDS_BROWSER=1.",
)
def list_apps(path2: bool, portal_token: Optional[str], use_browser: bool) -> None:
    """List all available AWS SAML applications."""
    cfg = _load_config()
    if path2:
        access_token = _get_oidc_token(cfg)
        sso = SsoClient(access_token=access_token, region=cfg["region"])
        entries = sso.list_account_roles()
        if not entries:
            console.print("[yellow]No accounts found.[/yellow]")
            return
        for e in entries:
            console.print(f"  [cyan]{e.account_name}[/cyan]  [dim]{e.account_id}[/dim]  → [green]{e.role_name}[/green]")
    else:
        portal_session = _resolve_portal_token(cfg, portal_token, use_browser=use_browser)
        client = _make_portal_client(cfg, portal_session)
        instances = _portal_guard(client.list_all_app_instances)
        if not instances:
            console.print("[yellow]No applications found.[/yellow]")
            return
        for inst in instances:
            console.print(f"  [cyan]{inst.name}[/cyan]  [dim]{inst.id}[/dim]")


# ---------------------------------------------------------------------------
# print-token
# ---------------------------------------------------------------------------


@cli.command("print-token")
@click.option(
    "--portal-token",
    default=None,
    help="Normalise an injected x-amz-sso_authn cookie instead of capturing "
    "one (strips a leading 'x-amz-sso_authn=' / 'Bearer ' and quotes).",
)
def print_token(portal_token: Optional[str]) -> None:
    """Capture an x-amz-sso_authn portal cookie and print it to stdout.

    Run this on a machine with a browser (your laptop): it signs you in via
    M365 in a real browser and prints the bare cookie value to stdout, so you
    can inject it into a headless environment where no browser is available:

    \b
      # On the laptop, pipe straight into the headless box:
      export CK_CREDS_PORTAL_TOKEN=$(ssh laptop ck-creds print-token)
      # …then on the headless box, every command skips auth:
      ck-creds list

    All status text is written to stderr, so the stdout capture stays clean —
    exactly the bare token, nothing else. If a cookie is supplied via
    --portal-token / CK_CREDS_PORTAL_TOKEN it is normalised and printed without
    launching a browser.
    """
    cfg = _load_config()
    # use_browser=True so that, with nothing injected, we capture via the
    # browser rather than falling through to headless live Path 1 auth — the
    # whole point of this command is "I have a browser here, mint me a cookie".
    token = _resolve_portal_token(cfg, portal_token, use_browser=True)
    # The ONLY thing on stdout — scriptable as $(ck-creds print-token).
    click.echo(token)


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


@cli.command("exec")
@click.option("--app", "-a", default=None, help="App name substring (must resolve to one app). Not needed with --browser-saml.")
@click.option("--role", "-r", default=None, help="Role name substring")
@click.option("--path2", is_flag=True, default=False)
@click.option(
    "--portal-token",
    default=None,
    help="Inject an x-amz-sso_authn portal cookie directly (Option B); "
    "skips M365/OIDC auth. Or set CK_CREDS_PORTAL_TOKEN.",
)
@click.option(
    "--browser",
    "use_browser",
    is_flag=True,
    default=False,
    help="Option A: open a browser to the AWS access portal, sign in via "
    "M365, and auto-capture the x-amz-sso_authn cookie. Or set CK_CREDS_BROWSER=1.",
)
@click.option(
    "--browser-saml",
    "browser_saml",
    is_flag=True,
    default=False,
    help="Option A-prime: sign in via M365 in a browser and intercept the AWS "
    "SAML assertion directly (no portal API). One app per sign-in.",
)
@click.option(
    "--saml-url",
    "saml_url",
    default=None,
    help="App-launch URL for --browser-saml (overrides saml_start_url config).",
)
@click.option(
    "--saml-timeout",
    "saml_timeout",
    type=int,
    default=None,
    help="Seconds to wait for the SAML sign-in with --browser-saml (default 180).",
)
@click.argument("command", nargs=-1, required=True)
def exec_cmd(app: Optional[str], role: Optional[str], path2: bool, portal_token: Optional[str], use_browser: bool, browser_saml: bool, saml_url: Optional[str], saml_timeout: Optional[int], command: tuple) -> None:
    """Assume a role and exec a command with credentials in the environment.

    \b
    Example:
      ck-creds exec --app "My-Account" -- aws s3 ls
      ck-creds exec --browser-saml -- aws s3 ls
    """
    cfg = _load_config()
    if path2:
        access_token = _get_oidc_token(cfg)
        sso = SsoClient(access_token=access_token, region=cfg["region"])
        entries = sso.list_account_roles()
        filtered = [e for e in entries if app and app.lower() in e.account_name.lower()]
        if not filtered:
            console.print(f"[red]No accounts matching '{app}'[/red]")
            sys.exit(1)
        chosen = pick_from_list(filtered, prompt="Select account/role", display_fn=lambda e: e.display_name, auto_select=len(filtered) == 1)
        creds = sso.get_credentials(chosen.account_id, chosen.role_name)
    elif browser_saml:
        # Option A-prime: assertion intercepted in-flight; --app is irrelevant.
        assertion = _capture_assertion_via_saml_intercept(cfg, saml_url, saml_timeout)
        chosen_role = _pick_role(assertion, role)
        creds = _assume(cfg, chosen_role, assertion)
    else:
        if not app:
            raise click.ClickException(
                "exec needs --app (or use --browser-saml / --path2)."
            )
        portal_session = _resolve_portal_token(cfg, portal_token, use_browser=use_browser)
        client = _make_portal_client(cfg, portal_session)
        inst, prof = _pick_app(client, app)

        assertion = _portal_guard(client.get_saml_assertion, prof.url)
        chosen_role = _pick_role(assertion, role)
        creds = _assume(cfg, chosen_role, assertion)

    env = {**os.environ, **creds.as_env()}
    result = subprocess.run(list(command), env=env)
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# credential-process
# ---------------------------------------------------------------------------


@cli.command("credential-process")
@click.option("--app", "-a", required=True, help="App name substring (must be unambiguous)")
@click.option("--role", "-r", default=None, help="Role name substring")
@click.option("--path2", is_flag=True, default=False)
@click.option(
    "--portal-token",
    default=None,
    help="Inject an x-amz-sso_authn portal cookie directly (Option B); "
    "skips M365/OIDC auth. Or set CK_CREDS_PORTAL_TOKEN.",
)
@click.option(
    "--browser",
    "use_browser",
    is_flag=True,
    default=False,
    help="Option A: open a browser to the AWS access portal, sign in via "
    "M365, and auto-capture the x-amz-sso_authn cookie. Or set CK_CREDS_BROWSER=1.",
)
def credential_process(app: str, role: Optional[str], path2: bool, portal_token: Optional[str], use_browser: bool) -> None:
    """Output credentials as JSON for AWS credential_process.

    \b
    Add to ~/.aws/config:
      [profile my-account]
      credential_process = ck-creds credential-process --path2 --app "My-Account-SSO"
    """
    cfg = _load_config()
    if path2:
        access_token = _get_oidc_token(cfg)
        sso = SsoClient(access_token=access_token, region=cfg["region"])
        entries = sso.list_account_roles()
        filtered = [e for e in entries if app.lower() in e.account_name.lower()]
        if not filtered:
            console.print(f"[red]No accounts matching '{app}'[/red]")
            sys.exit(1)
        if role:
            filtered = [e for e in filtered if role.lower() in e.role_name.lower()]
        if len(filtered) != 1:
            console.print(f"[red]Ambiguous match ({len(filtered)} entries) — use more specific --app/--role[/red]")
            sys.exit(1)
        chosen = filtered[0]
        creds = sso.get_credentials(chosen.account_id, chosen.role_name)
    else:
        portal_session = _resolve_portal_token(cfg, portal_token, use_browser=use_browser)
        client = _make_portal_client(cfg, portal_session)
        inst, prof = _pick_app(client, app)

        assertion = _portal_guard(client.get_saml_assertion, prof.url)
        chosen_role = _pick_role(assertion, role)
        creds = _assume(cfg, chosen_role, assertion)

    # AWS credential_process spec — printed to stdout (stderr carries status)
    print(json.dumps({
        "Version": 1,
        "AccessKeyId": creds.access_key_id,
        "SecretAccessKey": creds.secret_access_key,
        "SessionToken": creds.session_token,
        "Expiration": creds.expiration.isoformat(),
    }))


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


@cli.command()
def logout() -> None:
    """Clear all cached tokens (forces re-authentication on next use)."""
    cache = TokenCache()
    cache.clear_all()
    console.print("✅ [green]All cached tokens cleared.[/green] You will be prompted to log in again.")
