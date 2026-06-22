# ck-creds CLI

Terminal credential helper for AWS SAML applications via M365 SSO.  
No browser after the first login — silent token refresh handles renewals automatically.

---

## How it works

### Path 1 — M365 SAML (requires custom Azure AD app registration)

```
M365 device-code login (once)
    │
    ▼
Azure AD issues SAML assertion → IAM Identity Center ACS
    │
    ▼
Portal session cookie (cached in ~/.ck_creds/)
    │
    ▼
List customer SAML app instances via IAM Identity Center portal API
    │
    ▼
Fetch per-app SAML assertion → STS.AssumeRoleWithSAML
    │
    ▼
Temporary credentials → ~/.aws/credentials
```

### Path 2 — AWS SSO OIDC (recommended, works out of the box)

```
AWS SSO OIDC device-code login (once per ~8h)
    │   (opens your SSO access portal — M365 SSO happens there)
    ▼
OIDC accessToken (cached in ~/.ck_creds/oidc_portal_token.json)
    │
    ▼
boto3 SSO: list_accounts + list_account_roles
    │
    ▼
boto3 SSO: get_role_credentials → STS temp creds
    │
    ▼
Temporary credentials → ~/.aws/credentials
```

> **Note:** The OIDC `accessToken` from AWS SSO OIDC works with the **boto3 SSO API**
> (`list_accounts`, `list_account_roles`, `get_role_credentials`) but **not** with the
> IAM Identity Center portal HTTP API (`portal.sso.*.amazonaws.com`), which requires a
> SAML-exchange cookie. Path 2 therefore uses the boto3 SDK directly — this is the
> documented AWS approach and requires no custom Azure AD app registration.

---

## Prerequisites

- Python 3.9+
- Access to the IAM Identity Center Azure AD enterprise app in your M365 tenant
- Assigned to at least one SAML application in IAM Identity Center

### Install

```bash
git clone https://github.com/<your-fork>/CloudKeeper-Credential-Helper.git
cd CloudKeeper-Credential-Helper
pip install -e ".[dev]"        # or: uv pip install -e ".[dev]"
ck-creds --version
```

---

## Setup

```bash
ck-creds configure
```

Prompts you for:

| Prompt | Where to find it |
|--------|-----------------|
| Azure AD Tenant ID | portal.azure.com → Azure Active Directory → Overview |
| Azure App Client ID | Enterprise app → Overview → Application (client) ID (default: MS CLI public app) |
| IAM Identity Center App ID URI | Enterprise app → Expose an API → Application ID URI |
| IAM Identity Center Azure App ID | Enterprise app → Overview → Object ID (used for IdP-initiated SAML) |
| AWS SSO Start URL | IAM Identity Center console → Settings → AWS access portal URL |
| AWS Region | IAM Identity Center console → Settings (e.g. `eu-west-1`) |

Config is saved to `~/.ck_creds/config.json` (mode `0600`).

---

## Usage

### First login

```bash
ck-creds login
# Device code flow — visit https://microsoft.com/devicelogin and enter the code shown.
# Credentials written to ~/.aws/credentials [default].
```

Subsequent logins are silent (MSAL refreshes the token automatically). Re-authentication is only needed when the refresh token expires (~90 days).

### Login to a specific profile

```bash
ck-creds login --profile customer-a-admin
ck-creds login --app "MyAccount" --role "AdministratorAccess" --profile myaccount-admin
```

`--app` and `--role` accept name substrings — if unambiguous they auto-select, otherwise you get an interactive picker.

### List available applications

```bash
ck-creds list
```

### Run a command with credentials injected into the environment

```bash
ck-creds exec --app "Customer A" --role Admin -- aws s3 ls
ck-creds exec --app "Customer B" -- terraform plan
ck-creds exec --app "Staging" -- env | grep AWS
```

The subprocess inherits your full environment plus `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.

### Zero-touch auto-refresh via `credential_process`

Add to `~/.aws/config`:

```ini
[profile customer-a-admin]
credential_process = ck-creds credential-process --app "Customer A" --role Admin

[profile customer-b-readonly]
credential_process = ck-creds credential-process --app "Customer B" --role ReadOnly

[profile staging-admin]
credential_process = ck-creds credential-process --app "Staging-Account" --role AdministratorAccess
```

Then use any AWS tool normally — credentials are fetched (and silently refreshed) on demand:

```bash
aws s3 ls --profile customer-a-admin
AWS_PROFILE=staging-admin terraform plan
```

### Logout

```bash
ck-creds logout
# Clears all cached tokens. Next command triggers a new device-code flow.
```

---

## Path 2 — AWS SSO OIDC (Recommended)

Path 2 uses the AWS SSO OIDC device flow — the same flow `aws sso login` uses.
Your browser opens the AWS access portal (which triggers M365 SSO there), rather
than calling Azure AD directly from the CLI. No custom Azure AD app registration needed.

```bash
ck-creds login --path2
ck-creds list --path2
ck-creds exec --app "MyAccount-SSO" --path2 -- aws sts get-caller-identity
ck-creds credential-process --app "MyAccount-SSO" --path2
```

**Token TTL:** ~8 hours. After expiry you'll get a new device-code prompt.
The token is cached at `~/.ck_creds/oidc_portal_token.json`.

### Path 2 `credential_process` (zero-touch rotation)

```ini
# ~/.aws/config
[profile myaccount-sso]
credential_process = ck-creds credential-process --path2 --app "MyAccount-SSO"
```

```bash
# Then use normally — ck-creds is called automatically on expiry
aws sts get-caller-identity --profile myaccount-sso
AWS_PROFILE=myaccount-sso terraform plan
```

### Path 1 status (M365 SAML direct)

Path 1 requires a **custom Azure AD app registration** with API permission for the
IAM Identity Center enterprise app. The default MS CLI public app (`04b07795-...`)
will return `AADSTS650057`. See `TODO.txt` for the setup steps.

---

## File locations

| File | Purpose |
|------|---------| 
| `~/.ck_creds/config.json` | Configuration (0600) |
| `~/.ck_creds/msal_cache.bin` | MSAL token cache — Path 1 (0600) |
| `~/.ck_creds/portal_token.json` | Path 1 portal session cookie (0600) |
| `~/.ck_creds/oidc_portal_token.json` | Path 2 OIDC access token, ~8h TTL (0600) |
| `~/.aws/credentials` | STS temporary credentials |
| `~/.aws/config` | AWS profiles with `credential_process` |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `AADSTS650057` (Path 1) | Public MS CLI app not permitted for this resource | Register a custom Azure AD app — see `TODO.txt` |
| `SAMLResponse not found in Azure AD response` | Wrong `iic_azure_app_id` or scope | `ck-creds logout` → reconfigure → `ck-creds login` |
| `No SAML applications found` | User not assigned in IAM Identity Center | Check IAM Identity Center → Applications → Assign users |
| `No x-amz-sso_authn cookie` | Portal ACS endpoint changed | Use `--path2` |
| `Portal API returns 401` with `--path2` | OIDC token ≠ portal cookie — by design | Normal; Path 2 uses boto3 SSO API, not portal HTTP |
| `Portal API returns 401` (Path 1) | Portal token expired | `ck-creds logout && ck-creds login` |
| `Portal API returns 404` | Wrong region in config | Check `region` in `~/.ck_creds/config.json` |
| `durationSeconds exceeds MaxSessionDuration` | Role max session < 12h | Automatic — CLI retries with 4h → 1h → 15m |
| `AADSTS700016` (MSAL) | Client ID not found in tenant | Verify `tenant_id` and `client_id` in config |
| `FileNotFoundError: aws` in exec | `aws` CLI not installed | Install awscli or use a full command path |
| `ck-creds` imports wrong `cli` module | `/opt/hermes` in PYTHONPATH | Run via `env -u PYTHONPATH .venv/bin/python ck_creds_entry.py` |

---

## Development

```bash
# Install with dev dependencies
uv pip install -e ".[dev]"

# Run unit tests
pytest tests/ -v

# Run integration smoke test (requires real creds + network)
CK_INTEGRATION=1 pytest tests/test_integration_smoke.py -v -s
```

### Project layout

```
cli/
├── auth/
│   ├── token_cache.py      # File-backed token cache (~/.ck_creds/)
│   ├── msal_auth.py        # M365 device-code + silent refresh (Path 1 auth leg)
│   └── oidc_auth.py        # AWS SSO OIDC device flow (Path 2 auth leg)
├── portal/
│   ├── saml_exchange.py    # M365 access token → IAM Identity Center session cookie
│   ├── portal_client.py    # List app instances, profiles, fetch SAML assertions (Path 1)
│   └── saml_parser.py      # Decode SAML XML → role ARN + principal ARN pairs
├── aws/
│   ├── sso_client.py       # boto3 SSO: list accounts/roles, get_role_credentials (Path 2)
│   ├── sts_client.py       # AssumeRoleWithSAML with duration fallback ladder (Path 1)
│   └── credentials_writer.py  # Safe upsert of ~/.aws/credentials profiles
├── ui/
│   └── picker.py           # Rich interactive list picker with filter
└── main.py                 # Click CLI entrypoint
```
