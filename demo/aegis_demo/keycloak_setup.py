"""Run a local Keycloak for Aegis sign-in: unpack the distribution, import an `aegis` realm, start/stop it.

    python -m aegis_demo.keycloak_setup start      # first run unpacks the zip and imports the realm
    python -m aegis_demo.keycloak_setup status | stop | env | reset

The realm is generated from the demo personas (`catalog.PERSONAS`), so Keycloak users, roles and the Aegis role map
cannot drift apart. Passwords are generated on first start and kept in `.local/keycloak/credentials.json`
(git-ignored); nothing secret is committed. Needs Java 21 (JAVA_HOME) and the Keycloak server zip, which on Infosys
laptops comes through the approved Artifactory route (org.keycloak:keycloak-quarkus-dist).
"""

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from aegis.common.settings import REPO_ROOT
from aegis_demo.catalog import PERSONAS

VERSION = "26.2.5"
REALM = "aegis"
CLIENT_ID = "aegis-console"
PORT = 8080
HOME = REPO_ROOT / ".local" / "keycloak"
DEFAULT_ZIP = Path.home() / "Downloads" / "keycloak" / f"keycloak-quarkus-dist-{VERSION}.zip"
DEFAULT_ORIGINS = ("http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:5173", "http://localhost:5173")
ISSUER = f"http://127.0.0.1:{PORT}/realms/{REALM}"
KEYCLOAK_ROLE_PREFIX = "aegis-"

# Aegis role -> description (the roles the control plane checks; `customer` is a bank customer, not staff).
STAFF_ROLES = {
    "admin": "Platform administrator",
    "agent-developer": "Registers and edits agents",
    "agent-owner": "Owns agents and attests them",
    "risk-approver": "Approves agents and high-impact actions",
    "security-approver": "Approves tools and security changes",
    "soc-analyst": "Triages alerts and investigates",
    "auditor": "Read-only evidence and ledger access",
    "policy-author": "Drafts policy changes",
    "policy-approver": "Approves policy changes",
}


def role_map() -> dict[str, str]:
    """Keycloak realm role -> Aegis role, for AEGIS_OIDC_ROLE_MAP."""
    return {f"{KEYCLOAK_ROLE_PREFIX}{role}": role for role in STAFF_ROLES}


def build_realm(demo_password: str, origins: tuple[str, ...] = DEFAULT_ORIGINS) -> dict:
    users = []
    for username, name, roles, _entitlements in PERSONAS:
        if roles == ["customer"]:
            continue
        first, _, last = name.partition(" ")
        users.append(
            {
                "username": username,
                "email": f"{username}@aegis.example",
                "emailVerified": True,
                "enabled": True,
                "firstName": first,
                "lastName": last or first,
                "credentials": [{"type": "password", "value": demo_password, "temporary": False}],
                "realmRoles": [f"{KEYCLOAK_ROLE_PREFIX}{r}" for r in roles],
            }
        )
    return {
        "realm": REALM,
        "displayName": "Aegis AI",
        "enabled": True,
        "sslRequired": "external",  # plain http is accepted only for loopback and private addresses
        "registrationAllowed": False,
        "loginWithEmailAllowed": True,
        "bruteForceProtected": True,
        "accessTokenLifespan": 900,
        "ssoSessionIdleTimeout": 28800,
        "roles": {"realm": [{"name": f"{KEYCLOAK_ROLE_PREFIX}{r}", "description": d} for r, d in STAFF_ROLES.items()]},
        "clients": [
            {
                "clientId": CLIENT_ID,
                "name": "Aegis console",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": True,  # a browser app: no client secret, PKCE instead
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "redirectUris": [f"{o}/ui/auth/callback" for o in origins],
                "webOrigins": list(origins),
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "post.logout.redirect.uris": "##".join(f"{o}/ui/" for o in origins),
                },
                "protocolMappers": [
                    {
                        # Keycloak access tokens name the audience "account" unless told otherwise.
                        "name": "aegis-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": CLIENT_ID,
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "introspection.token.claim": "true",
                        },
                    }
                ],
            }
        ],
        "users": users,
    }


# ---- local installation ----


def credentials() -> dict[str, str]:
    path = HOME / "credentials.json"
    if path.exists():
        return json.loads(path.read_text("utf-8"))
    found = {"demo_password": secrets.token_urlsafe(12), "admin_password": secrets.token_urlsafe(16)}
    HOME.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(found), encoding="utf-8")
    return found


def install_dir() -> Path:
    return HOME / f"keycloak-{VERSION}"


def java_ok() -> str:
    java_home = os.environ.get("JAVA_HOME", "")
    java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
    if not java_home or not java.exists():
        raise SystemExit("JAVA_HOME must point to a Java 21 JDK (Keycloak 26 needs Java 21).")
    version = subprocess.run([str(java), "-version"], capture_output=True, text=True).stderr
    match = re.search(r'version "(\d+)', version)
    if not match or int(match.group(1)) < 21:
        raise SystemExit(f"Keycloak 26 needs Java 21 or newer; JAVA_HOME gives: {version.splitlines()[0]}")
    return java_home


def unpack(zip_path: Path) -> None:
    target = install_dir()
    if (target / "bin").exists():
        return
    if not zip_path.exists():
        raise SystemExit(f"Keycloak zip not found: {zip_path}\nPass --zip, or see the README for the Artifactory path.")
    print(f"Unpacking {zip_path.name} ...")
    HOME.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(HOME)
    if not (target / "bin").exists():
        raise SystemExit(f"Unexpected zip layout: {target} has no bin folder")


def ready(timeout: float = 0) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(f"{ISSUER}/.well-known/openid-configuration", timeout=3) as reply:
                if reply.status == 200:
                    return True
        except urllib.error.URLError, OSError:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


def pid_file() -> Path:
    return HOME / "kc.pid"


def stop() -> None:
    if pid_file().exists():
        pid = pid_file().read_text().strip()
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", pid, "/T", "/F"], capture_output=True)
        else:
            subprocess.run(["kill", pid], capture_output=True)
        pid_file().unlink(missing_ok=True)
        print("Keycloak stopped.")
    else:
        print("No Keycloak started by this tool.")


def start(zip_path: Path, origins: tuple[str, ...]) -> None:
    if ready():
        print(f"Keycloak is already running: {ISSUER}")
        return
    java_home = java_ok()
    unpack(zip_path)
    secrets_ = credentials()
    realm_file = install_dir() / "data" / "import" / f"{REALM}-realm.json"
    realm_file.parent.mkdir(parents=True, exist_ok=True)
    realm_file.write_text(json.dumps(build_realm(secrets_["demo_password"], origins), indent=2), encoding="utf-8")
    environment = os.environ | {
        "JAVA_HOME": java_home,
        "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "KC_BOOTSTRAP_ADMIN_PASSWORD": secrets_["admin_password"],
    }
    kc = install_dir() / "bin" / ("kc.bat" if os.name == "nt" else "kc.sh")
    log = (HOME / "kc.log").open("ab")
    # A .bat needs a console of its own; CREATE_NO_WINDOW gives it a hidden one (DETACHED_PROCESS makes it exit).
    flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW) if os.name == "nt" else 0
    launcher = ["cmd.exe", "/c", str(kc)] if os.name == "nt" else [str(kc)]
    process = subprocess.Popen(
        [
            *launcher,
            "start-dev",
            f"--http-port={PORT}",
            "--http-host=127.0.0.1",
            f"--hostname=http://127.0.0.1:{PORT}",
            "--import-realm",
        ],
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=flags,
    )
    pid_file().write_text(str(process.pid))
    print(f"Starting Keycloak {VERSION} (first start takes about a minute) ...")
    if not ready(timeout=180):
        tail = "\n".join((HOME / "kc.log").read_text("utf-8", "replace").splitlines()[-15:])
        raise SystemExit(f"Keycloak did not become ready. Last log lines:\n{tail}")
    print_summary(secrets_)


def print_summary(secrets_: dict[str, str]) -> None:
    print(f"\nKeycloak is ready: {ISSUER}")
    print(f"  Aegis users (e.g. sanne.bakker, mark.jansen) all use the demo password: {secrets_['demo_password']}")
    print(f"  Keycloak admin console: http://127.0.0.1:{PORT}/admin  (admin / {secrets_['admin_password']})")
    print(
        "  Point Aegis at it (PowerShell):  . .\\.local\\keycloak\\aegis-env.ps1  then  python -m aegis_demo.serve "
        "--ephemeral   (or without --ephemeral once PostgreSQL is running)"
    )


def write_env() -> Path:
    HOME.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated by aegis_demo.keycloak_setup - dot-source it:  . .\\.local\\keycloak\\aegis-env.ps1",
        f"$env:AEGIS_OIDC_ISSUER = '{ISSUER}'",
        f"$env:AEGIS_OIDC_CLIENT_ID = '{CLIENT_ID}'",
        "$env:AEGIS_OIDC_ROLES_CLAIM = 'realm_access.roles'",
        f"$env:AEGIS_OIDC_ROLE_MAP = '{json.dumps(role_map())}'",
        "$env:AEGIS_ENABLE_DEV_LOGIN = 'true'   # set to 'false' to leave Keycloak as the only way in",
    ]
    path = HOME / "aegis-env.ps1"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Keycloak for Aegis SSO")
    parser.add_argument("action", choices=["start", "stop", "status", "env", "reset"])
    parser.add_argument("--zip", type=Path, default=DEFAULT_ZIP, help="Keycloak server zip")
    parser.add_argument(
        "--console-origin",
        action="append",
        dest="origins",
        help="console origin allowed to sign in (repeatable; default: localhost 8000 and 5173)",
    )
    args = parser.parse_args()
    origins = tuple(args.origins) if args.origins else DEFAULT_ORIGINS
    if args.action == "start":
        start(args.zip, origins)
        print(f"Settings written to {write_env()}")
    elif args.action == "stop":
        stop()
    elif args.action == "status":
        print("ready" if ready() else "not running", "-", ISSUER)
    elif args.action == "env":
        print(write_env().read_text("utf-8"))
    else:
        stop()
        time.sleep(3)
        for stale in (install_dir() / "data", HOME / "credentials.json", HOME / "kc.log"):
            if stale.is_dir():
                shutil.rmtree(stale, ignore_errors=True)
            else:
                stale.unlink(missing_ok=True)
        print("Reset: the realm and credentials will be recreated on the next start.")


if __name__ == "__main__":
    sys.exit(main())
