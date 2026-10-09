"""Check Azure configuration, or explicitly make one paid call through the running local Aegis server."""

import argparse
import asyncio
import json
import logging

import httpx


def local_base_url(value: str) -> str:
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL:
        raise argparse.ArgumentTypeError("Use a local Aegis server URL.") from None
    if (
        url.scheme not in ("http", "https")
        or url.host not in ("127.0.0.1", "localhost", "::1")
        or url.path not in ("", "/")
        or url.userinfo
        or url.query
        or url.fragment
    ):
        raise argparse.ArgumentTypeError("Only a loopback Aegis server URL is permitted by this demo command.")
    return str(url).rstrip("/")


def checked_json(response: httpx.Response) -> dict:
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(
            "The local server returned a non-JSON response. Check the console version and server URL."
        ) from None
    if not isinstance(data, dict):
        raise RuntimeError("The local server returned an unexpected response.")
    if response.status_code != 200:
        if response.status_code == 404:
            raise RuntimeError(
                "The console does not have the new smoke endpoint. Load the updated server when ready; "
                "this command does not restart it."
            )
        detail = data.get("detail", data.get("error", "The local server refused the request."))
        if isinstance(detail, dict):
            detail = f"{detail.get('code', 'error')}: {detail.get('message', 'Request refused.')}"
        if not isinstance(detail, str):
            detail = "The local server refused the request."
        raise RuntimeError(f"HTTP {response.status_code}: {detail}")
    return data


async def run(base_url: str, call: bool) -> dict:
    # No environment proxy for loopback, no redirects, no automatic retries, and no cloud credentials here.
    async with httpx.AsyncClient(base_url=base_url, timeout=90.0, trust_env=False, follow_redirects=False) as http:
        login = checked_json(await http.post("/idp/login", json={"username": "jan.devries"}))
        token = login.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("The local development identity provider did not issue a user token.")
        headers = {"authorization": f"Bearer {token}"}
        status = checked_json(await http.get("/demo/api/llm/status", headers=headers))
        if not call:
            return status
        if not status.get("ready") or status.get("provider") != "azure-openai":
            error = status.get("error", {})
            raise RuntimeError(error.get("message", "Azure is not configured on the running server."))
        return checked_json(
            await http.post("/demo/api/llm/smoke", headers=headers, json={"confirm_external_call": True})
        )


def main() -> int:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", type=local_base_url, default="http://127.0.0.1:8000")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Configuration only, no Azure call (the default).")
    mode.add_argument("--call", action="store_true", help="Make ONE paid Azure request using a fixed synthetic prompt.")
    args = parser.parse_args()
    try:
        result = asyncio.run(run(args.base_url, args.call))
    except httpx.TimeoutException:
        print("Request timed out. If --call was used, Azure may have processed it. Check Aegis usage before retrying.")
        return 1
    except httpx.HTTPError:
        print("Cannot reach the local Aegis console. This command does not start or restart the app.")
        return 1
    except RuntimeError as exc:
        print(str(exc))
        return 1
    except KeyboardInterrupt:
        print("Interrupted. If --call was used, inspect Aegis usage before retrying.")
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if result.get("ready", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
