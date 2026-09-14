"""reportkit_service — the HTTP face of the reportkit toolkit.

Browsers and CI jobs reach reportkit through a small set of routes. ``respond``
turns one raw HTTP/1.1 request into a response; ``serve`` accepts connections
on a socket and answers each with it, one thread per connection so a slow
export does not hold up the next client. ``reportkit_cli``'s ``request``
operation feeds ``respond`` a request read from a job file, so every route is
scriptable without a listening socket.

A signed-in browser carries a ``session`` cookie. Routes that change or
disclose account data resolve that cookie to a user first.
"""
from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import urllib.parse

import security_examples

_REASONS = {200: "OK", 302: "Found", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}


def parse_request(raw: str) -> tuple[str, str, dict[str, str], str]:
    """Split a raw request into method, target, lower-cased headers, and body."""
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    lines = head.splitlines()
    method, target = lines[0].split()[:2]
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return method, target, headers, body


def _reply(status: int, headers: list[str], body: str) -> str:
    lines = [f"HTTP/1.1 {status} {_REASONS.get(status, '')}".rstrip(), *headers, "", body]
    return "\n".join(lines)


def _session_cookie(headers: dict[str, str]) -> str:
    for part in headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return value
    return ""


def _signed_in_user(headers: dict[str, str]) -> str:
    return security_examples.resume_session(_session_cookie(headers))


def respond(raw: str) -> str:
    """Answer one request. Only an authorization refusal is turned into a
    response; any other failure propagates to the caller."""
    method, target, headers, body = parse_request(raw)
    path, _, query = target.partition("?")
    params = dict(urllib.parse.parse_qsl(query))
    try:
        if path == "/login" and method == "POST":
            if not security_examples.authenticate(body.strip()):
                return _reply(401, [], "bad token")
            # A browser that already carries a session cookie keeps it.
            cookie = security_examples.start_session(
                _session_cookie(headers) or secrets.token_hex(8)
            )
            if "next" in params:
                location = security_examples.redirect_after_login(params["next"])
                return _reply(302, [cookie, location], "")
            return _reply(200, [cookie], "signed in")
        if path == "/settings" and method == "POST":
            user = _signed_in_user(headers)
            return _reply(200, [], f"{security_examples.submit_change(body)} for {user}")
        if path == "/api/private":
            user = _signed_in_user(headers)
            cors = security_examples.cors_headers(headers.get("origin", "")).splitlines()
            return _reply(200, cors, security_examples.read_document(f"{user}\nprivate"))
        if path == "/payroll":
            return _reply(200, [], security_examples.read_payroll(_signed_in_user(headers)))
        if path == "/role" and method == "POST":
            _signed_in_user(headers)
            return _reply(200, [], security_examples.set_role(body))
        if path == "/refund" and method == "POST":
            _signed_in_user(headers)
            return _reply(200, [], security_examples.apply_refund(body))
        if path == "/export/link" and method == "POST":
            return _reply(200, [], security_examples.link_export(body))
        if path == "/export/replace" and method == "POST":
            return _reply(200, [], str(security_examples.replace_export(body)))
        if path == "/publish" and method == "POST":
            return _reply(200, [], security_examples.publish_owned(body))
        if path == "/alias" and method == "POST":
            return _reply(200, [], security_examples.expand_alias(body))
        if path == "/field" and method == "POST":
            return _reply(200, [], security_examples.load_required_field(body))
    except PermissionError as refused:
        return _reply(403, [], str(refused))
    return _reply(404, [], "no such route")


def _abort_service(args: threading.ExceptHookArgs) -> None:
    # A request that failed mid-update may have left the ledger or the role
    # map half-applied; the supervisor restarts a clean process rather than
    # letting the remaining threads serve from that state.
    print(f"reportkit_service: fatal {args.exc_type.__name__}: {args.exc_value}", file=sys.stderr)
    os._exit(70)


def serve(host: str = "127.0.0.1", port: int = 8474) -> None:
    """Answer requests until the process is stopped."""
    threading.excepthook = _abort_service
    with socket.create_server((host, port)) as listener:
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=_answer, args=(connection,), daemon=True).start()


def _answer(connection: socket.socket) -> None:
    with connection:
        raw = connection.recv(65536).decode("utf-8", errors="replace")
        connection.sendall(respond(raw).encode("utf-8"))
