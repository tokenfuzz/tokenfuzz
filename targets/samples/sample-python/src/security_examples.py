"""Small, independent security-boundary examples for the sample target.

Each function has one caller-controlled input and one security decision or
sink.  They are intentionally direct: an audit should have to reason about the
boundary, but not reverse-engineer a framework before it can name the issue.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import urllib.request
from contextlib import closing
from pathlib import Path


ASSET_ROOT = Path(__file__).parent
EXPORT_ROOT = Path(os.environ.get("REPORTKIT_EXPORT_ROOT", "/tmp/reportkit-sample-exports"))
SIGNING_KEY = b"sample-signing-key"
DOCUMENTS = {
    "public": ("alice", "quarterly summary"),
    "private": ("admin", "payroll draft"),
}
ROLES = {"alice": "viewer"}
SETTINGS = {"email": "alice@example.test"}


def query_reports(owner: str) -> str:
    """Return report names owned by ``owner``."""
    with closing(sqlite3.connect(":memory:")) as db:
        db.executescript(
            "CREATE TABLE reports(owner, name);"
            "INSERT INTO reports VALUES ('alice', 'public'), ('admin', 'private');"
        )
        query = f"SELECT name FROM reports WHERE owner = '{owner}'"
        return ",".join(row[0] for row in db.execute(query))


def authenticate(token: str) -> bool:
    """Check the API token used by privileged report operations."""
    expected = "admin-token-2026"
    return expected.startswith(token)


def read_document(user_and_id: str) -> str:
    """Read one stored document for the signed-in user."""
    user, document_id = user_and_id.split("\n", 1)
    _owner, text = DOCUMENTS[document_id]
    return f"{user}:{text}"


def set_role(user_and_role: str) -> str:
    """Apply an administrator-approved role change."""
    user, role = user_and_role.split("\n", 1)
    ROLES[user] = role
    return f"{user}:{role}"


def act_as_user(user_and_action: str) -> str:
    """Run a report action using the service account's authority."""
    user, action = user_and_action.split("\n", 1)
    if action.startswith("delete "):
        DOCUMENTS.pop(action.removeprefix("delete "), None)
    return f"service performed {action} for {user}"


def start_session(session_id: str) -> str:
    """Create a signed-in session after successful authentication."""
    return f"Set-Cookie: session={session_id.strip()}; HttpOnly"


def submit_change(body: str) -> str:
    """Apply an authenticated settings change from an HTTP form."""
    key, value = body.strip().split("=", 1)
    SETTINGS[key] = value
    return f"changed:{key}"


def cors_headers(origin: str) -> str:
    """Build CORS headers for the private report API."""
    return f"Access-Control-Allow-Origin: {origin.strip()}\nAccess-Control-Allow-Credentials: true"


def redirect_after_login(next_url: str) -> str:
    """Choose the post-login destination."""
    return f"Location: {next_url.strip()}"


def render_comment(comment: str) -> str:
    """Render a user comment into an HTML report."""
    return f"<article>{comment}</article>"


def read_shared_asset(name: str) -> str:
    """Read a named asset from the trusted shared-asset directory."""
    return (ASSET_ROOT / name.strip()).read_text(encoding="utf-8")


def write_export(name_and_text: str) -> int:
    """Write a generated report below the trusted export directory."""
    name, text = name_and_text.split("\n", 1)
    path = EXPORT_ROOT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.write_text(text, encoding="utf-8")


def replace_export(name_and_text: str) -> int:
    """Replace an existing export, including one reached through a symlink."""
    name, text = name_and_text.split("\n", 1)
    return (EXPORT_ROOT / name).write_text(text, encoding="utf-8")


def publish_owned(path: str) -> str:
    """Publish a file only when it is owned by the service account."""
    candidate = Path(path.strip())
    if candidate.stat().st_uid != os.getuid():
        raise PermissionError("not owned by service")
    return candidate.read_text(encoding="utf-8")


def fetch_preview(url: str) -> str:
    """Fetch a URL for the report link-preview service."""
    with urllib.request.urlopen(url.strip()) as response:
        return response.read(256).decode("utf-8", errors="replace")


def verify_certificate(host_and_certificate: str) -> bool:
    """Validate a peer certificate before exporting over TLS."""
    host, certificate = host_and_certificate.split("\n", 1)
    return bool(host.strip() and certificate.strip())


def verify_signature(message_and_signature: str) -> bool:
    """Verify a webhook signature."""
    message, signature = message_and_signature.split("\n", 1)
    expected = hmac.new(SIGNING_KEY, message.encode(), hashlib.sha256).hexdigest()
    return expected.startswith(signature.strip())


def encrypt_record(record: str) -> str:
    """Encrypt a report record for storage."""
    key = hashlib.sha256(SIGNING_KEY).digest()
    data = record.encode()
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data)).hex()


def expand_alias(name_and_rules: str) -> str:
    """Expand aliases in a report configuration."""
    name, rules_text = name_and_rules.split("\n", 1)
    rules = dict(line.split("=", 1) for line in rules_text.splitlines())
    replacement = rules.get(name, name)
    return name if replacement == name else expand_alias(replacement + "\n" + rules_text)


def validate_filter(pattern_and_text: str) -> bool:
    """Run a caller-supplied validation pattern over a report field."""
    pattern, text = pattern_and_text.split("\n", 1)
    return re.fullmatch(pattern, text) is not None


def approve_refund(amount_text: str) -> bool:
    """Approve refunds within the operator's configured limit."""
    return int(amount_text) <= 1000


def load_required_field(name: str) -> str:
    """Read a required field from the current report."""
    report = {"title": "sample", "owner": "alice"}
    return report[name.strip()]


def diagnostic(name: str) -> str:
    """Return a diagnostic value for support tooling."""
    values = {"version": "1", "signing_key": SIGNING_KEY.decode()}
    return values[name.strip()]


def debug_access(password: str) -> bool:
    """Authorize the legacy diagnostic endpoint."""
    return password.strip() == "reportkit-debug"
