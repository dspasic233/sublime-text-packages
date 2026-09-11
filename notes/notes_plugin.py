# =============================================================================
# notes_plugin.py  —  Sublime Text 4 Notes Plugin (ST4Notes)
# Package: notes/  (Sublime Text Packages directory)
# =============================================================================

from __future__ import annotations

import os
import re
import sys
import ssl
import json
import time
import tempfile
import logging
import threading
import webbrowser
import subprocess
from datetime import datetime, date as datetime_date, timedelta
from urllib.request import Request, urlopen, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error   import URLError, HTTPError
from urllib.parse   import quote, urlparse
import ipaddress

import sublime
import sublime_plugin


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_NOTES_PATH = "~/Documents/ST4Notes"


def _notes_file() -> str:
    """Absolute path to the notes file (settings: notes_file)."""
    path = _settings().get("notes_file", _DEFAULT_NOTES_PATH)
    if not isinstance(path, str) or not path.strip():
        path = _DEFAULT_NOTES_PATH
    return os.path.expanduser(path.strip())


_TICKET_RE               = re.compile(r"^[A-Z0-9][A-Z0-9_\-]{0,63}$")
_NEW_TICKET_LABEL        = "[ + Create new issue (YouTrack) ]"
_IMPORT_FROM_YT_ME_LABEL  = "[ + Import from YouTrack (assigned to me) ]"
_IMPORT_FROM_YT_ALL_LABEL = "[ + Import from YouTrack (all) ]"
_OPEN_BY_ID_LABEL        = "[ + Open by ticket ID... ]"
_TODO_ID           = "TODO"
_OPS_ID            = "OPS"
_TODO_SEARCH_LABEL = "TODO (all days)"
_URL_RE            = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
)
# Inline ticket pattern: e.g. PROJ-1234, ABC-99
_INLINE_TICKET_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]{0,30}-\d+)\b",
    re.IGNORECASE,
)

# Maximum bytes read from a single API response
_API_MAX_RESPONSE_BYTES      = 512 * 1024      # 512 KB — single issue / small calls
_API_MAX_RESPONSE_BYTES_LIST = 8 * 1024 * 1024 # 8 MB  — list endpoints

log = logging.getLogger("ST4Notes")


# ---------------------------------------------------------------------------
# Browser helper
# ---------------------------------------------------------------------------

def _open_in_browser(url: str) -> None:
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", url])
        elif sys.platform == "win32":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", url])
    except Exception:
        try:
            webbrowser.open(url)
        except Exception as exc:
            log.error("Cannot open browser: %s", exc)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_SETTINGS_FILE = "ST4Notes.sublime-settings"


def _settings() -> sublime.Settings:
    return sublime.load_settings(_SETTINGS_FILE)


def _youtrack_base() -> str:
    base = _settings().get("youtrack_base", "").strip()
    if base and not base.endswith("/"):
        base += "/"
    return base


def _youtrack_api_root() -> str:
    base = _youtrack_base()
    if not base:
        return ""
    api_root = re.sub(r"/issues?/?$", "", base.rstrip("/"))
    return api_root + "/api"


def _youtrack_token() -> str:
    return _settings().get("youtrack_token", "").strip()


def _default_project() -> str:
    return _settings().get("default_project", "").strip().upper()


def _issue_stages() -> list[str]:
    stages = _settings().get("issue_stages", [])
    if not isinstance(stages, list):
        return []
    return [str(s).strip() for s in stages if str(s).strip()]


def _api_timeout() -> int:
    val = _settings().get("api_timeout_sec", 10)
    try:
        return max(3, min(60, int(val)))
    except (TypeError, ValueError):
        return 10


def _api_max_retries() -> int:
    val = _settings().get("api_max_retries", 2)
    try:
        return max(0, min(5, int(val)))
    except (TypeError, ValueError):
        return 2


def _post_comments_enabled() -> bool:
    """Global toggle: whether to post YouTrack comments when adding notes."""
    val = _settings().get("post_comments", False)
    if isinstance(val, bool):
        return val
    return False


# ---------------------------------------------------------------------------
# Security: base URL validation + host guard
# ---------------------------------------------------------------------------

def _is_blocked_ip_literal(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # CGNAT 100.64.0.0/10 (is_private covers this on modern Python; keep explicit)
    if isinstance(ip, ipaddress.IPv4Address):
        return ipaddress.IPv4Address("100.64.0.0") <= ip <= ipaddress.IPv4Address("100.127.255.255")
    return False


def _validate_youtrack_base(base: str) -> str | None:
    if not base:
        return None

    parsed = urlparse(base)

    if parsed.scheme != "https":
        return (
            "youtrack_base must start with https://\n"
            "Plain http is rejected because the Bearer token would be "
            "transmitted in cleartext."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "youtrack_base has no hostname."

    if _is_blocked_ip_literal(hostname):
        return (
            f"youtrack_base hostname '{hostname}' is a loopback/private/"
            "link-local address.\n"
            "Point youtrack_base at your public YouTrack instance."
        )

    _BLOCKED_EXACT = {
        "localhost",
        "metadata.google.internal",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
    if hostname in _BLOCKED_EXACT or hostname.endswith(".local"):
        return (
            f"youtrack_base hostname '{hostname}' is blocked.\n"
            "Point youtrack_base at your public YouTrack instance."
        )

    _BLOCKED_PREFIXES = (
        "localhost.", "127.", "0.", "10.", "192.168.", "169.254.",
    )
    _BLOCKED_RANGES_172 = range(16, 32)

    if any(hostname == p.rstrip(".") or hostname.startswith(p) for p in _BLOCKED_PREFIXES):
        return (
            f"youtrack_base hostname '{hostname}' is a loopback or private address.\n"
            "Point youtrack_base at your public YouTrack instance."
        )

    # Dotted hostname that is actually an IPv4 string already handled; also
    # reject 172.16–31.* and 100.64–127.* when written as DNS-looking labels.
    parts = hostname.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if _is_blocked_ip_literal(hostname):
            return (
                f"youtrack_base hostname '{hostname}' is a private address.\n"
                "Point youtrack_base at your public YouTrack instance."
            )
    if (
        len(parts) >= 2
        and parts[0] == "172"
        and parts[1].isdigit()
        and int(parts[1]) in _BLOCKED_RANGES_172
    ):
        return (
            f"youtrack_base hostname '{hostname}' is in a private IP range.\n"
            "Point youtrack_base at your public YouTrack instance."
        )
    if (
        len(parts) >= 2
        and parts[0] == "100"
        and parts[1].isdigit()
        and 64 <= int(parts[1]) <= 127
    ):
        return (
            f"youtrack_base hostname '{hostname}' is in the CGNAT range.\n"
            "Point youtrack_base at your public YouTrack instance."
        )

    return None


def _youtrack_host() -> str:
    base = _youtrack_base()
    if not base:
        return ""
    try:
        return urlparse(base).hostname or ""
    except Exception:
        return ""


def _is_youtrack_host(url: str) -> bool:
    yt_host = _youtrack_host()
    if not yt_host:
        return False
    try:
        url_host = urlparse(url).hostname or ""
    except Exception:
        return False
    return url_host.lower() == yt_host.lower()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _today_header() -> str:
    now = datetime.now()
    return f"# {now.year}.{now.month}.{now.day}"


def _now_hhmm() -> str:
    return datetime.now().strftime("%H:%M")


_SEP    = "# " + "=" * 77
_SEP_RE = re.compile(r"^# =+\s*$")


def _is_sep(line: str) -> bool:
    return bool(_SEP_RE.match(line))


def _is_stnotes_view(view: sublime.View) -> bool:
    if "stnotes" in view.scope_name(0):
        return True
    fname = view.file_name() or ""
    return fname == _notes_file()


def _is_notes_scratch_view(view: sublime.View) -> bool:
    """
    Return True for any scratch view produced by this plugin
    (Weekly Summary, Weekly Search, Notes: Search, Notes: TODO, etc.).
    """
    name = view.settings().get("stnotes_view_name", "")
    return bool(name)


def _is_weekly_summary_view(view: sublime.View) -> bool:
    """Return True for scratch views produced by Weekly Summary / Weekly Search."""
    name = view.settings().get("stnotes_view_name", "")
    return bool(name) and name.startswith("Notes: Weekly")


# ---------------------------------------------------------------------------
# File I/O  (atomic write) + mtime-keyed read cache
# ---------------------------------------------------------------------------

_notes_cache_lock   = threading.Lock()
_notes_cache_mtime: float | None = None
_notes_cache_lines: list[str]    = []


def _read_notes(force: bool = False) -> list[str]:
    global _notes_cache_mtime, _notes_cache_lines

    if os.path.isdir(_notes_file()):
        raise RuntimeError(f"Notes path '{_notes_file()}' is a directory, not a file.")

    if not os.path.exists(_notes_file()):
        return []

    try:
        mtime = os.path.getmtime(_notes_file())
    except OSError:
        mtime = 0.0

    with _notes_cache_lock:
        if not force and _notes_cache_mtime == mtime and _notes_cache_lines is not None:
            return list(_notes_cache_lines)

        try:
            with open(_notes_file(), "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except PermissionError:
            raise RuntimeError(f"Permission denied reading '{_notes_file()}'.")
        except OSError as exc:
            raise RuntimeError(f"Cannot read notes file: {exc}") from exc

        _notes_cache_mtime = mtime
        _notes_cache_lines = lines
        return list(lines)


def _invalidate_notes_cache() -> None:
    global _notes_cache_mtime
    with _notes_cache_lock:
        _notes_cache_mtime = None


def _write_notes(lines: list[str]) -> None:
    notes_dir = os.path.dirname(_notes_file()) or os.path.expanduser("~")
    try:
        os.makedirs(notes_dir, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot create notes directory '{notes_dir}': {exc}"
        ) from exc

    content = "\n".join(lines) + ("\n" if lines else "")
    try:
        fd, tmp_path = tempfile.mkstemp(dir=notes_dir, prefix=".ST4Notes_tmp_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, _notes_file())
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except PermissionError:
        raise RuntimeError(f"Permission denied writing to '{_notes_file()}'.")
    except OSError as exc:
        raise RuntimeError(f"Cannot write notes file: {exc}") from exc

    _invalidate_notes_cache()


# ---------------------------------------------------------------------------
# Ticket index cache (mtime-keyed)
# ---------------------------------------------------------------------------

_index_cache_lock   = threading.Lock()
_index_cache_mtime: float | None = None
_index_cache_data:  dict | None  = None


def _get_ticket_index() -> tuple[dict[str, list[str]], list[str]]:
    global _index_cache_mtime, _index_cache_data

    try:
        mtime = os.path.getmtime(_notes_file()) if os.path.exists(_notes_file()) else 0.0
    except OSError:
        mtime = 0.0

    with _index_cache_lock:
        if _index_cache_mtime == mtime and _index_cache_data is not None:
            return _index_cache_data["index"], _index_cache_data["tickets"]

    lines   = _read_notes()
    index   = _build_ticket_index(lines)
    tickets = _all_tickets_sorted(index)

    with _index_cache_lock:
        _index_cache_mtime = mtime
        _index_cache_data  = {"index": index, "tickets": tickets}

    return index, tickets


# ---------------------------------------------------------------------------
# Section / block location
# ---------------------------------------------------------------------------

def _find_today_section(lines: list[str]) -> tuple[int | None, ...]:
    header = _today_header()
    for idx, line in enumerate(lines):
        if line.strip() != header:
            continue
        open_sep  = idx - 1 if (idx > 0 and _is_sep(lines[idx - 1])) else None
        hdr_close = idx + 1
        if hdr_close < len(lines) and _is_sep(lines[hdr_close]):
            content_start = hdr_close + 1
        else:
            hdr_close     = None
            content_start = idx + 1
        next_sep = len(lines)
        for j in range(content_start, len(lines)):
            if _is_sep(lines[j]):
                next_sep = j
                break
        content_end = next_sep - 1
        while content_end >= content_start and not lines[content_end].strip():
            content_end -= 1
        if content_end < content_start:
            content_end = content_start - 1
        return open_sep, idx, hdr_close, content_start, content_end, next_sep
    return None, None, None, None, None, None


def _find_ticket_in_section(
    lines: list[str], content_start: int, content_end: int, ticket_id: str
) -> int | None:
    needle        = f"# {ticket_id}:"
    found_header: int | None = None
    for i in range(content_start, content_end + 1):
        if lines[i].strip().upper() == needle.upper():
            found_header = i
    if found_header is None:
        return None
    last_entry = found_header
    for i in range(found_header + 1, content_end + 1):
        stripped = lines[i].strip()
        if stripped.startswith("- "):
            last_entry = i
        elif stripped.upper().startswith("# "):
            break
    return last_entry


def _get_today_tickets() -> list[str]:
    try:
        lines = _read_notes()
    except RuntimeError:
        return []
    (_, hdr_idx, _, content_start, content_end, _) = _find_today_section(lines)
    if hdr_idx is None or content_end < content_start:
        return []
    ticket_re = re.compile(r"^#\s+([A-Z0-9][A-Z0-9_\-]*):\s*$", re.IGNORECASE)
    seen: dict[str, None] = {}
    for i in range(content_start, content_end + 1):
        m = ticket_re.match(lines[i].strip())
        if m:
            seen[m.group(1).upper()] = None
    return list(seen.keys())


def _get_today_tickets_with_desc() -> list[tuple[str, str]]:
    try:
        lines = _read_notes()
    except RuntimeError:
        return []
    (_, hdr_idx, _, content_start, content_end, _) = _find_today_section(lines)
    if hdr_idx is None or content_end < content_start:
        return []

    ticket_re = re.compile(r"^#\s+([A-Z0-9][A-Z0-9_\-]*):\s*$", re.IGNORECASE)
    bullet_re = re.compile(r"^-\s+(?:\[\d{2}:\d{2}\]\s+)?(.+)$")

    order:       list[str]      = []
    last_desc:   dict[str, str] = {}
    current_tid: str | None     = None

    for i in range(content_start, content_end + 1):
        stripped = lines[i].strip()
        m = ticket_re.match(stripped)
        if m:
            current_tid = m.group(1).upper()
            if current_tid not in last_desc:
                order.append(current_tid)
                last_desc[current_tid] = ""
        elif current_tid and stripped.startswith("- "):
            bm = bullet_re.match(stripped)
            if bm:
                last_desc[current_tid] = bm.group(1).strip()

    return [(tid, last_desc.get(tid, "")) for tid in order]


# ---------------------------------------------------------------------------
# Full-file ticket index
# ---------------------------------------------------------------------------

_DATE_HDR_RE   = re.compile(r"^#\s+\d{4}\.\d{1,2}\.\d{1,2}\s*$")
_TICKET_HDR_RE = re.compile(r"^#\s+([A-Z0-9][A-Z0-9_\-]*):\s*$", re.IGNORECASE)


def _build_ticket_index(lines: list[str]) -> dict[str, list[str]]:
    index:   dict[str, list[str]] = {}
    emitted: set[tuple[str, str]] = set()
    current_date   = ""
    current_ticket = ""

    for line in lines:
        stripped = line.strip()
        if _is_sep(stripped):
            current_ticket = ""
            continue
        if _DATE_HDR_RE.match(stripped):
            current_date   = stripped.lstrip("#").strip()
            current_ticket = ""
            continue
        m = _TICKET_HDR_RE.match(stripped)
        if m:
            current_ticket = m.group(1).upper()
            if current_ticket not in index:
                index[current_ticket] = []
            continue
        if stripped.startswith("- ") and current_ticket:
            key = (current_ticket, current_date)
            if key not in emitted:
                emitted.add(key)
                if index[current_ticket]:
                    index[current_ticket].append("")
                if current_date:
                    index[current_ticket].append(f"# {current_date}")
            index[current_ticket].append(stripped)
    return index


def _all_tickets_sorted(index: dict[str, list[str]]) -> list[str]:
    pinned = [t for t in (_TODO_ID, _OPS_ID) if t in index]
    done   = [t for t in index if t not in (_TODO_ID, _OPS_ID) and
              any("[DONE]<<-" in e for e in index[t])]
    active = [t for t in index if t not in (_TODO_ID, _OPS_ID) and t not in done]
    return pinned + active + done


def _first_bullet_from_index(entries: list[str]) -> str:
    bullet_re = re.compile(r"^-\s+(?:\[\d{2}:\d{2}\]\s+)?(.+)$")
    for entry in entries:
        m = bullet_re.match(entry.strip())
        if m:
            return m.group(1).strip()
    return ""


# ---------------------------------------------------------------------------
# SSL context
# ---------------------------------------------------------------------------

def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


# ---------------------------------------------------------------------------
# Rate-limit guard
# ---------------------------------------------------------------------------

_api_rate_lock      = threading.Lock()
_api_last_call_time: float = 0.0
_API_MIN_INTERVAL   = 0.1


def _api_rate_wait() -> None:
    global _api_last_call_time
    with _api_rate_lock:
        now     = time.monotonic()
        elapsed = now - _api_last_call_time
        if elapsed < _API_MIN_INTERVAL:
            time.sleep(_API_MIN_INTERVAL - elapsed)
        _api_last_call_time = time.monotonic()


# ---------------------------------------------------------------------------
# YouTrack REST API — shared HTTP helper
# ---------------------------------------------------------------------------

_NOT_FOUND: dict = {"__not_found__": True}


class _ApiError(dict):
    pass


def _make_api_error(status: int, body: str) -> _ApiError:
    try:
        data = json.loads(body)
        desc = data.get("error_description") or data.get("error") or body[:300]
    except Exception:
        desc = body[:300] if body else f"HTTP {status}"
    return _ApiError({"__api_error__": True, "status": status, "description": desc})


def _is_api_error(obj: object) -> bool:
    return isinstance(obj, _ApiError)



class _RejectRedirectHandler(HTTPRedirectHandler):
    """Refuse redirects so Bearer tokens are never forwarded to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise URLError(
            f"Refusing HTTP {code} redirect from YouTrack API to {newurl}"
        )


def _yt_urlopen(req: Request, timeout: int, ctx: ssl.SSLContext):
    opener = build_opener(HTTPSHandler(context=ctx), _RejectRedirectHandler())
    return opener.open(req, timeout=timeout)


def _yt_request(
    method: str,
    path: str,
    body: dict | None = None,
    params: str = "",
) -> dict | list | None:
    api_root = _youtrack_api_root()
    token    = _youtrack_token()
    if not api_root or not token:
        return None

    base_err = _validate_youtrack_base(_youtrack_base())
    if base_err:
        log.error("YouTrack base URL rejected: %s", base_err)
        return None

    url = f"{api_root}{path}"
    if params:
        url += ("&" if "?" in url else "?") + params

    data    = json.dumps(body).encode("utf-8") if body is not None else None
    timeout = _api_timeout()
    retries = _api_max_retries()
    ctx     = _ssl_context()

    for attempt in range(retries + 1):
        _api_rate_wait()

        req = Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept":        "application/json",
                "Content-Type":  "application/json",
                "Cache-Control": "no-cache",
            },
        )
        try:
            with _yt_urlopen(req, timeout=timeout, ctx=ctx) as resp:
                raw = resp.read(_API_MAX_RESPONSE_BYTES).decode("utf-8")
                return json.loads(raw) if raw.strip() else {}

        except HTTPError as exc:
            if exc.code == 404:
                return _NOT_FOUND

            if exc.code in (429, 502, 503) and attempt < retries:
                wait = 2 ** attempt
                log.warning(
                    "YouTrack: HTTP %s (attempt %d/%d), retrying in %ds",
                    exc.code, attempt + 1, retries + 1, wait,
                )
                time.sleep(wait)
                continue

            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            log.warning(
                "YouTrack API HTTP %s for %s %s  body: %s",
                exc.code, method, path, err_body[:200],
            )
            return _make_api_error(exc.code, err_body)

        except (URLError, OSError, json.JSONDecodeError) as exc:
            if attempt < retries:
                wait = 2 ** attempt
                log.warning(
                    "YouTrack API %s %s transient error (attempt %d/%d): %s",
                    method, path, attempt + 1, retries + 1, exc,
                )
                time.sleep(wait)
                continue
            log.warning("YouTrack API %s %s error: %s", method, path, exc)
            return None

    return None


# ---------------------------------------------------------------------------
# YouTrack — current user cache
# ---------------------------------------------------------------------------

_current_user_lock  = threading.Lock()
_CURRENT_USER_CACHE: dict[str, str] = {}


def _fetch_current_user_login() -> tuple[str | None, str | None]:
    with _current_user_lock:
        if _CURRENT_USER_CACHE:
            return (
                _CURRENT_USER_CACHE.get("login") or None,
                _CURRENT_USER_CACHE.get("fullName") or None,
            )

    result = _yt_request("GET", "/users/me", params="fields=login,fullName")
    if not result or not isinstance(result, dict) or _is_api_error(result):
        return None, None

    login    = (result.get("login") or "").strip()
    fullname = (result.get("fullName") or "").strip()

    if login:
        with _current_user_lock:
            _CURRENT_USER_CACHE["login"]    = login
            _CURRENT_USER_CACHE["fullName"] = fullname

    return login or None, fullname or None


# ---------------------------------------------------------------------------
# YouTrack — fetch ticket info
# ---------------------------------------------------------------------------

_YT_FIELDS = (
    "summary,"
    "idReadable,"
    "created,"
    "reporter(fullName,login),"
    "customFields("
      "name,"
      "value(name,fullName,presentation,login)"
    ")"
)

_YT_LIST_FIELDS = (
    "idReadable,"
    "summary,"
    "created,"
    "updated,"
    "reporter(fullName,login),"
    "customFields("
      "name,"
      "value(name,fullName,presentation,login)"
    ")"
)


def _fetch_youtrack_issue(ticket_id: str) -> dict | None:
    result = _yt_request(
        "GET",
        f"/issues/{quote(ticket_id)}",
        params=f"fields={quote(_YT_FIELDS)}",
    )
    if _is_api_error(result):
        return None
    return result  # type: ignore[return-value]


def _fetch_my_open_issues(project: str) -> list[dict]:
    """Fetch issues assigned to me (used by TODO scratch view)."""
    if not project:
        return []
    query = f"for: me #Unresolved project: {{{project}}}"
    result = _yt_request(
        "GET",
        "/issues",
        params=(
            f"query={quote(query)}"
            f"&fields={quote(_YT_LIST_FIELDS)}"
            f"&$top=200"
        ),
    )
    if result is None or result is _NOT_FOUND or _is_api_error(result):
        return []
    if not isinstance(result, list):
        return []
    return result


# ---------------------------------------------------------------------------
# YouTrack — shared list fetch helper (large buffer, safe encoding)
# ---------------------------------------------------------------------------

def _fetch_issues_list(
    query: str,
    top: int = 300,
) -> tuple[list[dict], str | None]:
    """
    Generic helper: fetch a list of YouTrack issues using the given query.
    Uses _API_MAX_RESPONSE_BYTES_LIST (8 MB) to prevent truncation on large
    projects.  Returns (issues, error_message).
    Sorted newest-updated first (client-side).
    """
    api_root = _youtrack_api_root()
    token    = _youtrack_token()
    if not api_root or not token:
        return [], "YouTrack is not configured (missing token or base URL)"

    base_err = _validate_youtrack_base(_youtrack_base())
    if base_err:
        return [], base_err

    # safe='' encodes ALL special chars: spaces, {, }, :, #
    url = (
        f"{api_root}/issues"
        f"?query={quote(query, safe='')}"
        f"&fields={quote(_YT_LIST_FIELDS, safe='')}"
        f"&$top={top}"
    )

    log.debug("ST4Notes fetch_issues_list URL: %s", url)

    timeout = _api_timeout()
    retries = _api_max_retries()
    ctx     = _ssl_context()
    last_error_msg: str = "Unknown error"
    raw: str = ""

    for attempt in range(retries + 1):
        _api_rate_wait()
        req = Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept":        "application/json",
                "Content-Type":  "application/json",
                "Cache-Control": "no-cache",
            },
        )
        try:
            with _yt_urlopen(req, timeout=timeout, ctx=ctx) as resp:
                # Use large buffer — list responses for big projects can be
                # several MB; truncation causes JSONDecodeError mid-object.
                raw  = resp.read(_API_MAX_RESPONSE_BYTES_LIST).decode("utf-8")
                data = json.loads(raw) if raw.strip() else []
                if not isinstance(data, list):
                    return [], "Unexpected response format from YouTrack"
                data.sort(
                    key=lambda i: i.get("updated") or i.get("created") or 0,
                    reverse=True,
                )
                return data, None

        except HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            if exc.code == 400:
                log.warning(
                    "ST4Notes fetch_issues_list HTTP 400\n  URL:  %s\n  Body: %s",
                    url, err_body[:400],
                )
                return [], (
                    f"HTTP 400 — query rejected by YouTrack.\n\n"
                    f"Query:    {query}\n"
                    f"Full URL: {url}\n\n"
                    f"Response: {err_body[:300]}"
                )
            if exc.code == 404:
                return [], "Project not found (HTTP 404)"
            if exc.code == 401:
                return [], "Authentication failed (HTTP 401) — check youtrack_token"
            if exc.code == 403:
                return [], "Permission denied (HTTP 403) — token lacks Read Issue"
            if exc.code in (429, 502, 503) and attempt < retries:
                time.sleep(2 ** attempt)
                last_error_msg = f"HTTP {exc.code}"
                continue
            last_error_msg = f"HTTP {exc.code}: {err_body[:200]}"

        except (TimeoutError, URLError, OSError) as exc:
            last_error_msg = f"Cannot reach YouTrack: {exc}"
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue

        except json.JSONDecodeError as exc:
            log.warning(
                "ST4Notes fetch_issues_list: JSON decode failed.\n"
                "  URL: %s\n"
                "  Error: %s\n"
                "  Raw (first 300 chars): %.300s",
                url, exc, raw,
            )
            return [], (
                f"JSON decode error from YouTrack.\n\n"
                f"URL: {url}\n\n"
                f"Error: {exc}\n\n"
                f"First 300 chars of response:\n{raw[:300]}\n\n"
                f"Check the ST4Notes log (View > Show Console) for details."
            )

    return [], last_error_msg


# ---------------------------------------------------------------------------
# YouTrack — concrete list fetch functions
# ---------------------------------------------------------------------------

def _fetch_project_issues_for_import(project: str) -> tuple[list[dict], str | None]:
    """
    Fetch all unresolved issues in the project (not just assigned to me).
    Used by: Import from YouTrack (all).
    Returns (issues, error_message).  Sorted newest-updated first.
    """
    if not project:
        return [], "default_project is not configured"
    query = f"#Unresolved project: {{{project}}}"
    return _fetch_issues_list(query, top=300)


def _fetch_my_assigned_issues_for_import(project: str) -> tuple[list[dict], str | None]:
    """
    Fetch unresolved issues assigned to the current user.
    Used by: Import from YouTrack (assigned to me).
    Returns (issues, error_message).  Sorted newest-updated first.
    """
    if not project:
        return [], "default_project is not configured"
    query = f"for: me #Unresolved project: {{{project}}}"
    return _fetch_issues_list(query, top=200)


# ---------------------------------------------------------------------------
# YouTrack — fetch unassigned issues
# ---------------------------------------------------------------------------

# States excluded from the unassigned view — mirrors your UI query exactly.
_UNASSIGNED_EXCLUDE_STATES: list[str] = [
    "Done",
    "In Progress",
    "In review",
    "On hold",
    "In PM review",
    "Code Review",
    "Ready For Review",
    "Resolved",
    "Closed",
    "Cannot Reproduce",
    "Fixed",
]


def _build_unassigned_query(project: str) -> str:
    """
    Build the YouTrack search query for unassigned open issues.

    Equivalent UI query:
        project: Infrastructure Assignee: Unassigned
        State: -Done, -{In Progress}, -{In review}, ...

    Each multi-word state must be wrapped in braces: -{In Progress}
    Single-word states are also wrapped for consistency.
    """
    exclude_clauses = " ".join(
        f"-{{{s}}}" for s in _UNASSIGNED_EXCLUDE_STATES
    )
    return (
        f"project: {{{project}}} "
        f"Assignee: Unassigned "
        f"State: {exclude_clauses}"
    )


def _fetch_unassigned_issues(project: str) -> tuple[list[dict], str | None]:
    """
    Fetch unassigned open issues, excluding resolved/done/in-progress states.
    Returns (issues, error_message).  Sorted newest-updated first.
    """
    if not project:
        return [], "default_project is not configured"
    query = _build_unassigned_query(project)
    return _fetch_issues_list(query, top=200)


# ---------------------------------------------------------------------------
# YouTrack — fetch ALL issues for a project
# ---------------------------------------------------------------------------

def _fetch_all_project_issues(project: str) -> tuple[list[dict], str | None]:
    """
    Fetch ALL unresolved issues for the given project (any assignee).
    Returns (issues, error_message).  Sorted newest-updated first.

    NOTE: Does NOT wrap single-word project names in braces.
    {PROJ} causes HTTP 400 on standard YouTrack REST endpoints.
    Only multi-word project names need braces, e.g. {My Project}.
    """
    if not project:
        return [], "default_project is not configured"
    proj_token = f"{{{project}}}" if " " in project else project
    query = f"project: {proj_token} #Unresolved"
    return _fetch_issues_list(query, top=500)


# ---------------------------------------------------------------------------
# Fetch parent issue info
# ---------------------------------------------------------------------------

_PARENT_FIELDS = (
    "idReadable,"
    "summary,"
    "customFields(name,value(login,fullName,name))"
)


def _fetch_parent_info(ticket_id: str) -> tuple[str | None, str | None]:
    result = _yt_request(
        "GET",
        f"/issues/{quote(ticket_id)}",
        params=f"fields={quote(_PARENT_FIELDS)}",
    )
    if not result or result is _NOT_FOUND or _is_api_error(result):
        return None, None
    if not isinstance(result, dict):
        return None, None

    summary = result.get("summary") or ""
    parsed  = _parse_youtrack_issue(result)
    assignee_login = parsed.get("assignee_login") or ""
    return summary or None, assignee_login or None


# ---------------------------------------------------------------------------
# YouTrack — add comment to issue
# ---------------------------------------------------------------------------

def _yt_add_comment(ticket_id: str, text: str) -> bool:
    """
    POST a plain-text comment to a YouTrack issue.
    Required permission: Create Comment.
    Returns True on success, False on any error.
    """
    if not text.strip():
        return False
    result = _yt_request(
        "POST",
        f"/issues/{quote(ticket_id)}/comments",
        body={"text": text},
        params="fields=id,text",
    )
    ok = (
        result is not None
        and result is not _NOT_FOUND
        and not _is_api_error(result)
    )
    if ok:
        log.info("YouTrack: comment added to %s", ticket_id)
    else:
        log.warning("YouTrack: failed to add comment to %s", ticket_id)
    return ok


# ---------------------------------------------------------------------------
# YouTrack — apply command (state transitions)
# ---------------------------------------------------------------------------

def _yt_apply_command(ticket_id: str, command: str) -> bool:
    """
    Apply a YouTrack command string to an issue (e.g. "State In Review", "Done").
    Returns True on success.
    """
    result = _yt_request(
        "POST",
        "/commands",
        body={
            "query":  command,
            "issues": [{"idReadable": ticket_id}],
            "silent": False,
        },
    )
    ok = (
        result is not None
        and result is not _NOT_FOUND
        and not _is_api_error(result)
    )
    if ok:
        log.info("YouTrack: applied command '%s' to %s", command, ticket_id)
    else:
        log.warning("YouTrack: failed to apply command '%s' to %s", command, ticket_id)
    return ok


# ---------------------------------------------------------------------------
# Severity sort
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "blocker":      0,
    "critical":     0,
    "show-stopper": 0,
    "showstopper":  0,
    "major":        1,
    "normal":       2,
    "minor":        3,
    "cosmetic":     4,
    "trivial":      4,
}


def _issue_severity_rank(issue: dict) -> int:
    for cf in issue.get("customFields") or []:
        name  = (cf.get("name") or "").lower()
        value = cf.get("value")
        if value is None:
            continue
        if name in ("priority", "severity"):
            val_name = ""
            if isinstance(value, dict):
                val_name = (
                    value.get("name") or value.get("presentation") or ""
                ).lower()
            elif isinstance(value, str):
                val_name = value.lower()
            rank = _SEVERITY_RANK.get(val_name)
            if rank is not None:
                return rank
    return 2


def _sort_issues_by_severity(issues: list[dict]) -> list[dict]:
    return sorted(issues, key=_issue_severity_rank)


# ---------------------------------------------------------------------------
# YouTrack — set issue Done
# ---------------------------------------------------------------------------

def _set_youtrack_done(ticket_id: str) -> None:
    ok = _yt_apply_command(ticket_id, "Done")
    if ok:
        sublime.set_timeout(
            lambda: sublime.status_message(
                f"Notes: YouTrack {ticket_id} -> Done"
            ),
            0,
        )
    else:
        sublime.set_timeout(
            lambda: sublime.status_message(
                f"Notes: WARNING - could not set {ticket_id} Done in YouTrack"
            ),
            0,
        )


# ---------------------------------------------------------------------------
# YouTrack — set issue In Review
# ---------------------------------------------------------------------------

def _set_youtrack_in_review(ticket_id: str) -> None:
    ok = _yt_apply_command(ticket_id, "State In Review")
    if ok:
        sublime.set_timeout(
            lambda: sublime.status_message(
                f"Notes: YouTrack {ticket_id} -> In Review"
            ),
            0,
        )
    else:
        sublime.set_timeout(
            lambda: sublime.status_message(
                f"Notes: WARNING - could not set {ticket_id} In Review in YouTrack"
            ),
            0,
        )


# ---------------------------------------------------------------------------
# YouTrack — project lookup
# ---------------------------------------------------------------------------

def _yt_get_project_id(short_name: str) -> str | None:
    result = _yt_request(
        "GET",
        "/admin/projects",
        params=f"fields=id,shortName,name&query={quote(short_name)}",
    )
    if not result or not isinstance(result, list):
        return None
    for proj in result:
        if (proj.get("shortName") or "").upper() == short_name.upper():
            return proj.get("id")
    if result:
        return result[0].get("id")
    return None


# ---------------------------------------------------------------------------
# YouTrack — subtask linking
# ---------------------------------------------------------------------------

def _yt_get_subtask_link_id(parent_id: str) -> str | None:
    result = _yt_request(
        "GET",
        f"/issues/{quote(parent_id)}/links",
        params="fields=id,direction,linkType(name,localizedName,sourceToTarget,targetToSource)",
    )
    if not result or not isinstance(result, list):
        return None
    for link in result:
        link_type = link.get("linkType") or {}
        type_name = (
            link_type.get("name") or link_type.get("localizedName") or ""
        ).lower()
        direction = (link.get("direction") or "").upper()
        if direction == "OUTWARD" and any(
            kw in type_name for kw in ("parent", "subtask", "child")
        ):
            return link.get("id")
    for link in result:
        link_type = link.get("linkType") or {}
        type_name = (
            link_type.get("name") or link_type.get("localizedName") or ""
        ).lower()
        if "subtask" in type_name or "parent" in type_name:
            return link.get("id")
    return None


def _yt_link_as_subtask(parent_id: str, child_id: str) -> bool:
    link_id = _yt_get_subtask_link_id(parent_id)
    if not link_id:
        log.warning(
            "YouTrack: no subtask link type found for %s; "
            "child %s created as standalone",
            parent_id, child_id,
        )
        return False

    result = _yt_request(
        "POST",
        f"/issues/{quote(parent_id)}/links/{quote(link_id)}/issues",
        body={"idReadable": child_id},
        params="fields=idReadable",
    )
    ok = (
        result is not None
        and result is not _NOT_FOUND
        and not _is_api_error(result)
    )
    if ok:
        log.info("YouTrack: linked %s as subtask of %s", child_id, parent_id)
    else:
        log.warning(
            "YouTrack: could not link %s as subtask of %s", child_id, parent_id
        )
    return ok


# ---------------------------------------------------------------------------
# YouTrack — issue creation
# ---------------------------------------------------------------------------

class IssueCreateError(Exception):
    def __init__(self, message: str, assignee_error: bool = False) -> None:
        super().__init__(message)
        self.assignee_error = assignee_error


def _yt_create_issue(
    project_short: str,
    summary: str,
    description: str,
    assignee_login: str,
) -> str:
    project_id = _yt_get_project_id(project_short)
    if not project_id:
        raise IssueCreateError(
            f"Project '{project_short}' not found.\n"
            "Check the project shortName and token Read Project permission."
        )

    custom_fields = []
    if assignee_login:
        custom_fields.append({
            "name":  "Assignee",
            "$type": "SingleUserIssueCustomField",
            "value": {"login": assignee_login},
        })

    body: dict = {
        "project": {"id": project_id},
        "summary": summary,
    }
    if description:
        body["description"] = description
    if custom_fields:
        body["customFields"] = custom_fields

    result = _yt_request(
        "POST",
        "/issues",
        body=body,
        params="fields=id,idReadable,summary",
    )

    if (
        result
        and isinstance(result, dict)
        and not _is_api_error(result)
        and result is not _NOT_FOUND
    ):
        ticket_id = result.get("idReadable")
        if ticket_id:
            return ticket_id
        raise IssueCreateError("Issue created but no idReadable returned.")

    if _is_api_error(result):
        api_err = result  # type: ignore[assignment]
        status  = api_err.get("status", 0)
        desc    = api_err.get("description", "")

        if assignee_login and status in (400, 404):
            body_no_assignee: dict = {
                "project": {"id": project_id},
                "summary": summary,
            }
            if description:
                body_no_assignee["description"] = description
            retry = _yt_request(
                "POST",
                "/issues",
                body=body_no_assignee,
                params="fields=id,idReadable,summary",
            )
            if (
                retry
                and isinstance(retry, dict)
                and not _is_api_error(retry)
                and retry is not _NOT_FOUND
                and retry.get("idReadable")
            ):
                orphan_id = retry.get("idReadable")
                raise IssueCreateError(
                    f"Assignee login '{assignee_login}' does not exist in YouTrack.\n\n"
                    f"The issue was created as {orphan_id} without an assignee.\n"
                    f"Please set the assignee manually in YouTrack.",
                    assignee_error=True,
                )
            raise IssueCreateError(
                f"HTTP {status} from YouTrack.\n\nDetails: {desc}\n\n"
                "Check: token permissions, project access, custom field values."
            )

        if status == 403:
            raise IssueCreateError(
                "Permission denied (HTTP 403).\n\n"
                "The API token does not have 'Create Issue' permission.\n"
                "Go to YouTrack -> Profile -> Authentication -> Permanent Tokens\n"
                "and ensure the token scope includes 'YouTrack' or 'Create Issue'."
            )

        raise IssueCreateError(
            f"YouTrack API error HTTP {status}.\n\nDetails: {desc}"
        )

    raise IssueCreateError(
        "Could not create issue: no response from YouTrack.\n"
        "Check your network connection and youtrack_base URL."
    )


# ---------------------------------------------------------------------------
# Popup HTML helpers
# ---------------------------------------------------------------------------

def _h(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _state_color(state: str) -> str:
    s = state.lower()
    if any(x in s for x in ("fixed", "done", "closed", "resolved")):
        return "#98c379"
    if any(x in s for x in ("open", "to do", "new")):
        return "#e06c75"
    return "#e5c07b"


def _priority_color(priority: str) -> str:
    p = priority.lower()
    if p in ("critical", "show-stopper", "blocker", "showstopper"):
        return "#e06c75"
    if p in ("major",):
        return "#e5c07b"
    return "#abb2bf"


def _build_hover_html(
    ticket_id: str,
    url: str,
    info: dict[str, str] | None,
    not_found: bool = False,
) -> str:
    safe_url  = _h(url)
    label_txt = ticket_id if ticket_id else url

    link_html = (
        f"<div style='margin-bottom:5px'>"
        f"<a href='open:{safe_url}' "
        f"style='color:#56b6c2;text-decoration:none;font-weight:bold'>"
        f"&#128279; {_h(label_txt)}</a>"
        f"</div>"
    )
    sep = "<div style='border-top:1px solid #3e4451;margin:4px 0 6px 0'></div>"

    if not_found:
        body = (
            "<div style='white-space:pre;line-height:1.7'>"
            "<span style='color:#e06c75'>x  Not found</span>\n"
            f"<span style='color:#5c6370'>No issue matching </span>"
            f"<span style='color:#abb2bf'>{_h(ticket_id)}</span>"
            f"<span style='color:#5c6370'> exists on this YouTrack instance.</span>"
            "</div>"
        )
        return (
            "<body id='stnotes-hover' "
            "style='margin:8px 12px;font-family:monospace;font-size:0.9em'>"
            + link_html + sep + body
            + "</body>"
        )

    if info is None:
        return (
            "<body id='stnotes-hover' "
            "style='margin:8px 12px;font-family:monospace'>"
            + link_html
            + "</body>"
        )

    sev = info.get("severity", "")
    pri = info.get("priority", "")
    if sev and pri:
        priority_row = ("sev/pri", f"{sev} / {pri}", _priority_color(pri))
        severity_row = None
    elif sev:
        severity_row = ("severity", sev, "#abb2bf")
        priority_row = None
    elif pri:
        severity_row = None
        priority_row = ("priority", pri, _priority_color(pri))
    else:
        severity_row = None
        priority_row = None

    FIELDS: list[tuple[str, str, str]] = []
    FIELDS.append(("summary",  info.get("summary",  ""), "#cdd9e5"))
    if priority_row:
        FIELDS.append(priority_row)
    if severity_row:
        FIELDS.append(severity_row)
    FIELDS.append(("state",    info.get("state",    ""), _state_color(info.get("state", ""))))
    FIELDS.append(("assignee", info.get("assignee", ""), "#6699cc"))
    FIELDS.append(("reporter", info.get("reporter", ""), "#abb2bf"))
    FIELDS.append(("created",  info.get("created",  ""), "#5c6370"))

    populated = [(lbl, val, col) for lbl, val, col in FIELDS if val]
    if not populated:
        rows_html = "<span style='color:#5c6370'>no data returned</span>"
    else:
        col_w = max(len(lbl) for lbl, _, _ in populated) + 2
        rows: list[str] = []
        for lbl, val, color in populated:
            label_padded = (lbl + ":").ljust(col_w)
            rows.append(
                f"<span style='color:#5c6370'>{_h(label_padded)}</span>"
                f"<span style='color:{color}'>{_h(val)}</span>"
            )
        rows_html = "\n".join(rows)

    return (
        "<body id='stnotes-hover' "
        "style='margin:8px 12px;font-family:monospace;font-size:0.9em'>"
        + link_html
        + sep
        + f"<div style='white-space:pre;line-height:1.7'>{rows_html}</div>"
        + "</body>"
    )


# ---------------------------------------------------------------------------
# Core business logic
# ---------------------------------------------------------------------------

def _build_entry(description: str) -> str:
    desc = description.strip()
    tag  = desc.upper()
    if tag == "DONE":
        body = "[DONE]<<-"
    elif tag == "EVAL":
        body = "[EVAL]"
    elif tag == "CREATED":
        body = "[CREATED]"
    elif tag == "REVIEW":
        body = "[IN REVIEW]"
    else:
        body = desc
    return f"- [{_now_hhmm()}] {body}"


def add_note(ticket_id: str, description: str) -> None:
    entry = _build_entry(description)
    lines = _read_notes()

    (open_sep, hdr_idx, hdr_close, content_start,
     content_end, next_sep) = _find_today_section(lines)

    if hdr_idx is None:
        new_section: list[str] = [
            _SEP,
            _today_header(),
            _SEP,
            "",
            f"# {ticket_id}:",
            entry,
            "",
        ]
        if lines and lines[0].strip():
            new_section.append("")
        lines = new_section + lines
        _write_notes(lines)
        return

    ticket_last = _find_ticket_in_section(
        lines, content_start, content_end, ticket_id
    )

    if ticket_last is None:
        insert_at  = content_end + 1
        new_block: list[str] = []
        if content_end >= content_start:
            new_block.append("")
        new_block += [f"# {ticket_id}:", entry]
        lines[insert_at:insert_at] = new_block
    else:
        lines.insert(ticket_last + 1, entry)

    _write_notes(lines)


def add_note_raw(ticket_id: str, raw_entry: str) -> None:
    lines = _read_notes()

    (open_sep, hdr_idx, hdr_close, content_start,
     content_end, next_sep) = _find_today_section(lines)

    if hdr_idx is None:
        new_section: list[str] = [
            _SEP,
            _today_header(),
            _SEP,
            "",
            f"# {ticket_id}:",
            raw_entry,
            "",
        ]
        if lines and lines[0].strip():
            new_section.append("")
        lines = new_section + lines
        _write_notes(lines)
        return

    ticket_last = _find_ticket_in_section(
        lines, content_start, content_end, ticket_id
    )

    if ticket_last is None:
        insert_at  = content_end + 1
        new_block: list[str] = []
        if content_end >= content_start:
            new_block.append("")
        new_block += [f"# {ticket_id}:", raw_entry]
        lines[insert_at:insert_at] = new_block
    else:
        lines.insert(ticket_last + 1, raw_entry)

    _write_notes(lines)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_ticket_id(raw: str) -> tuple[str | None, str | None]:
    tid = raw.strip().upper()
    if not tid:
        return None, "Ticket ID cannot be empty."
    if not _TICKET_RE.match(tid):
        return None, (
            f"Invalid ticket ID: '{tid}'\n"
            "Allowed: letters, digits, hyphens, underscores. "
            "Must start with a letter or digit. Max 64 chars."
        )
    return tid, None


# ---------------------------------------------------------------------------
# Scratch view helpers
# ---------------------------------------------------------------------------

def _open_scratch_view(window: sublime.Window, name: str, content: str) -> None:
    view = window.new_file()
    view.set_name(name)
    view.set_scratch(True)
    view.set_read_only(False)
    view.settings().set("stnotes_view_name", name)
    view.run_command("notes_insert_text", {"text": content})
    view.set_read_only(True)
    _assign_stnotes_syntax(view)


def _assign_stnotes_syntax(view: sublime.View) -> None:
    syntax = sublime.find_syntax_for_file("file.stnotes")
    if syntax:
        view.assign_syntax(syntax)


# ---------------------------------------------------------------------------
# YT open issues — sort + render
# ---------------------------------------------------------------------------

def _build_yt_issues_section(project: str, issues: list[dict]) -> str:
    header = f"{_SEP}\n# YouTrack open issues [{project}] - assigned to me\n{_SEP}"

    if not issues:
        return (
            header
            + "\n\n- (no open issues found or YouTrack not reachable)\n"
        )

    sorted_issues = _sort_issues_by_severity(issues)
    lines: list[str] = [header, ""]
    for issue in sorted_issues:
        iid     = issue.get("idReadable") or ""
        summary = issue.get("summary") or "(no summary)"
        if not iid:
            continue
        lines.append(f"# {iid}:")
        lines.append(f"- {summary}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Weekly summary helpers
# ---------------------------------------------------------------------------

_DATE_PARSE_RE = re.compile(r"^#\s+(\d{4})\.(\d{1,2})\.(\d{1,2})\s*$")


def _parse_date_header(line: str) -> datetime_date | None:
    m = _DATE_PARSE_RE.match(line.strip())
    if not m:
        return None
    try:
        return datetime_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _collect_weekly_sections(
    lines: list[str],
    start_date: datetime_date,
    end_date: datetime_date,
) -> list[tuple[datetime_date, list[str]]]:
    sections: list[tuple[datetime_date, list[str]]] = []
    i = 0
    n = len(lines)

    while i < n:
        stripped = lines[i].strip()

        if _is_sep(stripped):
            i += 1
            continue

        date = _parse_date_header(stripped)
        if date is None:
            i += 1
            continue

        content: list[str] = []
        j = i + 1

        if j < n and _is_sep(lines[j].strip()):
            j += 1

        while j < n:
            l = lines[j].strip()
            if _is_sep(l) or _parse_date_header(l) is not None:
                break
            content.append(lines[j])
            j += 1

        if start_date <= date <= end_date:
            sections.append((date, content))

        i = j

    sections.sort(key=lambda x: x[0])
    return sections


def _weekly_sort_key(ticket_id: str) -> tuple[int, str]:
    u = ticket_id.upper()
    if u == _TODO_ID:
        return (2, u)
    if u == _OPS_ID:
        return (1, u)
    return (0, u)


# ---------------------------------------------------------------------------
# Weekly summary — notes-file-compatible format
# ---------------------------------------------------------------------------

_BULLET_TEXT_RE = re.compile(r"^-\s+(?:\[\d{2}:\d{2}\]\s+)?(.+)$")


def _strip_bullet_text(raw: str) -> str:
    m = _BULLET_TEXT_RE.match(raw.strip())
    return m.group(1).strip() if m else raw.strip().lstrip("- ").strip()


def _render_weekly_summary(
    sections: list[tuple[datetime_date, list[str]]],
    start_date: datetime_date,
    end_date: datetime_date,
) -> str:
    ticket_re = re.compile(r"^#\s+([A-Z0-9][A-Z0-9_\-]*):\s*$", re.IGNORECASE)
    bullet_re = re.compile(r"^-\s+(?:\[\d{2}:\d{2}\]\s+)?(.+)$")

    ticket_order:       list[str]                                  = []
    ticket_first_date:  dict[str, datetime_date]                   = {}
    ticket_last_date:   dict[str, datetime_date]                   = {}
    ticket_bullets:     dict[str, list[tuple[datetime_date, str]]] = {}

    ops_entries:  list[tuple[datetime_date, str]] = []
    todo_entries: list[tuple[datetime_date, str]] = []

    for day, content_lines in sections:
        current_tid: str | None = None

        for raw in content_lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = ticket_re.match(stripped)
            if m:
                current_tid = m.group(1).upper()
                if current_tid not in ticket_first_date:
                    ticket_order.append(current_tid)
                    ticket_first_date[current_tid] = day
                    ticket_bullets[current_tid]    = []
                ticket_last_date[current_tid] = day
                continue

            if current_tid and stripped.startswith("- "):
                bm = bullet_re.match(stripped)
                text = bm.group(1).strip() if bm else stripped[2:].strip()

                if current_tid == _OPS_ID:
                    ops_entries.append((day, text))
                elif current_tid == _TODO_ID:
                    todo_entries.append((day, text))
                else:
                    ticket_bullets[current_tid].append((day, text))

    regular_tickets = [
        t for t in ticket_order
        if t not in (_OPS_ID, _TODO_ID)
    ]
    regular_tickets.sort(
        key=lambda t: ticket_last_date.get(t, ticket_first_date[t]),
        reverse=True,
    )

    ops_entries.sort(key=lambda x: x[0],  reverse=True)
    todo_entries.sort(key=lambda x: x[0], reverse=True)

    title_line = (
        f"# Weekly Summary  "
        f"{start_date.strftime('%Y.%m.%d')} - {end_date.strftime('%Y.%m.%d')}"
        f"  ({start_date.strftime('%A')} to {end_date.strftime('%A')})"
    )
    out: list[str] = [_SEP, title_line, _SEP, ""]

    out.append("# TICKETS:")
    out.append("")

    if regular_tickets:
        for tid in regular_tickets:
            out.append(f"# {tid}:")
            bullets = ticket_bullets.get(tid, [])
            bullets_sorted = sorted(bullets, key=lambda x: x[0], reverse=True)
            if bullets_sorted:
                for d, text in bullets_sorted:
                    out.append(f"- [{d.strftime('%Y.%m.%d')}] {text}")
            else:
                d = ticket_last_date.get(tid, ticket_first_date[tid])
                out.append(f"- [{d.strftime('%Y.%m.%d')}] (no entries)")
            out.append("")
    else:
        out.append("- (no tickets this week)")
        out.append("")

    out.append(_SEP)
    out.append("# OPS:")
    out.append("")
    if ops_entries:
        for d, text in ops_entries:
            out.append(f"- [{d.strftime('%Y.%m.%d')}] {text}")
    else:
        out.append("- (no OPS entries this week)")
    out.append("")

    out.append(_SEP)
    out.append("# TODO:")
    out.append("")
    if todo_entries:
        for d, text in todo_entries:
            out.append(f"- [{d.strftime('%Y.%m.%d')}] {text}")
    else:
        out.append("- (no TODO entries this week)")
    out.append("")

    out.append(_SEP)

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Week index helpers  (for Notes - Weekly Search)
# ---------------------------------------------------------------------------

def _iso_week_key(d: datetime_date) -> str:
    iso = d.isocalendar()
    return f"{iso[0]:04d}-W{iso[1]:02d}"


def _week_bounds(iso_year: int, iso_week: int) -> tuple[datetime_date, datetime_date]:
    jan4   = datetime_date(iso_year, 1, 4)
    monday = jan4 - timedelta(days=jan4.weekday()) + timedelta(weeks=iso_week - 1)
    sunday = monday + timedelta(days=6)
    return monday, sunday


def _collect_all_weeks(
    lines: list[str],
) -> list[tuple[str, datetime_date, datetime_date]]:
    seen_weeks: dict[str, tuple[datetime_date, datetime_date]] = {}
    for line in lines:
        d = _parse_date_header(line.strip())
        if d is None:
            continue
        key = _iso_week_key(d)
        if key not in seen_weeks:
            iso      = d.isocalendar()
            mon, sun = _week_bounds(iso[0], iso[1])
            seen_weeks[key] = (mon, sun)

    return sorted(
        [(k, v[0], v[1]) for k, v in seen_weeks.items()],
        key=lambda x: x[1],
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

class NotesAddCommand(sublime_plugin.WindowCommand):
    """
    Command: notes_add  |  Palette: Notes - Add

    Flow:
      Quick panel -> [TODO, OPS, today_tickets...,
                      + Import from YouTrack (assigned to me),
                      + Import from YouTrack (all),
                      + Create new issue (YouTrack)]

    '+ Import from YouTrack (assigned to me)': issues with for:me query.
    '+ Import from YouTrack (all)': all unresolved issues in the project.
    '+ Create new issue': full create-issue flow embedded here.

    For all real tickets (not TODO/OPS), if post_comments is enabled and
    YouTrack is configured, the note description is posted as a comment.
    """

    _active: bool = False

    _panel_items:    list[list[str] | str]
    _panel_item_ids: list[str]

    _ID_CREATE_ISSUE       = "__create_issue__"
    _ID_IMPORT_FROM_YT_ME  = "__import_from_yt_me__"
    _ID_IMPORT_FROM_YT_ALL = "__import_from_yt_all__"

    def run(self) -> None:
        if self._active:
            sublime.status_message("Notes: already waiting for input.")
            return
        self._active = True

        today_with_desc = _get_today_tickets_with_desc()

        def _make_item(tid: str, desc: str = "") -> list[str]:
            return [tid, desc] if desc else [tid]

        pinned_items = [_make_item(_TODO_ID), _make_item(_OPS_ID)]
        pinned_ids   = [_TODO_ID, _OPS_ID]

        regular_items = [
            _make_item(tid, desc)
            for tid, desc in today_with_desc
            if tid not in (_TODO_ID, _OPS_ID)
        ]
        regular_ids = [
            tid for tid, _ in today_with_desc
            if tid not in (_TODO_ID, _OPS_ID)
        ]

        yt_configured = bool(_youtrack_token() and _youtrack_base() and _default_project())

        action_items: list[list[str]] = []
        action_ids:   list[str]       = []

        if yt_configured:
            project = _default_project()
            action_items.append([
                _IMPORT_FROM_YT_ME_LABEL,
                f"project: {project}  |  assigned to me",
            ])
            action_ids.append(self._ID_IMPORT_FROM_YT_ME)

            action_items.append([
                _IMPORT_FROM_YT_ALL_LABEL,
                f"project: {project}  |  all unresolved",
            ])
            action_ids.append(self._ID_IMPORT_FROM_YT_ALL)

        action_items.append([_NEW_TICKET_LABEL, "create & link a new YouTrack issue"])
        action_ids.append(self._ID_CREATE_ISSUE)

        self._panel_items    = pinned_items + regular_items + action_items
        self._panel_item_ids = pinned_ids   + regular_ids   + action_ids

        default_idx = len(pinned_ids) if regular_ids else 0

        self.window.show_quick_panel(
            self._panel_items,
            self._on_quick_panel_done,
            flags=sublime.MONOSPACE_FONT,
            selected_index=default_idx,
            placeholder="Select ticket, TODO, OPS, import or create new...",
        )

    def _on_quick_panel_done(self, index: int) -> None:
        if index == -1:
            self._active = False
            sublime.status_message("Notes: cancelled.")
            return
        selected = self._panel_item_ids[index]
        if selected == self._ID_CREATE_ISSUE:
            self._start_create_issue()
        elif selected == self._ID_IMPORT_FROM_YT_ME:
            self._start_import_from_yt(mode="me")
        elif selected == self._ID_IMPORT_FROM_YT_ALL:
            self._start_import_from_yt(mode="all")
        else:
            self._ticket_id = selected
            self._prompt_description()

    # ------------------------------------------------------------------
    # Create new issue (full flow, embedded)
    # ------------------------------------------------------------------

    def _start_create_issue(self) -> None:
        if not _youtrack_token() or not _youtrack_base():
            self._active = False
            sublime.error_message(
                "Notes - YouTrack not configured.\n\n"
                "Run 'Notes - Settings' and set:\n"
                '  "youtrack_base":  "https://youtrack.example.com/issue/"\n'
                '  "youtrack_token": "<your permanent token>"'
            )
            return

        base_err = _validate_youtrack_base(_youtrack_base())
        if base_err:
            self._active = False
            sublime.error_message(f"Notes - invalid youtrack_base:\n\n{base_err}")
            return

        self._ci_with_stages        = False
        self._ci_parent_exists      = False
        self._ci_project            = _default_project()
        self._ci_summary            = ""
        self._ci_description        = ""
        self._ci_assignee           = ""
        self._ci_existing_parent_id = ""

        self.window.show_input_panel(
            "Create stage sub-tasks? [y/N]:",
            "n",
            self._ci_on_stages_yn,
            None,
            self._on_cancel,
        )

    def _ci_on_stages_yn(self, raw: str) -> None:
        if raw.strip().lower() in ("y", "yes"):
            self._ci_with_stages = True
            self.window.show_input_panel(
                "Does parent ticket already exist? [y/N]:",
                "n",
                self._ci_on_parent_exists_yn,
                None,
                self._on_cancel,
            )
        else:
            self._ci_with_stages = False
            self._ci_prompt_project()

    def _ci_on_parent_exists_yn(self, raw: str) -> None:
        if raw.strip().lower() in ("y", "yes"):
            self._ci_parent_exists = True
            self.window.show_input_panel(
                "Parent ticket ID (e.g. PROJ-1234):",
                "",
                self._ci_on_existing_parent_id,
                None,
                self._on_cancel,
            )
        else:
            self._ci_parent_exists = False
            self._ci_prompt_project()

    def _ci_on_existing_parent_id(self, raw: str) -> None:
        tid_raw = raw.strip().upper()
        if not tid_raw:
            self._active = False
            sublime.status_message("Notes: ticket ID cannot be empty - cancelled.")
            return
        self._ci_existing_parent_id = tid_raw
        sublime.status_message(f"Notes: fetching parent info for {tid_raw}...")
        sublime.set_timeout_async(lambda: self._ci_fetch_parent(tid_raw), 0)

    def _ci_fetch_parent(self, tid_raw: str) -> None:
        summary, assignee_login = _fetch_parent_info(tid_raw)

        def _continue() -> None:
            if summary is None:
                sublime.status_message(
                    f"Notes: WARNING - could not fetch info for {tid_raw}. "
                    "Continuing with empty defaults."
                )
                self._ci_summary = tid_raw
                assignee_default = ""
            else:
                self._ci_summary = summary
                assignee_default = assignee_login or ""

            self.window.show_input_panel(
                f"Assignee login [{assignee_default or 'optional'}]:",
                assignee_default,
                self._ci_on_assignee_existing_parent,
                None,
                self._on_cancel,
            )

        sublime.set_timeout(_continue, 0)

    def _ci_on_assignee_existing_parent(self, raw: str) -> None:
        self._ci_assignee = raw.strip()
        self._ci_resolve_stages_then_kick_off(
            parent_id      = self._ci_existing_parent_id,
            parent_summary = self._ci_summary,
            assignee       = self._ci_assignee,
            create_parent  = False,
        )

    def _ci_prompt_project(self) -> None:
        self.window.show_input_panel(
            "Project (shortName):",
            self._ci_project,
            self._ci_on_project,
            None,
            self._on_cancel,
        )

    def _ci_on_project(self, raw: str) -> None:
        project = raw.strip().upper()
        if not project:
            self._active = False
            sublime.status_message("Notes: project cannot be empty - cancelled.")
            return
        self._ci_project = project
        self.window.show_input_panel(
            f"Summary [{self._ci_project}]:",
            "",
            self._ci_on_summary,
            None,
            self._on_cancel,
        )

    def _ci_on_summary(self, raw: str) -> None:
        summary = raw.strip()
        if not summary:
            self._active = False
            sublime.status_message("Notes: summary cannot be empty - cancelled.")
            return
        self._ci_summary = summary
        self.window.show_input_panel(
            "Description (optional - Enter to skip):",
            "",
            self._ci_on_description,
            None,
            self._on_cancel,
        )

    def _ci_on_description(self, raw: str) -> None:
        self._ci_description = raw.strip()
        self.window.show_input_panel(
            "Assign to me? [y/N]:",
            "n",
            self._ci_on_assign_to_me_yn,
            None,
            self._on_cancel,
        )

    def _ci_on_assign_to_me_yn(self, raw: str) -> None:
        if raw.strip().lower() in ("y", "yes"):
            sublime.set_timeout_async(self._ci_fetch_me_then_proceed, 0)
        else:
            self.window.show_input_panel(
                "Assignee login (optional - Enter to skip):",
                "",
                self._ci_on_assignee_explicit,
                None,
                self._on_cancel,
            )

    def _ci_on_assignee_explicit(self, raw: str) -> None:
        self._ci_assignee = raw.strip()
        self._ci_proceed_after_assignee()

    def _ci_fetch_me_then_proceed(self) -> None:
        login, fullname = _fetch_current_user_login()
        if login:
            self._ci_assignee = login
            display_name = f"{fullname} ({login})" if fullname else login
            sublime.set_timeout(
                lambda: sublime.status_message(f"Notes: assignee set to {display_name}"), 0
            )
        else:
            self._ci_assignee = ""
            sublime.set_timeout(
                lambda: sublime.status_message(
                    "Notes: could not fetch current user - leaving unassigned."
                ), 0
            )
        sublime.set_timeout(self._ci_proceed_after_assignee, 0)

    def _ci_proceed_after_assignee(self) -> None:
        if self._ci_with_stages:
            self._ci_resolve_stages_then_kick_off(
                parent_id      = None,
                parent_summary = self._ci_summary,
                assignee       = self._ci_assignee,
                create_parent  = True,
            )
        else:
            self._ci_kick_off_single(
                project     = self._ci_project,
                summary     = self._ci_summary,
                description = self._ci_description,
                assignee    = self._ci_assignee,
            )

    def _ci_resolve_stages_then_kick_off(
        self,
        parent_id:      str | None,
        parent_summary: str,
        assignee:       str,
        create_parent:  bool,
    ) -> None:
        stages = _issue_stages()
        if stages:
            self._ci_kick_off_with_stages(
                parent_id      = parent_id,
                parent_summary = parent_summary,
                assignee       = assignee,
                stages         = stages,
                create_parent  = create_parent,
            )
        else:
            self._ci_pending_stage_kwargs = {
                "parent_id":      parent_id,
                "parent_summary": parent_summary,
                "assignee":       assignee,
                "create_parent":  create_parent,
            }
            self.window.show_input_panel(
                "Stage names (comma-separated, e.g. Design,Dev,QA,Deploy):",
                "",
                self._ci_on_stage_names_entered,
                None,
                self._on_cancel,
            )

    def _ci_on_stage_names_entered(self, raw: str) -> None:
        stages = [s.strip() for s in raw.split(",") if s.strip()]
        if not stages:
            self._active = False
            sublime.status_message("Notes: no stages entered - cancelled.")
            return
        s = _settings()
        s.set("issue_stages", stages)
        sublime.save_settings(_SETTINGS_FILE)
        sublime.status_message(f"Notes: saved {len(stages)} stages to settings.")
        kw = self._ci_pending_stage_kwargs
        self._ci_kick_off_with_stages(
            parent_id      = kw["parent_id"],
            parent_summary = kw["parent_summary"],
            assignee       = kw["assignee"],
            stages         = stages,
            create_parent  = kw["create_parent"],
        )

    def _ci_kick_off_single(
        self, project: str, summary: str, description: str, assignee: str,
    ) -> None:
        self._active = False
        sublime.status_message(f"Notes: creating {project} issue '{summary}'...")
        sublime.set_timeout_async(
            lambda: self._ci_do_create_single(project, summary, description, assignee), 0
        )

    def _ci_do_create_single(
        self, project: str, summary: str, description: str, assignee: str,
    ) -> None:
        try:
            ticket_id = _yt_create_issue(project, summary, description, assignee)
        except IssueCreateError as exc:
            err_msg = str(exc)
            sublime.set_timeout(
                lambda: sublime.error_message(f"Notes - failed to create issue:\n\n{err_msg}"), 0
            )
            return

        base = _youtrack_base()
        url  = f"{base}{ticket_id}"

        def _notify() -> None:
            try:
                add_note(ticket_id, "CREATED")
            except Exception as exc:
                log.warning("Could not write CREATED entry: %s", exc)
            sublime.set_clipboard(url)
            sublime.message_dialog(
                f"Issue created: {ticket_id}\nURL: {url}\n\nURL copied to clipboard."
            )
            sublime.status_message(f"Notes: created {ticket_id}")

        sublime.set_timeout(_notify, 0)

    def _ci_kick_off_with_stages(
        self,
        parent_id:      str | None,
        parent_summary: str,
        assignee:       str,
        stages:         list[str],
        create_parent:  bool,
    ) -> None:
        self._active = False
        project     = self._ci_project
        description = self._ci_description

        if create_parent:
            sublime.status_message(
                f"Notes: creating {project} issue '{parent_summary}' + "
                f"{len(stages)} stage(s)..."
            )
        else:
            sublime.status_message(
                f"Notes: creating {len(stages)} stage sub-task(s) under {parent_id}..."
            )

        sublime.set_timeout_async(
            lambda: self._ci_do_create_with_stages(
                project        = project,
                parent_id      = parent_id,
                parent_summary = parent_summary,
                description    = description,
                assignee       = assignee,
                stages         = stages,
                create_parent  = create_parent,
            ), 0,
        )

    def _ci_do_create_with_stages(
        self,
        project:        str,
        parent_id:      str | None,
        parent_summary: str,
        description:    str,
        assignee:       str,
        stages:         list[str],
        create_parent:  bool,
    ) -> None:
        base = _youtrack_base()

        if create_parent:
            try:
                parent_id = _yt_create_issue(project, parent_summary, description, assignee)
            except IssueCreateError as exc:
                err_msg = str(exc)
                sublime.set_timeout(
                    lambda: sublime.error_message(
                        f"Notes - failed to create parent issue:\n\n{err_msg}"
                    ), 0,
                )
                return

        assert parent_id is not None

        child_results: list[tuple[str, str, bool]] = []
        for stage in stages:
            child_summary = f"{parent_summary} - {stage}"
            try:
                child_id = _yt_create_issue(project, child_summary, "", assignee)
                linked   = _yt_link_as_subtask(parent_id, child_id)
                child_results.append((stage, child_id, linked))
            except IssueCreateError as exc:
                log.warning("YouTrack: failed to create stage '%s': %s", stage, exc)
                child_results.append((stage, f"FAILED: {exc}", False))

        _parent_id_snap  = parent_id
        _parent_url_snap = f"{base}{parent_id}"

        def _notify() -> None:
            ok_children = [cid for _, cid, _ in child_results if not cid.startswith("FAILED:")]
            if ok_children:
                child_refs  = ", ".join(f"#{cid}" for cid in ok_children)
                stage_entry = f"- [{_now_hhmm()}] [CREATED] for each stage: {child_refs}"
                try:
                    add_note_raw(_parent_id_snap, stage_entry)
                except Exception as exc:
                    log.warning("Could not write stage CREATED entry for %s: %s", _parent_id_snap, exc)
            else:
                try:
                    add_note(_parent_id_snap, "CREATED")
                except Exception as exc:
                    log.warning("Could not write CREATED for parent %s: %s", _parent_id_snap, exc)

            sublime.set_clipboard(_parent_url_snap)
            msg_lines = [
                f"Parent issue:   {_parent_id_snap}",
                f"URL:            {_parent_url_snap}",
                "Parent URL copied to clipboard.", "",
                "Stage sub-tasks:",
            ]
            for stage, cid_or_err, linked in child_results:
                if cid_or_err.startswith("FAILED:"):
                    msg_lines.append(f"  [{stage}]  FAILED - {cid_or_err[7:]}")
                else:
                    link_note = " (linked as subtask)" if linked else " (standalone)"
                    msg_lines.append(f"  [{stage}]  {cid_or_err}{link_note}")

            sublime.message_dialog("\n".join(msg_lines))
            n_ok = len(ok_children)
            sublime.status_message(
                f"Notes: {_parent_id_snap} + {n_ok}/{len(stages)} stage(s) created"
            )

        sublime.set_timeout(_notify, 0)

    # ------------------------------------------------------------------
    # Import from YouTrack  (mode="me" | mode="all")
    # ------------------------------------------------------------------

    def _start_import_from_yt(self, mode: str) -> None:
        """
        Kick off the import flow.

        mode="me"  -> fetch issues assigned to the current user
                      uses query: for: me #Unresolved project: {PROJECT}

        mode="all" -> fetch all unresolved issues in the project
                      uses query: #Unresolved project: {PROJECT}
        """
        project = _default_project()
        if not project:
            self._active = False
            sublime.error_message(
                "Notes - default_project is not set.\n\n"
                "Run 'Notes - Settings' and set:\n"
                '  "default_project": "MYPROJECT"'
            )
            return

        label = "assigned to me" if mode == "me" else "all unresolved"
        sublime.status_message(
            f"Notes: fetching YouTrack issues for {project} ({label})..."
        )
        sublime.set_timeout_async(
            lambda: self._fetch_yt_for_import(project, mode), 0
        )

    def _fetch_yt_for_import(self, project: str, mode: str) -> None:
        if mode == "me":
            issues, err_msg = _fetch_my_assigned_issues_for_import(project)
        else:
            issues, err_msg = _fetch_project_issues_for_import(project)
        sublime.set_timeout(
            lambda: self._show_yt_import_panel(issues, project, mode, err_msg), 0
        )

    def _show_yt_import_panel(
        self,
        issues:   list[dict],
        project:  str,
        mode:     str,
        err_msg:  str | None,
    ) -> None:
        if not issues:
            self._active = False
            if err_msg:
                low = err_msg.lower()
                if "timed out" in low or "timeout" in low:
                    sublime.status_message(
                        f"Notes: YouTrack timed out fetching {project} issues "
                        f"— check network or increase api_timeout_sec. ({err_msg})"
                    )
                elif "cannot reach" in low or "network" in low or "urlopen" in low:
                    sublime.status_message(
                        f"Notes: Cannot reach YouTrack ({err_msg}) "
                        f"— check youtrack_base URL and connectivity."
                    )
                elif "401" in err_msg or "authentication" in low:
                    sublime.status_message(
                        "Notes: YouTrack authentication failed — check youtrack_token."
                    )
                elif "403" in err_msg or "permission" in low:
                    sublime.status_message(
                        "Notes: YouTrack permission denied — token needs Read Issue permission."
                    )
                elif "404" in err_msg or "not found" in low:
                    sublime.status_message(
                        f"Notes: YouTrack project '{project}' not found — check default_project."
                    )
                else:
                    sublime.status_message(
                        f"Notes: Could not fetch issues from YouTrack — {err_msg}"
                    )
            else:
                label = "assigned to you" if mode == "me" else "unresolved"
                sublime.status_message(
                    f"Notes: no {label} issues found in project {project}."
                )
            return

        self._yt_import_issues = issues
        panel_items: list[list[str]] = []
        for issue in issues:
            iid     = issue.get("idReadable") or ""
            summary = issue.get("summary") or "(no summary)"
            parsed  = _parse_youtrack_issue(issue)
            state   = parsed.get("state") or ""
            assign  = parsed.get("assignee") or ""
            sub     = "  ".join(x for x in [state, assign] if x)
            panel_items.append(
                [f"{iid}  {summary}", sub] if sub else [f"{iid}  {summary}"]
            )

        mode_label = "assigned to me" if mode == "me" else "all unresolved"
        self.window.show_quick_panel(
            panel_items,
            self._on_yt_issue_selected,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder=f"Import from {project} ({mode_label})...",
        )

    def _on_yt_issue_selected(self, index: int) -> None:
        if index == -1:
            self._active = False
            sublime.status_message("Notes: import cancelled.")
            return
        issue = self._yt_import_issues[index]
        self._ticket_id = (issue.get("idReadable") or "").upper()
        if not self._ticket_id:
            self._active = False
            sublime.status_message("Notes: could not determine ticket ID.")
            return
        self._prompt_description()

    # ------------------------------------------------------------------
    # Description + write
    # ------------------------------------------------------------------

    def _prompt_description(self) -> None:
        self.window.show_input_panel(
            f"Description for {self._ticket_id}:",
            "",
            self._on_description,
            None,
            self._on_cancel,
        )

    def _on_description(self, raw: str) -> None:
        self._active = False
        desc = raw.strip()
        if not desc:
            sublime.status_message(
                "Notes: description cannot be empty - entry skipped."
            )
            return

        try:
            add_note(self._ticket_id, desc)
            sublime.status_message(f"Notes: [{self._ticket_id}] entry added.")
        except RuntimeError as exc:
            sublime.error_message(f"Notes - could not write entry:\n\n{exc}")
            return
        except Exception as exc:
            log.exception("Unexpected error in add_note")
            sublime.error_message(
                f"Notes - unexpected error:\n\n{type(exc).__name__}: {exc}"
            )
            return

        tid = self._ticket_id

        if tid not in (_TODO_ID, _OPS_ID) and _youtrack_token() and _youtrack_base():
            desc_upper = desc.upper()

            def _maybe_post_comment():
                if _post_comments_enabled():
                    comment_text = desc
                    sublime.set_timeout_async(
                        lambda: self._post_comment(tid, comment_text), 0
                    )

            if desc_upper in ("DONE", "REVIEW"):
                action = "Done" if desc_upper == "DONE" else "In Review"
                items = [
                    [f"Set YouTrack {tid} → {action}", "Confirm state change"],
                    ["Skip YouTrack state change", "Keep local note only"],
                ]

                def on_pick(index: int):
                    if index == 0:
                        if desc_upper == "DONE":
                            sublime.set_timeout_async(
                                lambda: _set_youtrack_done(tid), 0
                            )
                        else:
                            sublime.set_timeout_async(
                                lambda: _set_youtrack_in_review(tid), 0
                            )
                    _maybe_post_comment()

                self.window.show_quick_panel(items, on_pick)
            else:
                _maybe_post_comment()

    def _post_comment(self, ticket_id: str, text: str) -> None:
        ok = _yt_add_comment(ticket_id, text)
        if ok:
            sublime.set_timeout(
                lambda: sublime.status_message(
                    f"Notes: comment posted to {ticket_id}"
                ), 0,
            )
        else:
            sublime.set_timeout(
                lambda: sublime.status_message(
                    f"Notes: WARNING - could not post comment to {ticket_id}"
                ), 0,
            )

    def _on_cancel(self) -> None:
        self._active = False
        sublime.status_message("Notes: cancelled.")


class NotesSearchCommand(sublime_plugin.WindowCommand):
    """Command: notes_search  |  Palette: Notes - Search"""

    def run(self) -> None:
        try:
            index, all_tickets = _get_ticket_index()
        except RuntimeError as exc:
            sublime.error_message(f"Notes - cannot read file:\n\n{exc}")
            return

        if not index:
            sublime.status_message(
                "Notes: no entries found — notes file is empty or has no tickets yet. "
                "Use 'Notes - Add' to create your first entry."
            )
            return

        self._index = index
        self._tickets = [t for t in all_tickets if t != _OPS_ID]
        if not self._tickets:
            sublime.status_message(
                "Notes: no searchable tickets found "
                "(only OPS entries present, or file is empty)."
            )
            return

        panel_items: list[list[str]] = []
        for tid in self._tickets:
            entries = self._index[tid]
            desc    = _first_bullet_from_index(entries)
            if tid == _TODO_ID:
                label = _TODO_SEARCH_LABEL
            else:
                done_mark = (
                    "  [DONE]"
                    if any("[DONE]<<-" in e for e in entries)
                    else ""
                )
                label = f"{tid}{done_mark}"
            panel_items.append([label, desc] if desc else [label])

        self.window.show_quick_panel(
            panel_items,
            self._on_select,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder="Search ticket ID or TODO...",
        )

    def _on_select(self, index: int) -> None:
        if index == -1:
            return
        tid = self._tickets[index]

        if tid == _TODO_ID:
            self._show_todo(self._index[tid])
            return

        entries    = self._index[tid]
        name       = f"Notes: {tid}"
        lines_out: list[str] = [
            _SEP,
            f"# {tid}:",
            _SEP,
            "",
        ]
        lines_out.extend(entries)
        content = "\n".join(lines_out) + "\n"
        _open_scratch_view(self.window, name, content)

    def _show_todo(self, local_entries: list[str]) -> None:
        local_lines: list[str] = [
            _SEP,
            "# TODO - local notes (all dates)",
            _SEP,
            "",
        ]
        local_lines.extend(local_entries)
        local_body = "\n".join(local_lines)

        project = _default_project()
        if project and _youtrack_token() and _youtrack_base():
            view = self.window.new_file()
            view.set_name("Notes: TODO")
            view.set_scratch(True)
            view.set_read_only(False)
            view.settings().set("stnotes_view_name", "Notes: TODO")
            loading_text = (
                local_body
                + f"\n\n{_SEP}\n# YouTrack open issues [{project}] - loading...\n{_SEP}\n"
            )
            view.run_command("notes_insert_text", {"text": loading_text})
            view.set_read_only(True)
            _assign_stnotes_syntax(view)

            def _fetch_and_fill() -> None:
                yt_issues = _fetch_my_open_issues(project)

                def _render() -> None:
                    yt_section = _build_yt_issues_section(project, yt_issues)
                    full       = local_body + "\n\n" + yt_section
                    view.set_read_only(False)
                    view.run_command("notes_replace_text", {"text": full})
                    view.set_read_only(True)

                sublime.set_timeout(_render, 0)

            sublime.set_timeout_async(_fetch_and_fill, 0)
        else:
            view = self.window.new_file()
            view.set_name("Notes: TODO")
            view.set_scratch(True)
            view.set_read_only(False)
            view.settings().set("stnotes_view_name", "Notes: TODO")
            view.run_command("notes_insert_text", {"text": local_body})
            view.set_read_only(True)
            _assign_stnotes_syntax(view)


class NotesOpenIssueCommand(sublime_plugin.WindowCommand):
    """Command: notes_open_issue  |  Palette: Notes - Open Issue"""

    _OPEN_BY_ID        = "__open_by_id__"
    _UNASSIGNED_ISSUES = "__unassigned_issues__"
    _ALL_ISSUES        = "__all_issues__"

    def run(self) -> None:
        base = _youtrack_base()
        if not base:
            sublime.error_message(
                "Notes - YouTrack base URL not configured.\n\n"
                "Run 'Notes - Settings' and set:\n"
                '  "youtrack_base": "https://youtrack.example.com/issue/"'
            )
            return

        base_err = _validate_youtrack_base(base)
        if base_err:
            sublime.error_message(f"Notes - invalid youtrack_base:\n\n{base_err}")
            return

        self._base = base

        try:
            index, all_tickets = _get_ticket_index()
        except RuntimeError as exc:
            sublime.error_message(f"Notes - cannot read file:\n\n{exc}")
            return

        tickets = [
            t for t in all_tickets
            if t not in (_TODO_ID, _OPS_ID)
        ]

        project       = _default_project()
        yt_configured = bool(_youtrack_token() and project)

        panel_items: list[list[str]] = [[_OPEN_BY_ID_LABEL, "type any ticket ID"]]
        self._tickets: list[str]     = [self._OPEN_BY_ID]

        if yt_configured:
            panel_items.append([
                f"[ All issues ({project}) ]",
                "YouTrack: all unresolved issues",
            ])
            self._tickets.append(self._ALL_ISSUES)

            panel_items.append([
                f"[ Unassigned issues ({project}) ]",
                "YouTrack: unassigned open issues",
            ])
            self._tickets.append(self._UNASSIGNED_ISSUES)

        for tid in tickets:
            entries   = index[tid]
            desc      = _first_bullet_from_index(entries)
            done_mark = (
                "  [DONE]"
                if any("[DONE]<<-" in e for e in entries)
                else ""
            )
            label = f"{tid}{done_mark}"
            panel_items.append([label, desc] if desc else [label])
            self._tickets.append(tid)

        self.window.show_quick_panel(
            panel_items,
            self._on_select,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder="Select ticket, open by ID, or view YouTrack issues...",
        )

    def _on_select(self, index: int) -> None:
        if index == -1:
            return
        tid = self._tickets[index]

        if tid == self._OPEN_BY_ID:
            self.window.show_input_panel(
                "Ticket ID to open (e.g. PROJ-1234):",
                "",
                self._on_manual_id,
                None,
                None,
            )
            return

        if tid == self._ALL_ISSUES:
            self._show_all_issues()
            return

        if tid == self._UNASSIGNED_ISSUES:
            self._show_unassigned_issues()
            return

        url = f"{self._base}{tid}"
        _open_in_browser(url)
        sublime.status_message(f"Notes: opened {url}")

    def _on_manual_id(self, raw: str) -> None:
        tid = raw.strip().upper()
        if not tid:
            sublime.status_message("Notes: no ticket ID entered - cancelled.")
            return
        if not _ISSUE_ID_RE.match(tid):
            sublime.error_message(
                "Notes - invalid ticket ID.\n\n"
                "Expected form: PROJ-1234"
            )
            return
        url = f"{self._base}{tid}"
        _open_in_browser(url)
        sublime.status_message(f"Notes: opened {url}")

    # ------------------------------------------------------------------
    # All issues — quick panel
    # ------------------------------------------------------------------

    def _show_all_issues(self) -> None:
        project = _default_project()
        if not project:
            sublime.status_message("Notes: default_project is not set.")
            return
        sublime.status_message(f"Notes: fetching all issues for {project}...")
        sublime.set_timeout_async(lambda: self._fetch_all(project), 0)

    def _fetch_all(self, project: str) -> None:
        issues, err_msg = _fetch_all_project_issues(project)
        sublime.set_timeout(lambda: self._show_panel_all(issues, project, err_msg), 0)

    def _show_panel_all(
        self, issues: list[dict], project: str, err_msg: str | None
    ) -> None:
        if err_msg and not issues:
            sublime.error_message(
                f"Notes: could not fetch issues for {project}\n\n{err_msg}"
            )
            return
        if not issues:
            sublime.status_message(f"Notes: no unresolved issues found in {project}.")
            return

        self._panel_all_issues = issues
        panel_items: list[list[str]] = []
        for issue in issues:
            iid     = issue.get("idReadable") or ""
            summary = issue.get("summary") or "(no summary)"
            parsed  = _parse_youtrack_issue(issue)
            state   = parsed.get("state") or ""
            assign  = parsed.get("assignee") or "Unassigned"
            meta    = f"{state}  |  {assign}" if state else assign
            panel_items.append([f"{iid}  {summary}", meta])

        sublime.status_message("")
        self.window.show_quick_panel(
            panel_items,
            self._on_all_issues_select,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder=f"All unresolved issues in {project}...",
        )

    def _on_all_issues_select(self, index: int) -> None:
        if index == -1:
            return
        issue = self._panel_all_issues[index]
        iid   = issue.get("idReadable") or ""
        if not iid:
            return
        url = f"{self._base}{iid}"
        _open_in_browser(url)
        sublime.status_message(f"Notes: opened {url}")

    # ------------------------------------------------------------------
    # Unassigned issues — quick panel
    # ------------------------------------------------------------------

    def _show_unassigned_issues(self) -> None:
        project = _default_project()
        if not project:
            sublime.status_message("Notes: default_project is not set.")
            return
        sublime.status_message(
            f"Notes: fetching unassigned issues for {project}..."
        )
        sublime.set_timeout_async(lambda: self._fetch_unassigned(project), 0)

    def _fetch_unassigned(self, project: str) -> None:
        issues, err_msg = _fetch_unassigned_issues(project)
        sublime.set_timeout(
            lambda: self._show_panel_unassigned(issues, project, err_msg), 0
        )

    def _show_panel_unassigned(
        self, issues: list[dict], project: str, err_msg: str | None
    ) -> None:
        if err_msg and not issues:
            sublime.error_message(
                f"Notes: could not fetch unassigned issues for {project}\n\n{err_msg}"
            )
            return
        if not issues:
            sublime.status_message(
                f"Notes: no unassigned open issues found in {project}."
            )
            return

        self._panel_unassigned = issues
        panel_items: list[list[str]] = []
        for issue in issues:
            iid     = issue.get("idReadable") or ""
            summary = issue.get("summary") or "(no summary)"
            parsed  = _parse_youtrack_issue(issue)
            state   = parsed.get("state") or ""
            panel_items.append([f"{iid}  {summary}", state])

        sublime.status_message("")
        self.window.show_quick_panel(
            panel_items,
            self._on_unassigned_select,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder=f"Unassigned open issues in {project}...",
        )

    def _on_unassigned_select(self, index: int) -> None:
        if index == -1:
            return
        issue = self._panel_unassigned[index]
        iid   = issue.get("idReadable") or ""
        if not iid:
            return
        url = f"{self._base}{iid}"
        _open_in_browser(url)
        sublime.status_message(f"Notes: opened {url}")


class NotesWeeklySearchCommand(sublime_plugin.WindowCommand):
    """Command: notes_weekly_search  |  Palette: Notes - Weekly Search"""

    def run(self) -> None:
        try:
            lines = _read_notes()
        except RuntimeError as exc:
            sublime.error_message(f"Notes - cannot read file:\n\n{exc}")
            return
        if not lines:
            sublime.status_message("Notes: file is empty.")
            return

        self._lines = lines
        weeks = _collect_all_weeks(lines)

        if not weeks:
            sublime.status_message("Notes: no dated entries found.")
            return

        panel_items: list[list[str]] = []
        for week_key, monday, sunday in weeks:
            label = (
                f"{week_key}  "
                f"({monday.strftime('%b %d')} - {sunday.strftime('%b %d, %Y')})"
            )
            day_count = sum(
                1 for line in lines
                if (d := _parse_date_header(line.strip())) is not None
                and monday <= d <= sunday
            )
            day_hint = f"{day_count} day{'s' if day_count != 1 else ''} with entries"
            panel_items.append([label, day_hint])

        self._weeks = weeks

        self.window.show_quick_panel(
            panel_items,
            self._on_select,
            flags=sublime.MONOSPACE_FONT,
            selected_index=0,
            placeholder="Select week...",
        )

    def _on_select(self, index: int) -> None:
        if index == -1:
            return
        week_key, monday, sunday = self._weeks[index]
        sections = _collect_weekly_sections(self._lines, monday, sunday)

        if not sections:
            sublime.status_message(f"Notes: no entries found for {week_key}.")
            return

        content = _render_weekly_summary(sections, monday, sunday)
        title   = (
            f"Notes: Weekly {week_key}  "
            f"[{monday.strftime('%Y.%m.%d')} - {sunday.strftime('%Y.%m.%d')}]"
        )
        _open_scratch_view(self.window, title, content)


class NotesWeeklySummaryCommand(sublime_plugin.WindowCommand):
    """Command: notes_weekly_summary  |  Palette: Notes - Weekly Summary"""

    def run(self) -> None:
        try:
            lines = _read_notes()
        except RuntimeError as exc:
            sublime.error_message(f"Notes - cannot read file:\n\n{exc}")
            return
        if not lines:
            sublime.status_message("Notes: file is empty.")
            return

        today      = datetime.now().date()
        start_date = today - timedelta(days=7)

        sections = _collect_weekly_sections(lines, start_date, today)

        if not sections:
            sublime.status_message(
                f"Notes: no entries found between {start_date} and {today}."
            )
            return

        content = _render_weekly_summary(sections, start_date, today)
        title = (
            f"Notes: Weekly Summary  "
            f"[{start_date.strftime('%Y.%m.%d')} - {today.strftime('%Y.%m.%d')}]"
            f"  ({start_date.strftime('%A')} to {today.strftime('%A')})"
        )
        _open_scratch_view(self.window, title, content)


# ---------------------------------------------------------------------------
# Notes - Create Issue  (standalone — kept for direct palette use)
# ---------------------------------------------------------------------------

class NotesCreateIssueCommand(sublime_plugin.WindowCommand):
    """
    Command: notes_create_issue
    NOTE: This command is intentionally omitted from Default.sublime-commands
    (the palette). It is still callable programmatically.
    Use 'Notes - Add' -> '[ + Create new issue ]' instead.
    """

    _active: bool = False

    _with_stages:         bool
    _parent_exists:       bool
    _project:             str
    _summary:             str
    _description:         str
    _assignee:            str
    _existing_parent_id:  str

    def run(self) -> None:
        if not _youtrack_token() or not _youtrack_base():
            sublime.error_message(
                "Notes - YouTrack not configured.\n\n"
                "Run 'Notes - Settings' and set:\n"
                '  "youtrack_base":  "https://youtrack.example.com/issue/"\n'
                '  "youtrack_token": "<your permanent token>"'
            )
            return

        base_err = _validate_youtrack_base(_youtrack_base())
        if base_err:
            sublime.error_message(f"Notes - invalid youtrack_base:\n\n{base_err}")
            return

        if self._active:
            sublime.status_message("Notes: already creating an issue.")
            return

        self._active             = True
        self._with_stages        = False
        self._parent_exists      = False
        self._project            = _default_project()
        self._summary            = ""
        self._description        = ""
        self._assignee           = ""
        self._existing_parent_id = ""

        self.window.show_input_panel(
            "Create stage sub-tasks? [y/N]:",
            "n",
            self._on_stages_yn,
            None,
            self._on_cancel,
        )

    def _on_stages_yn(self, raw: str) -> None:
        answer = raw.strip().lower()
        if answer in ("y", "yes"):
            self._with_stages = True
            self.window.show_input_panel(
                "Does parent ticket already exist? [y/N]:",
                "n",
                self._on_parent_exists_yn,
                None,
                self._on_cancel,
            )
        else:
            self._with_stages = False
            self._prompt_project()

    def _on_parent_exists_yn(self, raw: str) -> None:
        answer = raw.strip().lower()
        if answer in ("y", "yes"):
            self._parent_exists = True
            self.window.show_input_panel(
                "Parent ticket ID (e.g. PROJ-1234):",
                "",
                self._on_existing_parent_id,
                None,
                self._on_cancel,
            )
        else:
            self._parent_exists = False
            self._prompt_project()

    def _on_existing_parent_id(self, raw: str) -> None:
        tid_raw = raw.strip().upper()
        if not tid_raw:
            self._active = False
            sublime.status_message("Notes: ticket ID cannot be empty - cancelled.")
            return

        self._existing_parent_id = tid_raw
        sublime.status_message(f"Notes: fetching parent info for {tid_raw}...")

        def _fetch() -> None:
            summary, assignee_login = _fetch_parent_info(tid_raw)

            def _continue() -> None:
                if summary is None:
                    sublime.status_message(
                        f"Notes: WARNING - could not fetch info for {tid_raw}. "
                        "Continuing with empty defaults."
                    )
                    self._summary    = tid_raw
                    assignee_default = ""
                else:
                    self._summary    = summary
                    assignee_default = assignee_login or ""

                self.window.show_input_panel(
                    f"Assignee login [{assignee_default or 'optional'}]:",
                    assignee_default,
                    self._on_assignee_existing_parent,
                    None,
                    self._on_cancel,
                )

            sublime.set_timeout(_continue, 0)

        sublime.set_timeout_async(_fetch, 0)

    def _on_assignee_existing_parent(self, raw: str) -> None:
        self._assignee = raw.strip()
        self._resolve_stages_then_kick_off(
            parent_id      = self._existing_parent_id,
            parent_summary = self._summary,
            assignee       = self._assignee,
            create_parent  = False,
        )

    def _prompt_project(self) -> None:
        self.window.show_input_panel(
            "Project (shortName):",
            self._project,
            self._on_project,
            None,
            self._on_cancel,
        )

    def _on_project(self, raw: str) -> None:
        project = raw.strip().upper()
        if not project:
            self._active = False
            sublime.status_message("Notes: project cannot be empty - cancelled.")
            return
        self._project = project
        self.window.show_input_panel(
            f"Summary [{self._project}]:",
            "",
            self._on_summary,
            None,
            self._on_cancel,
        )

    def _on_summary(self, raw: str) -> None:
        summary = raw.strip()
        if not summary:
            self._active = False
            sublime.status_message("Notes: summary cannot be empty - cancelled.")
            return
        self._summary = summary
        self.window.show_input_panel(
            "Description (optional - Enter to skip):",
            "",
            self._on_description,
            None,
            self._on_cancel,
        )

    def _on_description(self, raw: str) -> None:
        self._description = raw.strip()
        self.window.show_input_panel(
            "Assign to me? [y/N]:",
            "n",
            self._on_assign_to_me_yn,
            None,
            self._on_cancel,
        )

    def _on_assign_to_me_yn(self, raw: str) -> None:
        if raw.strip().lower() in ("y", "yes"):
            sublime.set_timeout_async(self._fetch_me_then_proceed, 0)
        else:
            self.window.show_input_panel(
                "Assignee login (optional - Enter to skip):",
                "",
                self._on_assignee_explicit,
                None,
                self._on_cancel,
            )

    def _on_assignee_explicit(self, raw: str) -> None:
        self._assignee = raw.strip()
        self._proceed_after_assignee()

    def _fetch_me_then_proceed(self) -> None:
        login, fullname = _fetch_current_user_login()
        if login:
            self._assignee = login
            display_name   = f"{fullname} ({login})" if fullname else login
            sublime.set_timeout(
                lambda: sublime.status_message(f"Notes: assignee set to {display_name}"), 0
            )
        else:
            self._assignee = ""
            sublime.set_timeout(
                lambda: sublime.status_message(
                    "Notes: could not fetch current user - leaving unassigned."
                ), 0
            )
        sublime.set_timeout(self._proceed_after_assignee, 0)

    def _proceed_after_assignee(self) -> None:
        if self._with_stages:
            self._resolve_stages_then_kick_off(
                parent_id      = None,
                parent_summary = self._summary,
                assignee       = self._assignee,
                create_parent  = True,
            )
        else:
            self._kick_off_single(
                project     = self._project,
                summary     = self._summary,
                description = self._description,
                assignee    = self._assignee,
            )

    def _resolve_stages_then_kick_off(
        self,
        parent_id:      str | None,
        parent_summary: str,
        assignee:       str,
        create_parent:  bool,
    ) -> None:
        stages = _issue_stages()
        if stages:
            self._kick_off_with_stages(
                parent_id      = parent_id,
                parent_summary = parent_summary,
                assignee       = assignee,
                stages         = stages,
                create_parent  = create_parent,
            )
        else:
            self._pending_stage_kwargs = {
                "parent_id":      parent_id,
                "parent_summary": parent_summary,
                "assignee":       assignee,
                "create_parent":  create_parent,
            }
            self.window.show_input_panel(
                "Stage names (comma-separated, e.g. Design,Dev,QA,Deploy):",
                "",
                self._on_stage_names_entered,
                None,
                self._on_cancel,
            )

    def _on_stage_names_entered(self, raw: str) -> None:
        stages = [s.strip() for s in raw.split(",") if s.strip()]
        if not stages:
            self._active = False
            sublime.status_message("Notes: no stages entered - cancelled.")
            return
        s = _settings()
        s.set("issue_stages", stages)
        sublime.save_settings(_SETTINGS_FILE)
        sublime.status_message(f"Notes: saved {len(stages)} stages to settings.")
        kw = self._pending_stage_kwargs
        self._kick_off_with_stages(
            parent_id      = kw["parent_id"],
            parent_summary = kw["parent_summary"],
            assignee       = kw["assignee"],
            stages         = stages,
            create_parent  = kw["create_parent"],
        )

    def _kick_off_single(
        self, project: str, summary: str, description: str, assignee: str,
    ) -> None:
        self._active = False
        sublime.status_message(f"Notes: creating {project} issue '{summary}'...")
        sublime.set_timeout_async(
            lambda: self._do_create_single(project, summary, description, assignee), 0
        )

    def _do_create_single(
        self, project: str, summary: str, description: str, assignee: str,
    ) -> None:
        try:
            ticket_id = _yt_create_issue(project, summary, description, assignee)
        except IssueCreateError as exc:
            err_msg = str(exc)
            sublime.set_timeout(
                lambda: sublime.error_message(
                    f"Notes - failed to create issue:\n\n{err_msg}"
                ), 0,
            )
            return

        base = _youtrack_base()
        url  = f"{base}{ticket_id}"

        def _notify() -> None:
            try:
                add_note(ticket_id, "CREATED")
            except Exception as exc:
                log.warning("Could not write CREATED entry: %s", exc)
            sublime.set_clipboard(url)
            sublime.message_dialog(
                f"Issue created: {ticket_id}\nURL: {url}\n\nURL copied to clipboard."
            )
            sublime.status_message(f"Notes: created {ticket_id}")

        sublime.set_timeout(_notify, 0)

    def _kick_off_with_stages(
        self,
        parent_id:      str | None,
        parent_summary: str,
        assignee:       str,
        stages:         list[str],
        create_parent:  bool,
    ) -> None:
        self._active = False
        project      = self._project
        description  = self._description

        if create_parent:
            sublime.status_message(
                f"Notes: creating {project} issue '{parent_summary}' + "
                f"{len(stages)} stage(s)..."
            )
        else:
            sublime.status_message(
                f"Notes: creating {len(stages)} stage sub-task(s) under {parent_id}..."
            )

        sublime.set_timeout_async(
            lambda: self._do_create_with_stages(
                project        = project,
                parent_id      = parent_id,
                parent_summary = parent_summary,
                description    = description,
                assignee       = assignee,
                stages         = stages,
                create_parent  = create_parent,
            ), 0,
        )

    def _do_create_with_stages(
        self,
        project:        str,
        parent_id:      str | None,
        parent_summary: str,
        description:    str,
        assignee:       str,
        stages:         list[str],
        create_parent:  bool,
    ) -> None:
        base = _youtrack_base()

        if create_parent:
            try:
                parent_id = _yt_create_issue(project, parent_summary, description, assignee)
            except IssueCreateError as exc:
                err_msg = str(exc)
                sublime.set_timeout(
                    lambda: sublime.error_message(
                        f"Notes - failed to create parent issue:\n\n{err_msg}"
                    ), 0,
                )
                return

        assert parent_id is not None

        child_results: list[tuple[str, str, bool]] = []
        for stage in stages:
            child_summary = f"{parent_summary} - {stage}"
            try:
                child_id = _yt_create_issue(project, child_summary, "", assignee)
                linked   = _yt_link_as_subtask(parent_id, child_id)
                child_results.append((stage, child_id, linked))
                log.info("YouTrack: created stage '%s' as %s (linked=%s)", stage, child_id, linked)
            except IssueCreateError as exc:
                log.warning("YouTrack: failed to create stage '%s': %s", stage, exc)
                child_results.append((stage, f"FAILED: {exc}", False))

        _parent_id_snap  = parent_id
        _parent_url_snap = f"{base}{parent_id}"

        def _notify() -> None:
            ok_children = [
                child_id
                for _, child_id, _ in child_results
                if not child_id.startswith("FAILED:")
            ]

            if ok_children:
                child_refs  = ", ".join(f"#{cid}" for cid in ok_children)
                stage_entry = f"- [{_now_hhmm()}] [CREATED] for each stage: {child_refs}"
                try:
                    add_note_raw(_parent_id_snap, stage_entry)
                except Exception as exc:
                    log.warning(
                        "Could not write stage CREATED entry for %s: %s", _parent_id_snap, exc
                    )
            else:
                try:
                    add_note(_parent_id_snap, "CREATED")
                except Exception as exc:
                    log.warning("Could not write CREATED for parent %s: %s", _parent_id_snap, exc)

            sublime.set_clipboard(_parent_url_snap)
            msg_lines = [
                f"Parent issue:   {_parent_id_snap}",
                f"URL:            {_parent_url_snap}",
                "Parent URL copied to clipboard.", "",
                "Stage sub-tasks:",
            ]
            for stage, child_id_or_err, linked in child_results:
                if child_id_or_err.startswith("FAILED:"):
                    msg_lines.append(f"  [{stage}]  FAILED - {child_id_or_err[7:]}")
                else:
                    link_note = " (linked as subtask)" if linked else " (standalone)"
                    msg_lines.append(f"  [{stage}]  {child_id_or_err}{link_note}")

            sublime.message_dialog("\n".join(msg_lines))
            n_ok = len(ok_children)
            sublime.status_message(
                f"Notes: {_parent_id_snap} + {n_ok}/{len(stages)} stage(s) created"
            )

        sublime.set_timeout(_notify, 0)

    def _on_cancel(self) -> None:
        self._active = False
        sublime.status_message("Notes: cancelled.")


class NotesEditCommand(sublime_plugin.WindowCommand):
    """Command: notes_edit  |  Palette: Notes - Edit"""

    def run(self) -> None:
        try:
            if os.path.isdir(_notes_file()):
                sublime.error_message(
                    f"Notes - path is a directory, not a file:\n{_notes_file()}"
                )
                return
            if not os.path.exists(_notes_file()):
                _write_notes([])
        except RuntimeError as exc:
            sublime.error_message(f"Notes - cannot create file:\n\n{exc}")
            return

        view = self.window.open_file(_notes_file())

        def _set_syntax() -> None:
            if view.is_loading():
                sublime.set_timeout(_set_syntax, 50)
                return
            _assign_stnotes_syntax(view)

        _set_syntax()


class NotesSettingsCommand(sublime_plugin.WindowCommand):
    """Command: notes_settings  |  Palette: Notes - Settings"""

    def run(self) -> None:
        self.window.run_command(
            "edit_settings",
            {
                "base_file": "${packages}/notes/ST4Notes.sublime-settings",
                "default": (
                    "// ST4Notes Settings\n"
                    "// -----------------\n"
                    "// notes_file      : path to the local notes file (~ and ${home} ok via expanduser)\n"
                    "// youtrack_base   : base URL for ticket links (https:// required, trailing slash required)\n"
                    "// youtrack_token  : permanent API token (KEEP IN User settings only — never commit)\n"
                    "//   Generate at: YouTrack -> Profile -> Authentication -> New token\n"
                    "//   Required permissions: Read Issue, Create Issue, Update Issue, Create Comment\n"
                    "// default_project : pre-filled shortName for issue creation and import\n"
                    "//                   also used for TODO YT open issues list\n"
                    "// issue_stages    : stage names used when 'Create stage sub-tasks? y'\n"
                    "//                   Leave [] to be prompted at creation time.\n"
                    '//                   Example: ["Design", "Dev", "QA", "Deploy"]\n'
                    "// post_comments   : true/false — whether to post a YouTrack comment\n"
                    "//                   each time you add a note via 'Notes - Add'\n"
                    "//                   When false, notes are written locally only.\n"
                    "//                   Re-enabling does NOT backfill skipped comments.\n"
                    "// api_timeout_sec : seconds before a YouTrack API call times out (default 10)\n"
                    "// api_max_retries : transient-error retries (429/502/503) before giving up (default 2)\n"
                    "{\n"
                    '    "notes_file":       "~/Documents/ST4Notes",\n'
                    '    "youtrack_base":    "https://youtrack.example.com/issue/",\n'
                    '    "youtrack_token":   "",\n'
                    '    "default_project":  "",\n'
                    '    "issue_stages":     [],\n'
                    '    "post_comments":    false,\n'
                    '    "api_timeout_sec":  10,\n'
                    '    "api_max_retries":  2\n'
                    "}\n"
                ),
            },
        )


# ---------------------------------------------------------------------------
# Issue ID pattern
# ---------------------------------------------------------------------------

_ISSUE_ID_RE = re.compile(
    r"^[A-Z][A-Z0-9_]{0,30}-\d+$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# URL + ticket hover
# ---------------------------------------------------------------------------

class NotesUrlHoverListener(sublime_plugin.EventListener):

    def on_hover(
        self,
        view: sublime.View,
        point: int,
        hover_zone: int,
    ) -> None:
        if hover_zone != sublime.HOVER_TEXT:
            return

        if not _is_stnotes_view(view) and not _is_notes_scratch_view(view):
            return

        line_region = view.line(point)
        line_text   = view.substr(line_region)
        col         = point - line_region.begin()

        # 1. Check for a URL under the cursor
        url: str | None = None
        for m in _URL_RE.finditer(line_text):
            if m.start() <= col <= m.end():
                url = m.group(0)
                break

        if url:
            if _is_youtrack_host(url):
                base      = _youtrack_base()
                ticket_id = self._ticket_id_from_url(url, base)
                if ticket_id:
                    self._show_issue_popup(view, point, url, ticket_id)
                else:
                    self._show_plain_popup(view, point, url)
            else:
                self._show_plain_popup(view, point, url)
            return

        # 2. Check for a ticket-ID header:  # PROJ-1234:
        header_id = self._ticket_id_from_header(line_text)
        if header_id:
            base = _youtrack_base()
            if base:
                constructed_url = f"{base}{header_id}"
                self._show_issue_popup(view, point, constructed_url, header_id)
            return

        # 3. Check for an inline ticket ID in bullet text or anywhere in the line
        inline_id = self._ticket_id_from_inline(line_text, col)
        if inline_id:
            base = _youtrack_base()
            if base:
                constructed_url = f"{base}{inline_id}"
                self._show_issue_popup(view, point, constructed_url, inline_id)
            return

        # 4. Fallback: word under cursor (original behaviour)
        word_id = self._ticket_id_from_word(view, point)
        if word_id:
            base = _youtrack_base()
            if base:
                constructed_url = f"{base}{word_id}"
                self._show_issue_popup(view, point, constructed_url, word_id)

    # ------------------------------------------------------------------
    # Inline scan: find any PROJ-NNN overlapping the cursor column
    # ------------------------------------------------------------------

    def _ticket_id_from_inline(self, line_text: str, col: int) -> str | None:
        """
        Scan the entire line for ticket IDs (PROJ-NNN pattern).
        Return the one whose span contains the cursor column.
        """
        for m in _INLINE_TICKET_RE.finditer(line_text):
            if m.start() <= col <= m.end():
                candidate = m.group(1).upper()
                if candidate not in (_TODO_ID, _OPS_ID):
                    return candidate
        return None

    # ------------------------------------------------------------------

    def _show_issue_popup(self, view, point, url, ticket_id):
        if _youtrack_token():
            view.show_popup(
                self._loading_html(ticket_id, url),
                flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
                location=point,
                max_width=740,
                on_navigate=self._on_navigate,
            )
            sublime.set_timeout_async(
                lambda: self._fetch_and_update(view, point, ticket_id, url), 0
            )
        else:
            view.show_popup(
                _build_hover_html(ticket_id, url, None),
                flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
                location=point,
                max_width=740,
                on_navigate=self._on_navigate,
            )

    def _show_plain_popup(self, view, point, url):
        view.show_popup(
            _build_hover_html("", url, None),
            flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
            location=point,
            max_width=520,
            on_navigate=self._on_navigate,
        )

    def _fetch_and_update(self, view, point, ticket_id, url):
        raw = _fetch_youtrack_issue(ticket_id)
        if raw is _NOT_FOUND:
            html = _build_hover_html(ticket_id, url, None, not_found=True)
        elif raw is None:
            html = _build_hover_html(ticket_id, url, None)
        else:
            info = _parse_youtrack_issue(raw)
            html = _build_hover_html(ticket_id, url, info)
        sublime.set_timeout(lambda: view.update_popup(html), 0)

    def _ticket_id_from_url(self, url, base):
        if not base:
            return None
        if not url.lower().startswith(base.lower()):
            return None
        suffix = url[len(base):].split("?")[0].split("#")[0].strip("/")
        if suffix and _ISSUE_ID_RE.match(suffix.upper()):
            return suffix.upper()
        return None

    def _ticket_id_from_header(self, line_text: str) -> str | None:
        """
        Match lines like:  # PROJ-1234:
        Also handles the weekly summary format:  # PROJ-1234 - full history
        """
        # Standard header with colon
        m = re.match(
            r"^\s*#\s+([A-Z][A-Z0-9_\-]{1,63}):\s*$",
            line_text,
            re.IGNORECASE,
        )
        if m:
            candidate = m.group(1).upper()
            if _ISSUE_ID_RE.match(candidate):
                return candidate

        # Weekly/search scratch header: "# PROJ-1234 - full history" or "# PROJ-1234:"
        m2 = re.match(
            r"^\s*#\s+([A-Z][A-Z0-9_\-]{1,63})(?::|[\s\-])",
            line_text,
            re.IGNORECASE,
        )
        if m2:
            candidate = m2.group(1).upper()
            if _ISSUE_ID_RE.match(candidate) and candidate not in (_TODO_ID, _OPS_ID):
                return candidate

        return None

    def _ticket_id_from_word(self, view, point):
        word_region = view.word(point)
        if word_region.empty():
            return None
        raw = view.substr(word_region).strip(".,;:()[]{}\"'`")
        if not raw:
            return None
        if not _ISSUE_ID_RE.match(raw.upper()):
            return None
        candidate = raw.upper()
        if candidate in (_TODO_ID, _OPS_ID):
            return None
        return candidate

    def _loading_html(self, ticket_id, url):
        safe_url = _h(url)
        return (
            "<body id='stnotes-hover' "
            "style='margin:8px 12px;font-family:monospace'>"
            f"<div><a href='open:{safe_url}' "
            f"style='color:#56b6c2;text-decoration:none;font-weight:bold'>"
            f"&#128279; {_h(ticket_id)}</a>"
            f"&nbsp;<span style='color:#5c6370'>loading...</span></div>"
            "</body>"
        )

    def _on_navigate(self, href):
        if href.startswith("open:"):
            _open_in_browser(href[len("open:"):])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class NotesInsertTextCommand(sublime_plugin.TextCommand):
    """Internal: insert text at position 0."""

    def run(self, edit: sublime.Edit, text: str = "") -> None:
        self.view.insert(edit, 0, text)


class NotesReplaceTextCommand(sublime_plugin.TextCommand):
    """Internal: replace entire view content."""

    def run(self, edit: sublime.Edit, text: str = "") -> None:
        self.view.replace(edit, sublime.Region(0, self.view.size()), text)


# ---------------------------------------------------------------------------
# YouTrack — parse issue fields
# ---------------------------------------------------------------------------

def _parse_youtrack_issue(issue: dict) -> dict[str, str]:
    """
    Extract a flat dict of display fields from a raw YouTrack issue dict.
    Works with both _YT_FIELDS and _YT_LIST_FIELDS response shapes.
    """
    result: dict[str, str] = {}

    result["summary"] = (issue.get("summary") or "").strip()

    # created timestamp (only present in full _YT_FIELDS responses)
    created_ms = issue.get("created")
    if created_ms:
        try:
            dt = datetime.fromtimestamp(int(created_ms) / 1000)
            result["created"] = dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError, OverflowError):
            pass

    # reporter (only present in full _YT_FIELDS responses)
    reporter = issue.get("reporter")
    if isinstance(reporter, dict):
        full  = (reporter.get("fullName") or "").strip()
        login = (reporter.get("login") or "").strip()
        result["reporter"] = full or login

    # custom fields
    for cf in issue.get("customFields") or []:
        name  = (cf.get("name") or "").strip()
        value = cf.get("value")
        if value is None or not name:
            continue

        name_lower = name.lower()

        if name_lower == "assignee":
            if isinstance(value, dict):
                full  = (value.get("fullName") or "").strip()
                login = (value.get("login") or "").strip()
                result["assignee"]       = full or login
                result["assignee_login"] = login
            elif isinstance(value, str):
                result["assignee"]       = value.strip()
                result["assignee_login"] = value.strip()

        elif name_lower == "state":
            if isinstance(value, dict):
                result["state"] = (
                    value.get("name") or value.get("presentation") or ""
                ).strip()
            elif isinstance(value, str):
                result["state"] = value.strip()

        elif name_lower == "priority":
            if isinstance(value, dict):
                result["priority"] = (value.get("name") or "").strip()
            elif isinstance(value, str):
                result["priority"] = value.strip()

        elif name_lower in ("severity", "type"):
            if isinstance(value, dict):
                result["severity"] = (value.get("name") or "").strip()
            elif isinstance(value, str):
                result["severity"] = value.strip()

    return result
