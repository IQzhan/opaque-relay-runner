#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpaqueRelayRuntime: Zero-Leakage Authenticated In-Memory Execution Relay & Anti-Abuse Cadence Engine
====================================================================================================
- Pure Python 3 standard library implementation (`0` third-party pip dependencies).
- Contains ZERO private repository names, ZERO cloud folder IDs, and ZERO hardcoded credentials.
- Ingests and immediately pops sensitive environment variables (`OPAQUE_PACKET`, `OPAQUE_SHARE`,
  `OPAQUE_SECRET`), authenticates and decrypts the ephemeral dispatch envelope in memory using
  `HMAC-SHA256` Counter-Mode stream cipher + constant-time `HMAC-SHA256` MAC verification, enforces
  strict `math.isfinite` NaN/Inf/TTL replay guards and 16-byte nonce validation, enforces healthy
  low-frequency cadence guards (`45s` coalescing debounce + `30/hour` sliding-window cap), hydrates
  the authorized private bridge payload into an ephemeral `0o700` RAM directory, captures all
  stdout/stderr at both Python stream and OS file-descriptor (`fd=1,2`) levels (`0` bytes leaked to
  GitHub Actions console), and uploads encrypted telemetry (`opaque_relay_telemetry.enc.json`) to
  the private control plane.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import io
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.dont_write_bytecode = True
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

OPAQUE_PROTOCOL_VERSION = "1.0"
DEFAULT_COOLDOWN_SEC = 45.0
DEFAULT_MAX_HOURLY_RUNS = 30
DEFAULT_ENVELOPE_TTL_SEC = 900.0
SENSITIVE_ENV_KEYS = (
    "OPAQUE_PACKET",
    "OPAQUE_SHARE",
    "OPAQUE_SECRET",
    "GH_MASTER_TOKEN",
    "GITHUB_TOKEN",
    "GDRIVE_ACCESS_TOKEN",
    "GDRIVE_CREDENTIALS_JSON",
)


def ComputeSha256Hex(raw_bytes: bytes) -> str:
    """Computes the lowercase SHA-256 hex digest of `raw_bytes`."""
    return hashlib.sha256(raw_bytes).hexdigest()


def DeriveOpaqueMasterKey(share_k: str, secret_s: str = "") -> bytes:
    """
    Derives a 256-bit key from the ephemeral key share `share_k` and optional repository
    secret `secret_s` using domain-separated `HMAC-SHA256`.
    """
    clean_share = str(share_k or "").strip()
    clean_secret = str(secret_s or "").strip()
    if not clean_share and not clean_secret:
        raise ValueError("Missing both ephemeral key share and repository secret.")
    combined = f"{clean_share}|{clean_secret}".encode("utf-8")
    return hmac.new(b"OPAQUE_RELAY_KDF_DOMAIN_V1", combined, hashlib.sha256).digest()


def _XorStreamBlocks(input_bytes: bytes, master_key: bytes, nonce_bytes: bytes) -> bytes:
    """Applies `HMAC-SHA256` counter-mode keystream XOR over `input_bytes`."""
    out = bytearray(len(input_bytes))
    blk_idx = 0
    offset = 0
    total_len = len(input_bytes)
    while offset < total_len:
        ks = hmac.new(master_key, nonce_bytes + blk_idx.to_bytes(4, "big"), hashlib.sha256).digest()
        take = min(len(ks), total_len - offset)
        for i in range(take):
            out[offset + i] = input_bytes[offset + i] ^ ks[i]
        offset += take
        blk_idx += 1
    return bytes(out)


def EncryptOpaqueRelayEnvelope(
    payload_obj: Dict[str, Any],
    share_k: str,
    secret_s: str = "",
    nonce_bytes: Optional[bytes] = None,
) -> str:
    """
    Encrypts `payload_obj` into an authenticated Base64URL packet (`HMAC-SHA256-CTR + HMAC-SHA256 MAC`).
    Compatible across Python 3 and Google Apps Script (`Utilities.computeHmacSha256Signature`).
    """
    if not isinstance(payload_obj, dict):
        raise ValueError("payload_obj must be a dictionary.")
    master_key = DeriveOpaqueMasterKey(share_k, secret_s)
    pt_bytes = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if nonce_bytes is not None:
        if len(nonce_bytes) != 16:
            raise ValueError("Custom nonce_bytes must be exactly 16 bytes.")
        eff_nonce = nonce_bytes
    else:
        eff_nonce = os.urandom(16)
    ct_bytes = _XorStreamBlocks(pt_bytes, master_key, eff_nonce)
    sig_hex = hmac.new(master_key, eff_nonce + ct_bytes, hashlib.sha256).hexdigest()
    envelope_json = json.dumps(
        {
            "v": OPAQUE_PROTOCOL_VERSION,
            "n": base64.b64encode(eff_nonce).decode("ascii"),
            "c": base64.b64encode(ct_bytes).decode("ascii"),
            "s": sig_hex,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(envelope_json).rstrip(b"=").decode("ascii")


def DecryptOpaqueRelayEnvelope(
    packet_text: str,
    share_k: str,
    secret_s: str = "",
    max_clock_skew_sec: float = DEFAULT_ENVELOPE_TTL_SEC,
    enforce_ttl: bool = True,
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Authenticates and decrypts an opaque relay packet in constant time (`hmac.compare_digest`),
    enforcing strict 16-byte nonce validation and `math.isfinite` replay protection (`iat` / `ttl`)
    so `NaN` or `Inf` timestamps can never bypass expiration checks (`[AUDIT-06]`).
    """
    raw_str = str(packet_text or "").strip()
    if not raw_str:
        raise ValueError("Empty opaque relay packet.")
    if raw_str.startswith("{"):
        env = json.loads(raw_str)
    else:
        padded = raw_str + ("=" * ((4 - len(raw_str) % 4) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        env = json.loads(decoded)

    if not isinstance(env, dict) or "n" not in env or "c" not in env or "s" not in env:
        raise ValueError("Malformed opaque envelope structure.")

    nonce_bytes = base64.b64decode(str(env["n"]))
    if len(nonce_bytes) != 16:
        raise ValueError(f"Invalid nonce length: expected 16 bytes, got {len(nonce_bytes)}.")
    ct_bytes = base64.b64decode(str(env["c"]))
    provided_sig = str(env.get("s") or "").strip()
    if len(provided_sig) != 64:
        raise ValueError("Invalid MAC signature length.")

    master_key = DeriveOpaqueMasterKey(share_k, secret_s)
    expected_sig = hmac.new(master_key, nonce_bytes + ct_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("Opaque relay packet authentication failed (MAC mismatch).")

    pt_bytes = _XorStreamBlocks(ct_bytes, master_key, nonce_bytes)
    payload = json.loads(pt_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Decrypted opaque payload is not a JSON object.")

    if enforce_ttl:
        cur_time = float(now_ts if now_ts is not None else time.time())
        try:
            iat = float(payload.get("iat"))
            ttl = float(payload.get("ttl") if payload.get("ttl") is not None else max_clock_skew_sec)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid non-numeric iat or ttl in opaque payload.") from exc
        if (
            not math.isfinite(cur_time)
            or not math.isfinite(iat)
            or not math.isfinite(ttl)
            or not math.isfinite(max_clock_skew_sec)
            or iat <= 0.0
            or ttl <= 0.0
            or max_clock_skew_sec <= 0.0
        ):
            raise ValueError("Non-finite or non-positive iat/ttl rejected by replay guard.")
        effective_window = min(max(ttl, 1.0), max(max_clock_skew_sec, 1.0))
        if abs(cur_time - iat) > effective_window:
            raise ValueError("Opaque relay packet expired or outside replay window.")

    return payload


def SanitizeAndIngestOpaqueEnvironment(target_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Extracts opaque bootstrap variables from `target_env` (defaulting to `os.environ`)
    or from the runner's `$GITHUB_EVENT_PATH` JSON file (immediately scrubbing `client_payload`
    from disk so neither `##[group] env:` nor runner temp files retain packet data, `[AUDIT-11]`),
    and immediately purges all sensitive keys from `target_env`.
    """
    env_ref = target_env if target_env is not None else os.environ
    packet = str(env_ref.get("OPAQUE_PACKET") or "").strip()
    share = str(env_ref.get("OPAQUE_SHARE") or "").strip()
    secret = str(env_ref.get("OPAQUE_SECRET") or "").strip()

    ev_path_str = str(env_ref.get("GITHUB_EVENT_PATH") or "").strip()
    if ev_path_str:
        ev_path = Path(ev_path_str)
        if ev_path.is_file():
            try:
                ev_obj = json.loads(ev_path.read_text(encoding="utf-8"))
                if isinstance(ev_obj, dict):
                    cp = ev_obj.get("client_payload")
                    if isinstance(cp, dict):
                        if not packet:
                            packet = str(cp.get("p") or "").strip()
                        if not share:
                            share = str(cp.get("k") or "").strip()
                        ev_obj["client_payload"] = {}
                        ev_path.write_text(json.dumps(ev_obj), encoding="utf-8")
            except Exception:
                pass

    ingested = {
        "packet": packet,
        "share": share,
        "secret": secret,
    }
    for k in SENSITIVE_ENV_KEYS:
        env_ref.pop(k, None)
    return ingested


def VerifyHealthyRelayCadence(
    state_fp: str,
    ledger_path: Path,
    cooldown_sec: float = DEFAULT_COOLDOWN_SEC,
    max_hourly_runs: int = DEFAULT_MAX_HOURLY_RUNS,
    now_ts: Optional[float] = None,
    force_run: bool = False,
) -> Dict[str, Any]:
    """
    Enforces healthy, low-frequency GitHub Actions execution:
      1. Content-Hash Deduplication & Coalescing Cooldown: skips duplicate `state_fp` dispatches
         within `cooldown_sec` (default 45s) unless `force_run=True`.
      2. Sliding-Window Hourly Rate Cap: limits automated runs to `max_hourly_runs` (default 30/hour)
         to prevent accidental infinite trigger loops or quota abuse.
    """
    cur_ts = float(now_ts if now_ts is not None else time.time())
    if not math.isfinite(cur_ts) or cur_ts <= 0.0:
        cur_ts = time.time()
    clean_fp = str(state_fp or "").strip()
    ledger_data: Dict[str, Any] = {
        "last_state_fp": "",
        "last_run_ts": 0.0,
        "hourly_timestamps": [],
        "coalesced_skips": 0,
    }
    if ledger_path.is_file():
        try:
            loaded = json.loads(ledger_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                ledger_data.update(loaded)
        except Exception:
            pass

    recent_runs = []
    for ts in (ledger_data.get("hourly_timestamps") or []):
        try:
            f_ts = float(ts)
            if math.isfinite(f_ts) and 0.0 <= (cur_ts - f_ts) < 3600.0:
                recent_runs.append(f_ts)
        except (TypeError, ValueError):
            continue

    try:
        last_ts = float(ledger_data.get("last_run_ts") or 0.0)
        if not math.isfinite(last_ts):
            last_ts = 0.0
    except (TypeError, ValueError):
        last_ts = 0.0

    last_fp = str(ledger_data.get("last_state_fp") or "")
    elapsed = max(0.0, cur_ts - last_ts)

    if not force_run:
        if clean_fp and clean_fp == last_fp and last_ts > 0.0 and elapsed < max(cooldown_sec * 4.0, 180.0):
            ledger_data["hourly_timestamps"] = recent_runs
            ledger_data["coalesced_skips"] = int(ledger_data.get("coalesced_skips") or 0) + 1
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            ledger_path.write_text(json.dumps(ledger_data, indent=2), encoding="utf-8")
            return {
                "allowed": False,
                "reason": "duplicate_state_fingerprint_coalesced",
                "elapsed_sec": round(elapsed, 3),
                "recent_hourly_runs": len(recent_runs),
            }
        if last_ts > 0.0 and elapsed < cooldown_sec:
            ledger_data["hourly_timestamps"] = recent_runs
            ledger_data["coalesced_skips"] = int(ledger_data.get("coalesced_skips") or 0) + 1
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            ledger_path.write_text(json.dumps(ledger_data, indent=2), encoding="utf-8")
            return {
                "allowed": False,
                "reason": "cooldown_window_active",
                "elapsed_sec": round(elapsed, 3),
                "cooldown_sec": cooldown_sec,
                "recent_hourly_runs": len(recent_runs),
            }
        if len(recent_runs) >= max_hourly_runs:
            ledger_data["hourly_timestamps"] = recent_runs
            ledger_data["coalesced_skips"] = int(ledger_data.get("coalesced_skips") or 0) + 1
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            ledger_path.write_text(json.dumps(ledger_data, indent=2), encoding="utf-8")
            return {
                "allowed": False,
                "reason": "hourly_rate_cap_reached",
                "recent_hourly_runs": len(recent_runs),
                "max_hourly_runs": max_hourly_runs,
            }

    recent_runs.append(cur_ts)
    ledger_data["last_state_fp"] = clean_fp
    ledger_data["last_run_ts"] = cur_ts
    ledger_data["hourly_timestamps"] = recent_runs
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(ledger_data, indent=2), encoding="utf-8")
    return {
        "allowed": True,
        "reason": "healthy_cadence_verified",
        "recent_hourly_runs": len(recent_runs),
        "max_hourly_runs": max_hourly_runs,
    }


@contextlib.contextmanager
def CaptureAndSilenceStandardStreams(silence_os_fds: bool = False):
    """
    Redirects Python `sys.stdout` and `sys.stderr` into an isolated in-memory buffer,
    and optionally redirects OS-level file descriptors `1` and `2` to `/dev/null` (`[AUDIT-03]`)
    so even C extensions or raw FD writes can never leak a single byte to the runner console.
    """
    mem_buffer = io.StringIO()
    saved_fd1 = None
    saved_fd2 = None
    devnull_fd = None
    try:
        if silence_os_fds:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
                saved_fd1 = os.dup(1)
                saved_fd2 = os.dup(2)
                devnull_fd = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull_fd, 1)
                os.dup2(devnull_fd, 2)
            except Exception:
                pass
        with contextlib.redirect_stdout(mem_buffer), contextlib.redirect_stderr(mem_buffer):
            yield mem_buffer
    finally:
        if saved_fd1 is not None:
            try:
                os.dup2(saved_fd1, 1)
            except Exception:
                pass
            try:
                os.close(saved_fd1)
            except Exception:
                pass
        if saved_fd2 is not None:
            try:
                os.dup2(saved_fd2, 2)
            except Exception:
                pass
            try:
                os.close(saved_fd2)
            except Exception:
                pass
        if devnull_fd is not None:
            try:
                os.close(devnull_fd)
            except Exception:
                pass


def BuildEncryptedTelemetryRecord(
    execution_summary: Dict[str, Any],
    captured_log: str,
    share_k: str,
    secret_s: str = "",
) -> Dict[str, Any]:
    """
    Compresses and encrypts the full execution summary and captured logs into an authenticated
    ciphertext structure (`opaque_relay_telemetry.enc.json`) with zero plaintext fields.
    """
    inner_doc = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_summary": execution_summary,
        "captured_log_zlib_b64": base64.b64encode(
            zlib.compress(str(captured_log or "").encode("utf-8"), 9)
        ).decode("ascii"),
    }
    ciphertext_packet = EncryptOpaqueRelayEnvelope(inner_doc, share_k=share_k, secret_s=secret_s)
    return {
        "schema": "opaque_relay_telemetry_v1",
        "updated_at": round(time.time(), 3),
        "ciphertext": ciphertext_packet,
        "ciphertext_sha256": ComputeSha256Hex(ciphertext_packet.encode("ascii")),
    }


def DecryptTelemetryRecord(
    telemetry_doc: Dict[str, Any],
    share_k: str,
    secret_s: str = "",
) -> Dict[str, Any]:
    """
    Decrypts an `opaque_relay_telemetry.enc.json` document back into its plaintext summary and log.
    """
    ct_packet = str(telemetry_doc.get("ciphertext") or "").strip()
    inner = DecryptOpaqueRelayEnvelope(ct_packet, share_k=share_k, secret_s=secret_s, enforce_ttl=False)
    compressed_log = base64.b64decode(inner.get("captured_log_zlib_b64") or "")
    raw_log = zlib.decompress(compressed_log).decode("utf-8", errors="replace") if compressed_log else ""
    return {
        "timestamp_utc": inner.get("timestamp_utc", ""),
        "execution_summary": inner.get("execution_summary", {}),
        "captured_log": raw_log,
    }


def UploadEncryptedTelemetryToDrive(
    control_plane_folder_id: str,
    gdrive_token: str,
    telemetry_doc: Dict[str, Any],
    filename: str = "opaque_relay_telemetry.enc.json",
    api_base: str = "",
    upload_base: str = "",
) -> Dict[str, Any]:
    """
    Uploads the encrypted telemetry record (`opaque_relay_telemetry.enc.json`) to the private
    control-plane folder on Google Drive with SHA-256 idempotency.
    """
    if not control_plane_folder_id or not gdrive_token:
        return {"status": "skipped_missing_drive_target"}

    eff_api = (api_base or os.environ.get("GDRIVE_API_BASE_URL") or "https://www.googleapis.com/drive/v3").rstrip("/")
    eff_up = (upload_base or os.environ.get("GDRIVE_UPLOAD_BASE_URL") or "https://www.googleapis.com/upload/drive/v3").rstrip("/")
    hdrs_auth = {"Authorization": f"Bearer {gdrive_token}"}

    q_str = f"'{control_plane_folder_id}' in parents and name = '{filename}' and trashed = false"
    q_params = urllib.parse.urlencode(
        {
            "q": q_str,
            "fields": "files(id,name,description)",
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
        }
    )
    req_list = urllib.request.Request(f"{eff_api}/files?{q_params}", headers=hdrs_auth, method="GET")
    with urllib.request.urlopen(req_list, timeout=30) as resp:
        files = json.loads(resp.read().decode("utf-8")).get("files", [])

    payload_bytes = (json.dumps(telemetry_doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    desc = f"sha256={ComputeSha256Hex(payload_bytes)}"
    if files and files[0].get("description") == desc:
        return {"status": "skipped_unchanged", "file_id": files[0]["id"]}

    boundary = f"===============OpaqueTelemetryBoundary{int(time.time() * 1000)}=="
    meta: Dict[str, Any] = {"name": filename, "mimeType": "application/json", "description": desc}
    if not files:
        meta["parents"] = [control_plane_folder_id]

    body = b"".join(
        [
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{json.dumps(meta)}\r\n".encode("utf-8"),
            b"--" + boundary.encode("utf-8") + b"\r\nContent-Type: application/json\r\n\r\n",
            payload_bytes,
            f"\r\n--{boundary}--\r\n".encode("utf-8"),
        ]
    )
    up_hdrs = {
        "Authorization": f"Bearer {gdrive_token}",
        "Content-Type": f"multipart/related; boundary={boundary}",
    }
    if files:
        fid = files[0]["id"]
        url = f"{eff_up}/files/{fid}?uploadType=multipart&supportsAllDrives=true"
        req_up = urllib.request.Request(url, data=body, headers=up_hdrs, method="PATCH")
    else:
        url = f"{eff_up}/files?uploadType=multipart&supportsAllDrives=true"
        req_up = urllib.request.Request(url, data=body, headers=up_hdrs, method="POST")

    with urllib.request.urlopen(req_up, timeout=30) as resp_up:
        res_obj = json.loads(resp_up.read().decode("utf-8"))
    return {"status": "uploaded", "file_id": res_obj.get("id", "")}


def _CreateSecureRamDirectory(prefix: str = "opaque_rt_") -> Path:
    """Creates a `0o700` ephemeral directory in `/dev/shm` (RAM) when available, else system temp."""
    shm_root = Path("/dev/shm")
    base_dir = str(shm_root) if (shm_root.is_dir() and os.access(str(shm_root), os.W_OK)) else None
    tmp_path = Path(tempfile.mkdtemp(prefix=prefix, dir=base_dir))
    os.chmod(tmp_path, 0o700)
    return tmp_path


def _FetchPrivateScriptBytes(envelope: Dict[str, Any], rel_script_path: str) -> bytes:
    """
    Fetches an authorized script from the private control repository via GitHub REST API
    (or from the private Google Drive control plane folder as fallback) strictly in memory.
    """
    inline_scripts = envelope.get("inline_scripts_b64")
    if isinstance(inline_scripts, dict) and rel_script_path in inline_scripts:
        return zlib.decompress(base64.b64decode(inline_scripts[rel_script_path]))

    gh_token = str(envelope.get("gh_token") or "").strip()
    gh_owner = str(envelope.get("gh_owner") or "").strip()
    control_repo = str(envelope.get("control_repo") or "").strip()
    control_branch = str(envelope.get("control_branch") or "main").strip()
    gh_api = str(envelope.get("github_api_base") or os.environ.get("GITHUB_API_BASE_URL") or "https://api.github.com").rstrip("/")

    if gh_token and gh_owner and control_repo:
        url = f"{gh_api}/repos/{gh_owner}/{control_repo}/contents/{rel_script_path.lstrip('/')}?ref={control_branch}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "OpaqueRelayRuntime/1.0",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                obj = json.loads(resp.read().decode("utf-8"))
                b64_content = str(obj.get("content") or "").replace("\n", "").replace("\r", "").strip()
                if b64_content:
                    return base64.b64decode(b64_content)
        except Exception:
            pass

    gdrive_token = str(envelope.get("gdrive_token") or "").strip()
    cp_folder_id = str(envelope.get("control_plane_folder_id") or "").strip()
    drive_api = str(envelope.get("gdrive_api_base") or os.environ.get("GDRIVE_API_BASE_URL") or "https://www.googleapis.com/drive/v3").rstrip("/")
    if gdrive_token and cp_folder_id:
        script_name = Path(rel_script_path).name
        q_str = f"'{cp_folder_id}' in parents and name = '{script_name}' and trashed = false"
        q_params = urllib.parse.urlencode(
            {
                "q": q_str,
                "fields": "files(id,name)",
                "supportsAllDrives": "true",
                "includeItemsFromAllDrives": "true",
            }
        )
        req_f = urllib.request.Request(
            f"{drive_api}/files?{q_params}",
            headers={"Authorization": f"Bearer {gdrive_token}"},
            method="GET",
        )
        with urllib.request.urlopen(req_f, timeout=30) as resp_f:
            files = json.loads(resp_f.read().decode("utf-8")).get("files", [])
        if files:
            fid = files[0]["id"]
            req_dl = urllib.request.Request(
                f"{drive_api}/files/{fid}?alt=media&supportsAllDrives=true",
                headers={"Authorization": f"Bearer {gdrive_token}"},
                method="GET",
            )
            with urllib.request.urlopen(req_dl, timeout=60) as resp_dl:
                return resp_dl.read()

    raise RuntimeError("Unable to hydrate authorized bridge payload from private control plane.")


def FetchAndExecutePrivateBridgeInMemory(
    envelope: Dict[str, Any],
    cadence_ledger_path: Optional[Path] = None,
    silence_os_fds: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """
    Executes the full private control-plane synchronization inside an isolated `0o700` RAM directory
    with all standard streams captured in memory and zero console leakage.
    """
    with CaptureAndSilenceStandardStreams(silence_os_fds=silence_os_fds) as log_buf:
        ram_dir = _CreateSecureRamDirectory()
        try:
            ledger_file = cadence_ledger_path or (ram_dir / "cadence_ledger.json")
            cadence_res = VerifyHealthyRelayCadence(
                state_fp=str(envelope.get("state_fp") or ""),
                ledger_path=ledger_file,
                cooldown_sec=float(envelope.get("cooldown_sec") or DEFAULT_COOLDOWN_SEC),
                max_hourly_runs=int(envelope.get("max_hourly_runs") or DEFAULT_MAX_HOURLY_RUNS),
                force_run=bool(envelope.get("force_run", False)),
            )
            if not cadence_res["allowed"]:
                return (
                    {
                        "status": "skipped_by_cadence_guard",
                        "cadence": cadence_res,
                    },
                    log_buf.getvalue(),
                )

            scripts_dir = ram_dir / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            entry_rel = str(envelope.get("entry_script") or "scripts/github_actions_drive_bridge.py")
            companion_rels: List[str] = list(
                envelope.get("companion_scripts") or ["scripts/partner_stream_worker.py"]
            )

            entry_bytes = _FetchPrivateScriptBytes(envelope, entry_rel)
            entry_path = ram_dir / entry_rel
            entry_path.parent.mkdir(parents=True, exist_ok=True)
            entry_path.write_bytes(entry_bytes)

            for comp_rel in companion_rels:
                try:
                    c_bytes = _FetchPrivateScriptBytes(envelope, comp_rel)
                    c_path = ram_dir / comp_rel
                    c_path.parent.mkdir(parents=True, exist_ok=True)
                    c_path.write_bytes(c_bytes)
                except Exception:
                    pass

            cp_folder_id = str(envelope.get("control_plane_folder_id") or "").strip()
            cli_args = list(
                envelope.get("bridge_args")
                or [
                    "--sync-all-registered",
                    "--sync-control-plane-self",
                    "--control-plane-folder-id",
                    cp_folder_id,
                    "--clean-loose-files",
                ]
            )

            child_env = os.environ.copy()
            for k in SENSITIVE_ENV_KEYS:
                child_env.pop(k, None)
            child_env["PYTHONDONTWRITEBYTECODE"] = "1"
            child_env["OPAQUE_SILENT_RUNNER"] = "1"
            if envelope.get("gh_token"):
                child_env["GH_MASTER_TOKEN"] = str(envelope["gh_token"])
            if envelope.get("gdrive_token"):
                child_env["GDRIVE_ACCESS_TOKEN"] = str(envelope["gdrive_token"])
            if envelope.get("gdrive_credentials_json"):
                child_env["GDRIVE_CREDENTIALS_JSON"] = str(envelope["gdrive_credentials_json"])
            if envelope.get("github_api_base"):
                child_env["GITHUB_API_BASE_URL"] = str(envelope["github_api_base"])
            if envelope.get("gdrive_api_base"):
                child_env["GDRIVE_API_BASE_URL"] = str(envelope["gdrive_api_base"])
            if envelope.get("gdrive_upload_base"):
                child_env["GDRIVE_UPLOAD_BASE_URL"] = str(envelope["gdrive_upload_base"])

            proc = subprocess.run(
                [sys.executable, "-B", str(entry_path)] + cli_args,
                cwd=str(ram_dir),
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.stdout:
                log_buf.write(proc.stdout)
            if proc.stderr:
                log_buf.write("\n[STDERR]\n" + proc.stderr)

            summary: Dict[str, Any] = {
                "status": "completed" if proc.returncode == 0 else "nonzero_exit",
                "returncode": proc.returncode,
                "cadence": cadence_res,
            }
            try:
                parsed_out = json.loads(proc.stdout.strip())
                if isinstance(parsed_out, dict):
                    summary["bridge_report_keys"] = sorted(parsed_out.keys())
            except Exception:
                pass
            return summary, log_buf.getvalue()
        except Exception:
            log_buf.write("\n[INTERNAL_EXCEPTION]\n" + traceback.format_exc())
            return {"status": "internal_error", "returncode": 1}, log_buf.getvalue()
        finally:
            shutil.rmtree(ram_dir, ignore_errors=True)


def RunOpaqueRelayCli(argv: Optional[List[str]] = None) -> int:
    """
    Main CLI entrypoint for `.github/workflows/opaque_pulse.yml` and local encrypted telemetry decoding.
    Guarantees zero private output on stdout/stderr during relay pulse execution.
    """
    try:
        parser = argparse.ArgumentParser(description="OpaqueRelayRuntime: Zero-Leakage Stateless Relay", add_help=False)
        parser.add_argument("--decrypt-telemetry-file", type=str, default="")
        parser.add_argument("--share-key", type=str, default="")
        parser.add_argument("--secret-key", type=str, default="")
        args, _ = parser.parse_known_args(argv)
    except Exception:
        return 0

    if args.decrypt_telemetry_file:
        doc = json.loads(Path(args.decrypt_telemetry_file).read_text(encoding="utf-8"))
        dec = DecryptTelemetryRecord(doc, share_k=args.share_key, secret_s=args.secret_key)
        sys.stdout.write(json.dumps(dec, indent=2, ensure_ascii=False) + "\n")
        return 0

    ingested = SanitizeAndIngestOpaqueEnvironment()
    if not ingested["packet"] or (not ingested["share"] and not ingested["secret"]):
        return 0

    try:
        envelope = DecryptOpaqueRelayEnvelope(
            packet_text=ingested["packet"],
            share_k=ingested["share"],
            secret_s=ingested["secret"],
            enforce_ttl=True,
        )
    except Exception:
        return 0

    summary, captured_log = FetchAndExecutePrivateBridgeInMemory(envelope, silence_os_fds=True)
    try:
        telem_key = str(envelope.get("telemetry_key") or ingested["share"])
        telem_doc = BuildEncryptedTelemetryRecord(
            execution_summary=summary,
            captured_log=captured_log,
            share_k=telem_key,
            secret_s=ingested["secret"],
        )
        UploadEncryptedTelemetryToDrive(
            control_plane_folder_id=str(envelope.get("control_plane_folder_id") or ""),
            gdrive_token=str(envelope.get("gdrive_token") or ""),
            telemetry_doc=telem_doc,
            api_base=str(envelope.get("gdrive_api_base") or ""),
            upload_base=str(envelope.get("gdrive_upload_base") or ""),
        )
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(RunOpaqueRelayCli())
