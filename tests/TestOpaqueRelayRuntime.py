#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TestOpaqueRelayRuntime: Verification Suite for Node 2 (`N-02-OpaqueRelayRuntime`)
=================================================================================
Verifies:
  1. Authenticated Ephemeral Envelope encryption/decryption (`EncryptOpaqueRelayEnvelope` <->
     `DecryptOpaqueRelayEnvelope`), constant-time MAC tamper rejection, and TTL replay protection.
  2. Environment ingestion and immediate sanitization (`SanitizeAndIngestOpaqueEnvironment`).
  3. Complete console silence (`CaptureAndSilenceStandardStreams`) and end-to-end in-memory bridge
     hydration and execution (`FetchAndExecutePrivateBridgeInMemory`).
  4. Healthy Low-Frequency Anti-Abuse Cadence Guard (`VerifyHealthyRelayCadence`):
     - Duplicate state fingerprint coalescing, 45s cooldown window, and 30/hour sliding-window rate cap.
  5. Encrypted Telemetry round-trip (`BuildEncryptedTelemetryRecord` <-> `DecryptTelemetryRecord`)
     and mock Drive upload (`UploadEncryptedTelemetryToDrive`).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import OpaqueRelayRuntime as rt  # noqa: E402


def VerifyAuthenticatedEnvelopeCryptoAndReplayGuard() -> None:
    """Tests stream cipher + HMAC tag round-trip, tamper rejection, and TTL window check."""
    now = time.time()
    sample_payload = {
        "v": 1,
        "iat": now,
        "ttl": 600,
        "gh_owner": "DemoOwner",
        "control_repo": "demo-private-vault",
        "control_plane_folder_id": "mock_folder_alpha",
        "gh_token": "tok_gh_sample_99",
        "gdrive_token": "tok_gd_sample_88",
        "state_fp": "fp_hash_001",
    }
    packet = rt.EncryptOpaqueRelayEnvelope(sample_payload, share_k="share_alpha_123", secret_s="sec_beta_456")
    assert "demo-private-vault" not in packet
    assert "tok_gh_sample_99" not in packet

    decrypted = rt.DecryptOpaqueRelayEnvelope(
        packet,
        share_k="share_alpha_123",
        secret_s="sec_beta_456",
        now_ts=now + 10.0,
    )
    assert decrypted["control_repo"] == "demo-private-vault"
    assert decrypted["gh_token"] == "tok_gh_sample_99"

    # Wrong key share must fail closed
    try:
        rt.DecryptOpaqueRelayEnvelope(packet, share_k="wrong_share", secret_s="sec_beta_456", now_ts=now + 10.0)
        raise AssertionError("Decryption with wrong key share must fail!")
    except ValueError:
        pass

    # Expired TTL replay must fail closed
    try:
        rt.DecryptOpaqueRelayEnvelope(
            packet,
            share_k="share_alpha_123",
            secret_s="sec_beta_456",
            max_clock_skew_sec=600.0,
            now_ts=now + 3600.0,
        )
        raise AssertionError("Expired replay envelope must be rejected!")
    except ValueError:
        pass


def VerifyHealthyCadenceAntiAbuseGuard() -> None:
    """Tests debounce cooldown, duplicate fingerprint coalescing, and hourly rate cap."""
    with tempfile.TemporaryDirectory(prefix="opaque_cadence_") as tmp_str:
        ledger = Path(tmp_str) / "cadence.json"
        t0 = 1_800_000_000.0

        # 1st run is allowed
        r1 = rt.VerifyHealthyRelayCadence("fp_A", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0)
        assert r1["allowed"] is True

        # Duplicate fingerprint within 180s is coalesced/skipped
        r2 = rt.VerifyHealthyRelayCadence("fp_A", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0 + 60.0)
        assert r2["allowed"] is False and r2["reason"] == "duplicate_state_fingerprint_coalesced"

        # Different fingerprint within 45s cooldown is throttled
        r3 = rt.VerifyHealthyRelayCadence("fp_B", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0 + 20.0)
        assert r3["allowed"] is False and r3["reason"] == "cooldown_window_active"

        # Different fingerprint after 50s is allowed (2nd run in hour)
        r4 = rt.VerifyHealthyRelayCadence("fp_B", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0 + 50.0)
        assert r4["allowed"] is True

        # 3rd run after another 50s is allowed
        r5 = rt.VerifyHealthyRelayCadence("fp_C", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0 + 105.0)
        assert r5["allowed"] is True

        # 4th run within the same hour exceeds max_hourly_runs=3 -> blocked!
        r6 = rt.VerifyHealthyRelayCadence("fp_D", ledger, cooldown_sec=45.0, max_hourly_runs=3, now_ts=t0 + 160.0)
        assert r6["allowed"] is False and r6["reason"] == "hourly_rate_cap_reached"


def VerifyInMemoryExecutionAndEncryptedTelemetryEndToEnd() -> None:
    """
    Tests end-to-end execution of `RunOpaqueRelayCli`:
      - Mock private GitHub contents endpoint + Mock private Drive endpoint
      - Confirms ZERO bytes are written to stdout/stderr during relay execution
      - Confirms encrypted telemetry (`opaque_relay_telemetry.enc.json`) is uploaded and decrypts cleanly
    """
    mock_bridge_code = (
        "import json, sys\n"
        "print(json.dumps({'status': 'bridge_ok', 'synced_count': 4}))\n"
        "sys.stderr.write('internal_private_diagnostic_line_do_not_leak\\n')\n"
    ).encode("utf-8")

    store: Dict[str, Dict[str, Any]] = {}

    class _MockRelayServer(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _send_json(self, obj: Dict[str, Any], code: int = 200) -> None:
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path.startswith("/repos/DemoOwner/demo-vault/contents/scripts/github_actions_drive_bridge.py"):
                self._send_json({"content": base64.b64encode(mock_bridge_code).decode("ascii")})
                return
            if parsed.path == "/drive/v3/files":
                files = [{"id": k, "name": v["name"], "description": v.get("description", "")} for k, v in store.items()]
                self._send_json({"files": files})
                return
            self._send_json({"error": "not_found"}, 404)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            ctype = self.headers.get("Content-Type", "")
            b_idx = ctype.find("boundary=")
            boundary = ctype[b_idx + len("boundary="):].strip().encode("utf-8")
            parts = [p for p in body.split(b"--" + boundary) if b"Content-Type:" in p]
            meta = json.loads(parts[0][parts[0].find(b"\r\n\r\n") + 4:].strip().decode("utf-8"))
            raw_p = parts[1][parts[1].find(b"\r\n\r\n") + 4:]
            if raw_p.endswith(b"\r\n"):
                raw_p = raw_p[:-2]
            store["f_telem_1"] = {
                "name": meta["name"],
                "description": meta.get("description", ""),
                "bytes": raw_p,
            }
            self._send_json({"id": "f_telem_1", "name": meta["name"]})

        def do_PATCH(self) -> None:
            self.do_POST()

    srv = HTTPServer(("127.0.0.1", 0), _MockRelayServer)
    port = srv.server_port
    t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
    t_srv.start()
    try:
        base_url = f"http://127.0.0.1:{port}"
        envelope = {
            "v": 1,
            "iat": time.time(),
            "ttl": 600,
            "gh_owner": "DemoOwner",
            "control_repo": "demo-vault",
            "control_branch": "main",
            "control_plane_folder_id": "cp_mock_99",
            "gh_token": "tok_gh_test",
            "gdrive_token": "tok_gd_test",
            "github_api_base": base_url,
            "gdrive_api_base": f"{base_url}/drive/v3",
            "gdrive_upload_base": f"{base_url}/upload/drive/v3",
            "state_fp": "fp_live_e2e_01",
            "companion_scripts": [],
        }
        share_k = "ephemeral_share_key_xyz"
        secret_s = "repo_secret_abc"
        packet = rt.EncryptOpaqueRelayEnvelope(envelope, share_k=share_k, secret_s=secret_s)

        os.environ["OPAQUE_PACKET"] = packet
        os.environ["OPAQUE_SHARE"] = share_k
        os.environ["OPAQUE_SECRET"] = secret_s

        with rt.CaptureAndSilenceStandardStreams() as console_check:
            rc = rt.RunOpaqueRelayCli([])

        assert rc == 0
        # Zero characters may be printed to stdout/stderr during relay pulse execution!
        assert console_check.getvalue() == "", f"Console leaked output: {console_check.getvalue()}"
        # Sensitive env vars must be purged from os.environ!
        assert "OPAQUE_PACKET" not in os.environ
        assert "OPAQUE_SHARE" not in os.environ
        assert "OPAQUE_SECRET" not in os.environ

        # Encrypted telemetry must be uploaded to mock Drive without any plaintext leakage
        assert "f_telem_1" in store
        raw_telem_str = store["f_telem_1"]["bytes"].decode("utf-8")
        assert "internal_private_diagnostic_line_do_not_leak" not in raw_telem_str
        assert "bridge_ok" not in raw_telem_str

        # Authorized control plane can decrypt the telemetry losslessly
        telem_doc = json.loads(raw_telem_str)
        dec_telem = rt.DecryptTelemetryRecord(telem_doc, share_k=share_k, secret_s=secret_s)
        assert dec_telem["execution_summary"]["status"] == "completed"
        assert "bridge_report_keys" in dec_telem["execution_summary"]
        assert "internal_private_diagnostic_line_do_not_leak" in dec_telem["captured_log"]

        # Verify CLI --decrypt-telemetry-file mode
        with tempfile.TemporaryDirectory(prefix="dec_cli_") as td:
            tf = Path(td) / "opaque_relay_telemetry.enc.json"
            tf.write_text(raw_telem_str, encoding="utf-8")
            with rt.CaptureAndSilenceStandardStreams() as dec_out:
                rc_dec = rt.RunOpaqueRelayCli(
                    ["--decrypt-telemetry-file", str(tf), "--share-key", share_k, "--secret-key", secret_s]
                )
            assert rc_dec == 0
            cli_dec_obj = json.loads(dec_out.getvalue())
            assert cli_dec_obj["execution_summary"]["status"] == "completed"
    finally:
        srv.shutdown()
        srv.server_close()


class TestOpaqueRelayRuntimeSuite(unittest.TestCase):
    def test_opaque_relay_runtime_end_to_end(self) -> None:
        VerifyAuthenticatedEnvelopeCryptoAndReplayGuard()
        VerifyHealthyCadenceAntiAbuseGuard()
        VerifyInMemoryExecutionAndEncryptedTelemetryEndToEnd()


if __name__ == "__main__":
    unittest.main()
