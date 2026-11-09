#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TestOpaqueRelayGovernance: Verification Suite for Node 1 (`N-01-OpaqueRelayGovernance`)
=======================================================================================
Verifies:
  1. Single-source `RULES.md` governance (`[UNI-RULE-01]` ~ `[UNI-RULE-17]` + `[ZONE-2]` project rules)
     and pure `@RULES.md` context pointers in `AGENTS.md` and `.cursorrules`.
  2. Strict Zero-Private-Leakage Gate across the entire `opaque-relay-runner` repository:
     - Zero private repository identifiers, zero cloud drive resource IDs, zero credential tokens,
       and zero local drive/user paths (`C:\\`, `D:\\`, `E:\\`, `Users\\`).
  3. Opaque Workflow Confidentiality & Anti-Abuse Structure in `.github/workflows/opaque_pulse.yml`:
     - Event-driven only (`repository_dispatch` + `workflow_dispatch`, zero `schedule`/`cron`).
     - Serialized concurrency lock (`cancel-in-progress: false`).
     - Mandatory `set +x`, `::add-mask::` on all secret/packet inputs, and OS-level `>/dev/null 2>&1 || true`
       stream silencing so zero internal logs appear on the GitHub Actions web page.
"""
from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# SHA-256 digests of lowercase private identifiers that must NEVER appear anywhere in this public repository
FORBIDDEN_TOKEN_SHA256 = frozenset(
    {
        hashlib.sha256(b"lattray-moe-source").hexdigest(),
        hashlib.sha256(b"lattray_git.bundle").hexdigest(),
        hashlib.sha256(b"github-workspace-control").hexdigest(),
        hashlib.sha256(b"github-workspace-control_git.bundle").hexdigest(),
        hashlib.sha256(b"global_workspace_orchestrator.yml").hexdigest(),
        hashlib.sha256(b"ai_engineering_hub_partner_lease_key_7f9a2c8e").hexdigest(),
    }
)

DRIVE_ID_PATTERN = re.compile(r"\b1[A-Za-z0-9_-]{32}\b")
SECRET_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9_-]{16,}\b"),
)
LOCAL_PATH_PATTERNS = (
    re.compile(r"[CDE]:\\", re.IGNORECASE),
    re.compile(r"Users\\", re.IGNORECASE),
)


def VerifyUnifiedRulesAndContextPointers(repo_root: Path = REPO_ROOT) -> None:
    """Verifies `RULES.md` contains all 17 universal rules and `[ZONE-2]` opaque relay rules."""
    rules_path = repo_root / "RULES.md"
    assert rules_path.is_file(), "RULES.md must exist at repository root."
    rules_txt = rules_path.read_text(encoding="utf-8")
    for idx in range(1, 18):
        tag = f"[UNI-RULE-{idx:02d}]"
        assert tag in rules_txt, f"Missing {tag} in RULES.md"
    for p_idx in range(1, 5):
        ptag = f"[PROJ-RULE-{p_idx:02d}]"
        assert ptag in rules_txt, f"Missing {ptag} in RULES.md [ZONE-2]"

    for ptr_name in ("AGENTS.md", ".cursorrules"):
        ptr_path = repo_root / ptr_name
        assert ptr_path.is_file(), f"Missing pointer file: {ptr_name}"
        ptr_txt = ptr_path.read_text(encoding="utf-8")
        assert "@RULES.md" in ptr_txt, f"{ptr_name} must reference @RULES.md"
        assert "[UNI-RULE-01]" not in ptr_txt and "[PROJ-RULE-01]" not in ptr_txt, (
            f"{ptr_name} must not duplicate concrete rules outside RULES.md"
        )


def VerifyZeroPrivateLeakageInPublicRepo(repo_root: Path = REPO_ROOT) -> None:
    """
    Scans every file in the public repository to ensure zero private repository names,
    zero Google Drive 33-char resource IDs, zero tokens, and zero local paths are present.
    """
    token_splitter = re.compile(r"[A-Za-z0-9_.-]{6,}")
    scanned_count = 0
    for file_path in sorted(repo_root.rglob("*")):
        if not file_path.is_file():
            continue
        rel_parts = file_path.relative_to(repo_root).parts
        if ".git" in rel_parts or "__pycache__" in rel_parts:
            continue
        if file_path.resolve() == Path(__file__).resolve():
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        scanned_count += 1

        for match in token_splitter.findall(text):
            digest = hashlib.sha256(match.lower().encode("utf-8")).hexdigest()
            assert digest not in FORBIDDEN_TOKEN_SHA256, (
                f"Private identifier leaked in {file_path.relative_to(repo_root)}: token SHA256={digest[:12]}"
            )

        drive_matches = DRIVE_ID_PATTERN.findall(text)
        assert not drive_matches, (
            f"Cloud folder/file ID pattern leaked in {file_path.relative_to(repo_root)}: {drive_matches}"
        )

        for sec_re in SECRET_PATTERNS:
            assert not sec_re.search(text), f"Credential token leaked in {file_path.relative_to(repo_root)}"

        for path_re in LOCAL_PATH_PATTERNS:
            assert not path_re.search(text), f"Local path pattern leaked in {file_path.relative_to(repo_root)}"

    assert scanned_count >= 5, f"Expected at least 5 repository files scanned, got {scanned_count}"


def VerifyOpaqueWorkflowConfidentiality(repo_root: Path = REPO_ROOT) -> None:
    """Verifies `.github/workflows/opaque_pulse.yml` enforces strict masking, zero cron, and console silencing."""
    wf_path = repo_root / ".github" / "workflows" / "opaque_pulse.yml"
    assert wf_path.is_file(), "Missing .github/workflows/opaque_pulse.yml"
    wf_txt = wf_path.read_text(encoding="utf-8")

    assert "schedule:" not in wf_txt and "cron:" not in wf_txt, "Workflow must never use cron polling."
    assert "push:" not in wf_txt, "Workflow must not self-trigger on push."
    assert "repository_dispatch:" in wf_txt and "workflow_dispatch:" in wf_txt
    assert "cancel-in-progress: false" in wf_txt, "Workflow must enforce serialized non-canceling concurrency."
    assert "set +x" in wf_txt, "Workflow must disable shell command echoing via set +x."
    assert "client_payload" not in wf_txt, "Workflow YAML must NEVER place client_payload in env: (prevents ##[group] header echo)!"
    assert "::add-mask::${OPAQUE_SECRET}" in wf_txt
    assert ">/dev/null 2>&1 || true" in wf_txt, "Workflow must silence all stdout/stderr at the OS descriptor level."
    assert "[OPAQUE-RELAY] status=completed" in wf_txt


class TestOpaqueRelayGovernanceSuite(unittest.TestCase):
    def test_opaque_relay_governance_and_zero_leakage(self) -> None:
        VerifyUnifiedRulesAndContextPointers()
        VerifyZeroPrivateLeakageInPublicRepo()
        VerifyOpaqueWorkflowConfidentiality()


if __name__ == "__main__":
    unittest.main()
