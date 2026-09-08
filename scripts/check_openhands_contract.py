#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

UPSTREAM_REPOSITORY = "OpenHands/OpenHands"
DEFAULT_COMMIT = "ea7a85c27628a6abad4d5738527e5044b34b91ff"
ACTION_EVENT_PATH = "src/types/agent-server/core/events/action-event.ts"
ACTION_TYPES_PATH = "src/types/agent-server/core/base/action.ts"

ACTION_EVENT_MARKERS = (
    "action: T;",
    "tool_name: string;",
    "tool_call_id: ToolCallID;",
)

REVIEWED_ACTION_KIND_MARKERS = (
    'ActionBase<"MCPToolAction">',
    'ActionBase<"ExecuteBashAction">',
    'ActionBase<"TerminalAction">',
    'ActionBase<"FileEditorAction">',
    'ActionBase<"StrReplaceEditorAction">',
    'ActionBase<"PlanningFileEditorAction">',
    'ActionBase<"BrowserNavigateAction">',
    'ActionBase<"BrowserClickAction">',
    'ActionBase<"BrowserTypeAction">',
    'ActionBase<"TaskAction">',
)

LAUNCH_CHILD_MARKER = "LAUNCH_CHILD_CONVERSATION_ACTION_KIND"
FILE_COMMAND_MARKER = '"view" | "create" | "str_replace" | "insert" | "undo_edit"'


def raw_url(commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{UPSTREAM_REPOSITORY}/{commit}/{path}"


def fetch_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain",
            "User-Agent": "ClaimSieve-OpenHands-contract-probe/1",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def check_markers(name: str, content: str, markers: tuple[str, ...]) -> dict[str, Any]:
    missing = [marker for marker in markers if marker not in content]
    return {
        "name": name,
        "status": "PASS" if not missing else "FAIL",
        "missing_markers": missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check the pinned OpenHands proposal-event contract used by the "
            "ClaimSieve proposal-only adapter. This is a structural drift probe, "
            "not proof of runtime safety."
        )
    )
    parser.add_argument("--commit", default=DEFAULT_COMMIT)
    parser.add_argument(
        "--output",
        default="openhands-contract-baseline.json",
        help="JSON report path",
    )
    args = parser.parse_args()

    paths = (ACTION_EVENT_PATH, ACTION_TYPES_PATH)
    urls = {path: raw_url(args.commit, path) for path in paths}
    report: dict[str, Any] = {
        "schema_version": "claimsieve.openhands_contract_probe.v1",
        "upstream_repository": UPSTREAM_REPOSITORY,
        "commit": args.commit,
        "checked_paths": list(paths),
        "checked_urls": urls,
        "checks": [],
        "status": "FAIL",
        "limitations": [
            "Structural source compatibility only; this does not prove OpenHands runtime safety.",
            "The probe does not authorize execution and does not validate ClaimSieve permits.",
            "Unknown or newly introduced action kinds remain fail-closed in the adapter until reviewed.",
        ],
    }

    try:
        action_event = fetch_text(urls[ACTION_EVENT_PATH])
        action_types = fetch_text(urls[ACTION_TYPES_PATH])
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, OSError) as exc:
        report["error"] = f"upstream fetch failed: {type(exc).__name__}: {exc}"
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(report["error"], file=sys.stderr)
        return 1

    report["checks"].append(
        check_markers("ActionEvent boundary fields", action_event, ACTION_EVENT_MARKERS)
    )
    report["checks"].append(
        check_markers(
            "Reviewed consequential action kinds",
            action_types,
            REVIEWED_ACTION_KIND_MARKERS,
        )
    )
    report["checks"].append(
        check_markers(
            "Launch-child action remains present",
            action_types,
            (LAUNCH_CHILD_MARKER,),
        )
    )
    report["checks"].append(
        check_markers(
            "File-editor command contract",
            action_types,
            (FILE_COMMAND_MARKER,),
        )
    )

    report["status"] = (
        "PASS"
        if all(check["status"] == "PASS" for check in report["checks"])
        else "FAIL"
    )
    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(
        f"OpenHands contract probe: {report['status']} "
        f"({UPSTREAM_REPOSITORY}@{args.commit})"
    )
    for check in report["checks"]:
        print(f"- {check['status']}: {check['name']}")
        for marker in check["missing_markers"]:
            print(f"  missing: {marker}")

    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
