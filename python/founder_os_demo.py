from __future__ import annotations

import json
import tempfile
from pathlib import Path

from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest


def main() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workflow = FounderOSReferenceWorkflow(
            Path(temp),
            allowed_repositories={"example/claimsieve-mainstreet"},
            provider_mode="timeout_after_commit",
        )
        request = GitHubIssueRequest(
            proposal_id="founder-proposal-001",
            trace_id="founder-trace-001",
            campaign_id="founder-campaign-001",
            session_id="founder-session-001",
            work_item_id="work-item-001",
            repository="example/claimsieve-mainstreet",
            title="Review Founder OS integration",
            body="Inspect the exact action binding and unknown-outcome behavior.",
            requested_at_seq=10,
        )
        prepared = workflow.prepare_issue(request)
        result = workflow.execute_issue(prepared, execute_seq=11, observe_seq=12)
        print(json.dumps({
            "proposal_id": prepared.proposal["proposal_id"],
            "permit_id": prepared.permit["permit_id"],
            "provider_status": result.execution["executor_receipt"]["provider_status"],
            "independent_outcome": result.observation["reconciliation"],
            "automatic_retry_allowed": result.execution["automatic_retry_allowed"],
            "ledger_errors": workflow.verify_ledgers(),
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
