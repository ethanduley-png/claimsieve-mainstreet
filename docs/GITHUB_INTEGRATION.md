# GitHub Integration

## Status

The restricted GitHub issue adapter is implemented and tested against a deterministic HTTP boundary. On 2026-08-02, an explicitly authorized canary created [issue #1](https://github.com/ethanduley-png/claimsieve-mainstreet/issues/1) exactly once. The immediate bounded read returned `OUTCOME_UNKNOWN`; a later read-only reconciliation matched the exact permitted action digest and returned `CONFIRMED_SUCCESS`. No write retry occurred, and both temporary canary tokens were revoked afterward. See `evidence/GITHUB_LIVE_CANARY_REPORT.json`.

The adapter supports only `POST /repos/{owner}/{repo}/issues` and read-only repository/issue endpoints on `https://api.github.com`. It does not expose a generic HTTP client.

## Security boundary

- MainStreet and OpenClaw still receive no GitHub credentials.
- The repository must exactly match the local allowlist, signed destination evidence, approved proposal, and permit.
- The writer and observer require different tokens.
- The writer performs one POST and never retries a transport-ambiguous write.
- A hidden ClaimSieve marker binds the permit, request, resource, fence, work item, and approved action metadata.
- The observer lists issues using its read-only token and reconstructs the externally visible action.
- Edits are classified as `DIVERGENT_EFFECT`; duplicate or malformed markers become conflicting evidence and `OUTCOME_UNKNOWN`.
- Creation is blocked if read-back access cannot be established first.

GitHub documents that a fine-grained token needs repository `Issues: write` permission to create an issue. Use a second token with `Issues: read` for observation. Limit each token to the exact repository. See [Create an issue](https://docs.github.com/en/rest/issues/issues#create-an-issue) and [fine-grained token permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).

## Configure secrets

Provide secrets through a process-level secret injector or terminal environment. Do not put tokens in JSON, command-line arguments, source control, logs, or the packaged archive.

Required variables:

```text
CLAIMSIEVE_GITHUB_READ_TOKEN
CLAIMSIEVE_GITHUB_WRITE_TOKEN
```

Live execution also requires this deliberate enable switch:

```text
CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE=1
```

The read and write values must be different. The `check` and `plan` commands create no external effect.

## Check repository access

From the project root on Windows:

```powershell
$env:PYTHONPATH = "python"
& "..\.venv-claimsieve-v034\Scripts\python.exe" python\github_integration.py check OWNER/REPOSITORY
```

The command returns bounded repository metadata and never prints a token.

## Prepare without sending

Copy `config/github-issue-request.example.json`, replace `OWNER/REPOSITORY`, and use unique proposal, trace, campaign, session, and work-item identifiers. Then run:

```powershell
$env:PYTHONPATH = "python"
& "..\.venv-claimsieve-v034\Scripts\python.exe" python\github_integration.py plan path\to\request.json
```

This evaluates the policy and produces proposal/action digests and a permit identifier in a temporary local state store. It does not contact GitHub.

## Create one governed issue

Live creation requires all three independent confirmations: the `execute` command, the enable environment variable, and an exact `--confirm-repository` value.

```powershell
$env:CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE = "1"
$env:PYTHONPATH = "python"
& "..\.venv-claimsieve-v034\Scripts\python.exe" python\github_integration.py execute path\to\request.json `
  --workspace .claimsieve-github `
  --confirm-repository OWNER/REPOSITORY `
  --execute-live-write
```

Do not automatically rerun this command after a timeout or crash. Inspect durable state and reconcile the issue marker with the read-only observer first.

## Reconcile an unknown outcome without writing

Use only the observer token. The idempotency key and expected action digest are emitted by `plan` and retained in the durable workspace:

```powershell
$env:PYTHONPATH = "python"
& "..\.venv-claimsieve-v034\Scripts\python.exe" python\github_integration.py observe OWNER/REPOSITORY `
  permit:IDEMPOTENCY_KEY `
  --expected-action-digest sha256:EXPECTED_ACTION_DIGEST
```

`observe` performs no write and always reports `automatic_retry_allowed: false`. Exact marker and action-digest agreement produces `CONFIRMED_SUCCESS`; absence remains `OUTCOME_UNKNOWN`, and conflicting provider evidence is reported rather than guessed.

## Live canary evidence

- Repository: `ethanduley-png/claimsieve-mainstreet`
- Provider resource: [issue #1](https://github.com/ethanduley-png/claimsieve-mainstreet/issues/1)
- Proposal: `founder-proposal-github-canary-20260802142713`
- Expected and observed digest: `sha256:d5d781e81f83f68f829a152315ad5f6588bb6612ad31f6572bbb91e64ce2b325`
- Initial outcome: `OUTCOME_UNKNOWN`
- Reconciled outcome: `CONFIRMED_SUCCESS`
- Write retry: none
- Temporary credentials: revoked

## Remaining production work

- Replace deterministic fixture signing keys with isolated production identities.
- Store tokens in a platform secret manager or GitHub App installation-token broker rather than ordinary process environment variables.
- Move the observer to a distinct process and credential boundary.
- Add webhook-assisted observation; bounded REST read-back remains the source of truth for this reference adapter.
- Move reconciled observations into a separately signed durable observer receipt; the current `observe` command prints a read-only reconciliation summary.
