# MainStreet proposal-only OpenClaw bridge

MainStreet owns the owner experience, tenant setup, workflows, communications, documents, reminders, and operational controls. OpenClaw remains a replaceable planning and skill runtime. The bridge in this directory has one authority: submit a bounded proposal to ClaimSieve intake.

It deliberately does not contain a provider software development kit, provider credentials, permit signer, reservation client, shell, generic network client, browser automation, or direct execution method.

The included OpenClaw descriptor is an integration seam and has not been loaded into a live pinned OpenClaw runtime in this environment. Production acceptance requires the exact upstream package, an isolated runtime, a hash of installed skills, and an egress test proving the process can reach only the ClaimSieve intake identity.

Run:

```bash
npm test
npm run check
```
