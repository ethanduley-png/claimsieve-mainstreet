# Supply-chain evidence

The SLSA, in-toto, and CycloneDX files are templates or source inventories. They are not signed attestations. A release workflow must replace placeholders, include exact dependency and image digests, sign the statement with a protected release identity, publish the signature and verification material, and preserve raw build logs.

The package script creates a deterministic file manifest and ZIP timestamp. Deterministic packaging does not by itself prove who built the package or whether the builder was trustworthy.
