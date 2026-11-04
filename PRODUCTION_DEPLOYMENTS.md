# Production deployments

## MTPL-20261030-JSON-FALLBACK

- Result: verified production deployment; collector active and fresh encrypted proxy list published.
- Verified at: 2026-10-30T00:20:11.484198+00:00.
- Code commit: fd010e5eceef9d8e055e0f3162e9551eb406b5cb.
- Publication artifact: [73dab791913aaa22584c64893e60ff130d4bd912](https://github.com/nellimonix/mtproxy_list/commit/73dab791913aaa22584c64893e60ff130d4bd912).
- Runtime SHA-256: 552a7b4932c5582267ff49e40c2c7ec7255b97755f416cc7d6f8e0fd1f03eddd.
- Previous runtime SHA-256: e61676a545dcced07209bdf1ed1b6ec8352c114ab164c752bf723725fb409d3f.
- Validation: 123 Linux tests passed; 50 unique encrypted records published; GitHub matches the collector checkout.
- Newest source verification timestamp: 2026-10-30T00:04:08+00:00.
- Owner approved result and release scope with "да" in [this chat](codex://threads/01a12f54-90e0-7dc1-9c92-89f84a29cb56), message 01a18a2b-0750-74a3-a484-341ed792521f.
- Backup and machine-readable deployment manifest retained in the isolated deployment directory.

## MTPL-20261104-MULTISOURCE-100-MIGRATION

- Result: verified migration to the approved replacement host; collector active and enabled at boot with user lingering.
- Verified at: 2026-11-04T04:28:29.999065+00:00.
- Code commit: 353cedd66819014e68125d2dd814475edf034aee.
- Publication artifact: [d9d7b959fec76efb20db98fcc8d260cd6c078a84](https://github.com/nellimonix/mtproxy_list/commit/d9d7b959fec76efb20db98fcc8d260cd6c078a84).
- Runtime SHA-256: bab20e800aae33e0d14016ef5de522914dab604fcff5c8762edcf250f6fd504e.
- Sources module SHA-256: fe19af1e56ae94580c61eb0865ab28b392c2bbd904c306bc57cb478b77eaf3f2.
- Validation: 175 Linux tests passed; 100 unique records published with the existing encryption key; GitHub matches the publication checkout; consumer format compatibility and service unit verified.
- Runtime: pinned release, 1800-second collection interval, independent public-source requests, persisted discovery timestamps, and retry of unpublished Git commits.
- Source availability: six requested websites supplied records; the remaining public API returned an empty list and did not block collection.
- Approval and production queue are maintained only in the local registry.
