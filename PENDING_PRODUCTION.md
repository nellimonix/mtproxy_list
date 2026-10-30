# Pending production

## MTPL-20261030-JSON-FALLBACK

- Description: add an independent JSON fallback with response and record freshness validation, schema validation, and cached proxy merging.
- Repository: https://github.com/nellimonix/mtproxy_list
- Code commit: fd010e5eceef9d8e055e0f3162e9551eb406b5cb
- Dependencies: none.
- Validation: 123 tests passed on Linux; live read-only collection returned 500 records and selected 50 unique proxies; encryption round-trip passed.
- Approved: 2026-10-30, result and production scope approved with "да" in [this chat](codex://threads/01a12f54-90e0-7dc1-9c92-89f84a29cb56), message 01a18a2b-0750-74a3-a484-341ed792521f.
- Approved release scope: deploy only this code commit, synchronize code and release records with GitHub, restart the collector, and verify publication.
