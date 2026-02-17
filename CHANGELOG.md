# Changelog

## v0.2.1 - 2026-02-17

- Hardened advisory feed ingestion by rejecting insecure `http://` remote references.
- Enforced explicit advisory feed schema (`aixv.advisory-feed/v1`) for sync operations.
- Added `record_id` safety validation (`^[A-Za-z0-9._-]{1,128}$`) to prevent path traversal footguns.
- Added tests for insecure feed rejection and unsafe record ID rejection.

