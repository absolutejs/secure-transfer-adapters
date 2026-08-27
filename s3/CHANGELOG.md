# Changelog

## 0.1.0

- Add opaque resumable-receipt persistence using ETag leases and conditional
  compare-and-swap updates.
- Add completion tombstones and bounded expiry drills for abandoned receipts.

## 0.0.1

- Add conditional `PutObject` storage for AWS S3 and Cloudflare R2.
- Add collision and transient conflict handling without unconditional writes.
- Add bounded, cursor-based cleanup sweeps.
