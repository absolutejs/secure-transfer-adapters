# Changelog

## 0.1.0

- Add protected resumable-receipt persistence with cross-process leases,
  compare-and-swap versions, atomic state replacement, and stale-lock recovery.
- Add bounded expiry drills for abandoned receipts.

## 0.0.1

- Add atomic, create-only local record storage.
- Add opaque transfer paths and embedded expiry framing.
- Add bounded, cursor-based cleanup sweeps, including interrupted temporary files.
