# `@absolutejs/secure-transfer-local`

Local-filesystem `SecureTransferLifecycleStore` for development, tests, and
single-host deployments.

```ts
import {
  localProtectedReceiptStore,
  localSecureTransferStore,
} from "@absolutejs/secure-transfer-local";

const store = localSecureTransferStore({ root: "/srv/private/ciphertext" });
const receiptStore = localProtectedReceiptStore({
  root: "/srv/private/ciphertext",
});
```

Records are atomically installed with a same-filesystem hard link. Existing
records are never overwritten. Each record carries a private binary expiry
header so an interrupted write cannot leave ciphertext without cleanup data.

Run `sweepExpired()` on a schedule and repeat while `truncated` is true. The
adapter validates transfer IDs and never follows caller-controlled paths.
Expiry-stamped temporary writes are swept too, including partial files left by a
process crash before the atomic link.

The receipt store persists only bytes already protected by a
`SecureTransferReceiptProtector`. It uses cross-process lock directories, lease
expiry, version checks, and atomic rename. Run `sweepExpiredReceipts()` for
abandoned resumable-upload state.
