# `@absolutejs/secure-transfer-s3`

AWS SDK storage adapter for `@absolutejs/secure-transfer`. It also works with
S3-compatible services such as Cloudflare R2 when the SDK client is configured
with that service's endpoint and credentials.

```ts
import { S3Client } from "@aws-sdk/client-s3";
import {
  s3ProtectedReceiptStore,
  s3SecureTransferStore,
} from "@absolutejs/secure-transfer-s3";

const store = s3SecureTransferStore({
  bucket: "private-ciphertext",
  client: new S3Client({ region: "us-east-1" }),
  prefix: "secure-transfer/",
});
const receiptStore = s3ProtectedReceiptStore({
  bucket: "private-ciphertext",
  client: new S3Client({ region: "us-east-1" }),
  prefix: "secure-transfer/",
});
```

Writes use `If-None-Match: *`; a precondition failure becomes `"exists"` and is
never retried as an unconditional write. Transient `409` conflicts are retried
with the condition still attached, following AWS guidance. Configure bucket
lifecycle expiration as defense in depth, and run `sweepExpired()` with its
continuation cursor for a testable application-level cleanup path.

Protected receipts use ETags as compare-and-swap versions. Lease acquisition and
checkpoint updates use `If-Match`; creation uses `If-None-Match: *`. Completion
first installs a conditional tombstone so a stale resumer cannot revive state,
then removes it. Run `sweepExpiredReceipts()` for abandoned receipt state.

Cloud credentials and paid object storage are bring-your-own. Managed credentials
and scheduled lifecycle operations belong in AbsoluteJS PaaS.
