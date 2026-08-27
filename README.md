# AbsoluteJS secure-transfer adapters

Interchangeable storage adapters for
[`@absolutejs/secure-transfer`](https://github.com/absolutejs/secure-transfer).

| Package                             | Backend                                             | Atomic create-only primitive        |
| ----------------------------------- | --------------------------------------------------- | ----------------------------------- |
| `@absolutejs/secure-transfer-local` | Local filesystem                                    | same-filesystem hard link           |
| `@absolutejs/secure-transfer-s3`    | AWS S3, Cloudflare R2, MinIO, and compatible stores | `PutObject` with `If-None-Match: *` |

Both packages implement bounded, repeatable expiry sweeps for ciphertext left by
crashed uploads. They deliberately do not emulate conditional creation with a
`HEAD` followed by `PUT`; that sequence has a time-of-check/time-of-use race.

The S3 behavior follows AWS's
[conditional-write guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).
Cloudflare's current
[R2 S3 compatibility table](https://developers.cloudflare.com/r2/api/s3/api/)
lists conditional `PutObject` operations, including `If-None-Match`, as supported.

## Security

Storage sees opaque transfer IDs, record positions, sizes, and expiry times. It
does not receive decryption capabilities or attachment metadata. Treat storage
credentials as infrastructure secrets and restrict them to the configured prefix.

## License

Apache-2.0
