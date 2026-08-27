# Changelog

## 0.0.1

- Add conditional `PutObject` storage for AWS S3 and Cloudflare R2.
- Add collision and transient conflict handling without unconditional writes.
- Add bounded, cursor-based cleanup sweeps.
