import { createHash } from "node:crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import {
  SecureTransferConfigurationError,
  SecureTransferProtocolError,
  type SecureTransferLifecycleStore,
} from "@absolutejs/secure-transfer";

export { s3ProtectedReceiptStore } from "./receipts";

export type S3SecureTransferStoreOptions = {
  readonly bucket: string;
  readonly client: Pick<S3Client, "send">;
  readonly id?: string;
  /** Retries for S3's transient 409 conditional-write conflict. Default 2. */
  readonly maximumConditionalRetries?: number;
  /** Key namespace. Defaults to `secure-transfer/`. */
  readonly prefix?: string;
};

const EXPIRY_METADATA = "absolutejs-expiry-ms";
const RECORD_SUFFIX = ".record";

const requireText = (value: string, name: string): void => {
  if (value.trim().length === 0)
    throw new SecureTransferConfigurationError(`${name} must not be empty.`);
};

const requireTransferId = (transferId: string): void => {
  const bytes = new TextEncoder().encode(transferId).length;
  if (bytes < 1 || bytes > 512)
    throw new SecureTransferProtocolError(
      "transferId must contain between 1 and 512 UTF-8 bytes.",
    );
};

const requireRecordIndex = (recordIndex: number): void => {
  if (!Number.isSafeInteger(recordIndex) || recordIndex < 0)
    throw new SecureTransferProtocolError(
      "recordIndex must be a non-negative safe integer.",
    );
};

const requirePositiveInteger = (value: number, name: string): void => {
  if (!Number.isSafeInteger(value) || value < 1)
    throw new SecureTransferProtocolError(
      `${name} must be a positive safe integer.`,
    );
};

const isStatus = (error: unknown, status: number): boolean =>
  typeof error === "object" &&
  error !== null &&
  "$metadata" in error &&
  typeof error.$metadata === "object" &&
  error.$metadata !== null &&
  "httpStatusCode" in error.$metadata &&
  error.$metadata.httpStatusCode === status;

const isPreconditionFailed = (error: unknown): boolean =>
  isStatus(error, 412) ||
  (error instanceof Error && error.name === "PreconditionFailed");

const isNotFound = (error: unknown): boolean =>
  isStatus(error, 404) ||
  (error instanceof Error &&
    (error.name === "NoSuchKey" || error.name === "NotFound"));

const normalizePrefix = (prefix: string): string => {
  const trimmed = prefix.replace(/^\/+|\/+$/gu, "");
  return trimmed.length === 0 ? "" : `${trimmed}/`;
};

const transferHash = (transferId: string): string => {
  requireTransferId(transferId);
  return createHash("sha256").update(transferId).digest("hex");
};

const transferPrefix = (prefix: string, transferId: string): string =>
  `${prefix}${transferHash(transferId)}/`;

const recordKey = (
  prefix: string,
  transferId: string,
  recordIndex: number,
): string => {
  requireRecordIndex(recordIndex);
  return `${transferPrefix(prefix, transferId)}${recordIndex
    .toString()
    .padStart(16, "0")}${RECORD_SUFFIX}`;
};

export const s3SecureTransferStore = (
  options: S3SecureTransferStoreOptions,
): SecureTransferLifecycleStore => {
  requireText(options.bucket, "bucket");
  const id = options.id ?? "secure-transfer.s3";
  requireText(id, "store id");
  const prefix = normalizePrefix(options.prefix ?? "secure-transfer/");
  const maximumConditionalRetries = options.maximumConditionalRetries ?? 2;
  if (
    !Number.isSafeInteger(maximumConditionalRetries) ||
    maximumConditionalRetries < 0 ||
    maximumConditionalRetries > 10
  )
    throw new SecureTransferConfigurationError(
      "maximumConditionalRetries must be an integer between 0 and 10.",
    );

  return Object.freeze({
    id,
    getRecord: async ({ recordIndex, transferId }) => {
      try {
        const output = await options.client.send(
          new GetObjectCommand({
            Bucket: options.bucket,
            Key: recordKey(prefix, transferId, recordIndex),
          }),
        );
        if (output.Body === undefined)
          throw new SecureTransferProtocolError(
            "S3 returned a secure-transfer record without a body.",
          );
        return new Uint8Array(await output.Body.transformToByteArray());
      } catch (error) {
        if (isNotFound(error)) return undefined;
        throw error;
      }
    },
    putRecord: async ({ bytes, expiresAt, recordIndex, transferId }) => {
      requirePositiveInteger(expiresAt, "expiresAt");
      if (bytes.length === 0)
        throw new SecureTransferProtocolError(
          "Ciphertext record must not be empty.",
        );
      for (let attempt = 0; ; attempt += 1) {
        try {
          await options.client.send(
            new PutObjectCommand({
              Body: bytes,
              Bucket: options.bucket,
              IfNoneMatch: "*",
              Key: recordKey(prefix, transferId, recordIndex),
              Metadata: { [EXPIRY_METADATA]: String(expiresAt) },
            }),
          );
          return "created" as const;
        } catch (error) {
          if (isPreconditionFailed(error)) return "exists" as const;
          if (isStatus(error, 409) && attempt < maximumConditionalRetries)
            continue;
          throw error;
        }
      }
    },
    removeTransfer: async (transferId) => {
      let cursor: string | undefined;
      do {
        const page = await options.client.send(
          new ListObjectsV2Command({
            Bucket: options.bucket,
            ...(cursor === undefined ? {} : { ContinuationToken: cursor }),
            Prefix: transferPrefix(prefix, transferId),
          }),
        );
        for (const object of page.Contents ?? [])
          if (object.Key !== undefined)
            await options.client.send(
              new DeleteObjectCommand({
                Bucket: options.bucket,
                Key: object.Key,
              }),
            );
        cursor = page.IsTruncated ? page.NextContinuationToken : undefined;
        if (page.IsTruncated && cursor === undefined)
          throw new SecureTransferProtocolError(
            "S3 returned a truncated listing without a continuation token.",
          );
      } while (cursor !== undefined);
    },
    sweepExpired: async ({ cursor, expiresAtOrBefore, maximumRecords }) => {
      requirePositiveInteger(expiresAtOrBefore, "expiresAtOrBefore");
      requirePositiveInteger(maximumRecords, "maximumRecords");
      const page = await options.client.send(
        new ListObjectsV2Command({
          Bucket: options.bucket,
          ...(cursor === undefined ? {} : { ContinuationToken: cursor }),
          MaxKeys: maximumRecords,
          Prefix: prefix,
        }),
      );
      let examinedRecords = 0;
      let removedRecords = 0;
      for (const object of page.Contents ?? []) {
        if (object.Key === undefined || !object.Key.endsWith(RECORD_SUFFIX))
          continue;
        examinedRecords += 1;
        try {
          const head = await options.client.send(
            new HeadObjectCommand({
              Bucket: options.bucket,
              Key: object.Key,
            }),
          );
          const expiryText = head.Metadata?.[EXPIRY_METADATA];
          const expiry = expiryText === undefined ? NaN : Number(expiryText);
          if (!Number.isSafeInteger(expiry) || expiry < 1)
            throw new SecureTransferProtocolError(
              `S3 record ${object.Key} is missing valid expiry metadata.`,
            );
          if (expiry <= expiresAtOrBefore) {
            await options.client.send(
              new DeleteObjectCommand({
                Bucket: options.bucket,
                Key: object.Key,
              }),
            );
            removedRecords += 1;
          }
        } catch (error) {
          if (!isNotFound(error)) throw error;
        }
      }
      const truncated = page.IsTruncated === true;
      if (truncated && page.NextContinuationToken === undefined)
        throw new SecureTransferProtocolError(
          "S3 returned a truncated listing without a continuation token.",
        );
      return {
        ...(truncated ? { cursor: page.NextContinuationToken } : {}),
        examinedRecords,
        removedRecords,
        truncated,
      };
    },
  });
};
