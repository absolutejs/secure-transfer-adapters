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
  type SecureTransferProtectedReceiptLifecycleStore,
} from "@absolutejs/secure-transfer";
import type { S3SecureTransferStoreOptions } from "./index";

const RECEIPT_SUFFIX = ".receipt";
const EXPIRY = "absolutejs-receipt-expiry-ms";
const LEASE_EXPIRY = "absolutejs-receipt-lease-expiry-ms";
const LEASE_ID = "absolutejs-receipt-lease-id";
const COMPLETED = "absolutejs-receipt-completed";

const positiveInteger = (value: number): boolean =>
  Number.isSafeInteger(value) && value > 0;

const statusOf = (error: unknown): number | undefined => {
  if (
    typeof error !== "object" ||
    error === null ||
    !("$metadata" in error) ||
    typeof error.$metadata !== "object" ||
    error.$metadata === null ||
    !("httpStatusCode" in error.$metadata)
  )
    return undefined;
  return error.$metadata.httpStatusCode as number | undefined;
};

const isNotFound = (error: unknown): boolean =>
  statusOf(error) === 404 ||
  (error instanceof Error &&
    (error.name === "NoSuchKey" || error.name === "NotFound"));

const isConflict = (error: unknown): boolean =>
  statusOf(error) === 409 ||
  statusOf(error) === 412 ||
  (error instanceof Error && error.name === "PreconditionFailed");

const normalizePrefix = (prefix: string): string => {
  const trimmed = prefix.replace(/^\/+|\/+$/gu, "");
  return trimmed.length === 0 ? "receipts/" : `${trimmed}/receipts/`;
};

const receiptKey = (prefix: string, receiptId: string): string => {
  const length = new TextEncoder().encode(receiptId).length;
  if (length < 1 || length > 512)
    throw new SecureTransferProtocolError(
      "receiptId must contain between 1 and 512 UTF-8 bytes.",
    );
  return `${prefix}${createHash("sha256")
    .update(receiptId)
    .digest("hex")}${RECEIPT_SUFFIX}`;
};

const encodeLeaseId = (leaseId: string): string =>
  Buffer.from(leaseId, "utf8").toString("base64url");

type ReceiptState = {
  readonly completed: boolean;
  readonly expiresAt: number;
  readonly leaseExpiresAt?: number;
  readonly leaseId?: string;
  readonly protectedBytes: Uint8Array;
  readonly version: string;
};

const metadataFor = (input: {
  readonly completed?: boolean;
  readonly expiresAt: number;
  readonly leaseExpiresAt?: number;
  readonly leaseId?: string;
}): Record<string, string> => ({
  [EXPIRY]: String(input.expiresAt),
  ...(input.completed ? { [COMPLETED]: "1" } : {}),
  ...(input.leaseExpiresAt === undefined
    ? {}
    : { [LEASE_EXPIRY]: String(input.leaseExpiresAt) }),
  ...(input.leaseId === undefined
    ? {}
    : { [LEASE_ID]: encodeLeaseId(input.leaseId) }),
});

export const s3ProtectedReceiptStore = (
  options: S3SecureTransferStoreOptions,
): SecureTransferProtectedReceiptLifecycleStore => {
  if (options.bucket.trim().length === 0)
    throw new SecureTransferConfigurationError("bucket must not be empty.");
  const id = options.id ?? "secure-transfer.receipts.s3";
  if (id.trim().length === 0)
    throw new SecureTransferConfigurationError("store id must not be empty.");
  const prefix = normalizePrefix(options.prefix ?? "secure-transfer/");
  const maximumRetries = options.maximumConditionalRetries ?? 2;
  if (
    !Number.isSafeInteger(maximumRetries) ||
    maximumRetries < 0 ||
    maximumRetries > 10
  )
    throw new SecureTransferConfigurationError(
      "maximumConditionalRetries must be an integer between 0 and 10.",
    );

  const getState = async (key: string): Promise<ReceiptState | undefined> => {
    try {
      const output = await options.client.send(
        new GetObjectCommand({ Bucket: options.bucket, Key: key }),
      );
      if (output.Body === undefined || output.ETag === undefined)
        throw new SecureTransferProtocolError(
          "S3 returned protected receipt state without a body or ETag.",
        );
      const expiresAt = Number(output.Metadata?.[EXPIRY]);
      const leaseExpiresAtText = output.Metadata?.[LEASE_EXPIRY];
      const leaseIdText = output.Metadata?.[LEASE_ID];
      const leaseExpiresAt =
        leaseExpiresAtText === undefined
          ? undefined
          : Number(leaseExpiresAtText);
      if (
        !positiveInteger(expiresAt) ||
        (leaseExpiresAt !== undefined && !positiveInteger(leaseExpiresAt)) ||
        (leaseExpiresAt === undefined) !== (leaseIdText === undefined)
      )
        throw new SecureTransferProtocolError(
          "S3 protected receipt metadata is invalid.",
        );
      const protectedBytes = new Uint8Array(
        await output.Body.transformToByteArray(),
      );
      if (protectedBytes.length === 0)
        throw new SecureTransferProtocolError(
          "S3 protected receipt body is empty.",
        );
      return {
        completed: output.Metadata?.[COMPLETED] === "1",
        expiresAt,
        ...(leaseExpiresAt === undefined ? {} : { leaseExpiresAt }),
        ...(leaseIdText === undefined
          ? {}
          : {
              leaseId: Buffer.from(leaseIdText, "base64url").toString("utf8"),
            }),
        protectedBytes,
        version: output.ETag,
      };
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  };

  const conditionalPut = async (input: {
    readonly bytes: Uint8Array;
    readonly expectedVersion: string;
    readonly key: string;
    readonly metadata: Record<string, string>;
  }): Promise<string | undefined> => {
    try {
      const output = await options.client.send(
        new PutObjectCommand({
          Body: input.bytes,
          Bucket: options.bucket,
          IfMatch: input.expectedVersion,
          Key: input.key,
          Metadata: input.metadata,
        }),
      );
      if (output.ETag === undefined)
        throw new SecureTransferProtocolError(
          "S3 conditional receipt update did not return an ETag.",
        );
      return output.ETag;
    } catch (error) {
      if (isConflict(error)) return undefined;
      throw error;
    }
  };

  return Object.freeze({
    id,
    acquire: async ({ leaseExpiresAt, leaseId, now, receiptId }) => {
      if (
        !positiveInteger(now) ||
        !positiveInteger(leaseExpiresAt) ||
        leaseExpiresAt <= now
      )
        throw new SecureTransferProtocolError(
          "Receipt lease timestamps are invalid.",
        );
      const key = receiptKey(prefix, receiptId);
      for (let attempt = 0; ; attempt += 1) {
        const state = await getState(key);
        if (state === undefined || state.completed || state.expiresAt <= now)
          return { status: "missing" } as const;
        if (
          state.leaseId !== undefined &&
          state.leaseId !== leaseId &&
          (state.leaseExpiresAt ?? 0) > now
        )
          return { status: "busy" } as const;
        const nextVersion = await conditionalPut({
          bytes: state.protectedBytes,
          expectedVersion: state.version,
          key,
          metadata: metadataFor({
            expiresAt: state.expiresAt,
            leaseExpiresAt: Math.min(leaseExpiresAt, state.expiresAt),
            leaseId,
          }),
        });
        if (nextVersion !== undefined)
          return {
            protectedBytes: state.protectedBytes,
            status: "acquired",
            version: nextVersion,
          } as const;
        if (attempt >= maximumRetries) return { status: "busy" } as const;
      }
    },
    create: async ({ expiresAt, protectedBytes, receiptId }) => {
      if (!positiveInteger(expiresAt) || protectedBytes.length === 0)
        throw new SecureTransferProtocolError(
          "Protected receipt input is invalid.",
        );
      try {
        await options.client.send(
          new PutObjectCommand({
            Body: protectedBytes,
            Bucket: options.bucket,
            IfNoneMatch: "*",
            Key: receiptKey(prefix, receiptId),
            Metadata: metadataFor({ expiresAt }),
          }),
        );
        return "created" as const;
      } catch (error) {
        if (
          statusOf(error) === 412 ||
          (error instanceof Error && error.name === "PreconditionFailed")
        )
          return "exists" as const;
        throw error;
      }
    },
    release: async ({ leaseId, now, receiptId, version }) => {
      const key = receiptKey(prefix, receiptId);
      const state = await getState(key);
      if (
        state === undefined ||
        state.version !== version ||
        state.leaseId !== leaseId ||
        (state.leaseExpiresAt ?? 0) <= now
      )
        return;
      await conditionalPut({
        bytes: state.protectedBytes,
        expectedVersion: version,
        key,
        metadata: metadataFor({ expiresAt: state.expiresAt }),
      });
    },
    remove: async ({ leaseId, now, receiptId, version }) => {
      const key = receiptKey(prefix, receiptId);
      const state = await getState(key);
      if (
        state === undefined ||
        state.version !== version ||
        state.leaseId !== leaseId ||
        (state.leaseExpiresAt ?? 0) <= now
      )
        return "conflict" as const;
      const tombstone = await conditionalPut({
        bytes: Uint8Array.of(1),
        expectedVersion: version,
        key,
        metadata: metadataFor({ completed: true, expiresAt: state.expiresAt }),
      });
      if (tombstone === undefined) return "conflict" as const;
      await options.client.send(
        new DeleteObjectCommand({ Bucket: options.bucket, Key: key }),
      );
      return "removed" as const;
    },
    update: async ({
      expiresAt,
      leaseExpiresAt,
      leaseId,
      now,
      protectedBytes,
      receiptId,
      version,
    }) => {
      if (protectedBytes.length === 0 || leaseExpiresAt <= now)
        throw new SecureTransferProtocolError(
          "Protected receipt update is invalid.",
        );
      const key = receiptKey(prefix, receiptId);
      const state = await getState(key);
      if (
        state === undefined ||
        state.completed ||
        state.version !== version ||
        state.expiresAt !== expiresAt ||
        state.expiresAt <= now ||
        state.leaseId !== leaseId ||
        (state.leaseExpiresAt ?? 0) <= now
      )
        return { status: "conflict" } as const;
      const nextVersion = await conditionalPut({
        bytes: protectedBytes,
        expectedVersion: version,
        key,
        metadata: metadataFor({
          expiresAt,
          leaseExpiresAt: Math.min(leaseExpiresAt, expiresAt),
          leaseId,
        }),
      });
      return nextVersion === undefined
        ? ({ status: "conflict" } as const)
        : ({ status: "updated", version: nextVersion } as const);
    },
    sweepExpiredReceipts: async ({
      cursor,
      expiresAtOrBefore,
      maximumReceipts,
    }) => {
      if (
        !positiveInteger(expiresAtOrBefore) ||
        !positiveInteger(maximumReceipts)
      )
        throw new SecureTransferProtocolError(
          "Receipt sweep limits are invalid.",
        );
      const page = await options.client.send(
        new ListObjectsV2Command({
          Bucket: options.bucket,
          ...(cursor === undefined ? {} : { ContinuationToken: cursor }),
          MaxKeys: maximumReceipts,
          Prefix: prefix,
        }),
      );
      let examinedReceipts = 0;
      let removedReceipts = 0;
      for (const object of page.Contents ?? []) {
        if (object.Key === undefined || !object.Key.endsWith(RECEIPT_SUFFIX))
          continue;
        examinedReceipts += 1;
        try {
          const head = await options.client.send(
            new HeadObjectCommand({ Bucket: options.bucket, Key: object.Key }),
          );
          const expiry = Number(head.Metadata?.[EXPIRY]);
          if (!positiveInteger(expiry))
            throw new SecureTransferProtocolError(
              `S3 receipt ${object.Key} is missing valid expiry metadata.`,
            );
          if (expiry <= expiresAtOrBefore) {
            await options.client.send(
              new DeleteObjectCommand({
                Bucket: options.bucket,
                Key: object.Key,
              }),
            );
            removedReceipts += 1;
          }
        } catch (error) {
          if (!isNotFound(error)) throw error;
        }
      }
      const truncated = page.IsTruncated === true;
      if (truncated && page.NextContinuationToken === undefined)
        throw new SecureTransferProtocolError(
          "S3 returned a truncated receipt listing without a continuation token.",
        );
      return {
        ...(truncated ? { cursor: page.NextContinuationToken } : {}),
        examinedReceipts,
        removedReceipts,
        truncated,
      };
    },
  });
};
