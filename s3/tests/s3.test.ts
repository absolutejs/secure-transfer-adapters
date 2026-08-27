import { describe, expect, test } from "bun:test";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { s3ProtectedReceiptStore, s3SecureTransferStore } from "../src";

type Stored = {
  readonly body: Uint8Array;
  readonly etag: string;
  readonly metadata: Record<string, string>;
};

const fakeS3 = () => {
  const objects = new Map<string, Stored>();
  const commands: unknown[] = [];
  let version = 0;
  const send = async (command: unknown): Promise<unknown> => {
    commands.push(command);
    if (command instanceof PutObjectCommand) {
      const key = command.input.Key!;
      const current = objects.get(key);
      if (command.input.IfNoneMatch === "*" && current !== undefined)
        throw Object.assign(new Error("collision"), {
          $metadata: { httpStatusCode: 412 },
          name: "PreconditionFailed",
        });
      if (
        command.input.IfMatch !== undefined &&
        command.input.IfMatch !== current?.etag
      )
        throw Object.assign(new Error("version conflict"), {
          $metadata: { httpStatusCode: 412 },
          name: "PreconditionFailed",
        });
      if (
        command.input.IfNoneMatch === undefined &&
        command.input.IfMatch === undefined
      )
        throw new Error("conditional creation or update was not required");
      version += 1;
      const etag = `\"etag-${version}\"`;
      objects.set(key, {
        body: new Uint8Array(command.input.Body as Uint8Array),
        etag,
        metadata: { ...(command.input.Metadata ?? {}) },
      });
      return { ETag: etag };
    }
    if (command instanceof GetObjectCommand) {
      const stored = objects.get(command.input.Key!);
      if (stored === undefined)
        throw Object.assign(new Error("missing"), {
          $metadata: { httpStatusCode: 404 },
          name: "NoSuchKey",
        });
      return {
        Body: { transformToByteArray: async () => stored.body.slice() },
        ETag: stored.etag,
        Metadata: stored.metadata,
      };
    }
    if (command instanceof HeadObjectCommand) {
      const stored = objects.get(command.input.Key!);
      if (stored === undefined)
        throw Object.assign(new Error("missing"), {
          $metadata: { httpStatusCode: 404 },
          name: "NotFound",
        });
      return { ETag: stored.etag, Metadata: stored.metadata };
    }
    if (command instanceof DeleteObjectCommand) {
      objects.delete(command.input.Key!);
      return {};
    }
    if (command instanceof ListObjectsV2Command) {
      const keys = [...objects.keys()]
        .filter((key) => key.startsWith(command.input.Prefix ?? ""))
        .sort();
      const token = command.input.ContinuationToken;
      const offset =
        token === undefined ? 0 : keys.findIndex((key) => key > token);
      const limit = command.input.MaxKeys ?? 1_000;
      const selected = offset < 0 ? [] : keys.slice(offset, offset + limit);
      const truncated = selected.length > 0 && selected.at(-1) !== keys.at(-1);
      return {
        Contents: selected.map((Key) => ({ Key })),
        IsTruncated: truncated,
        ...(truncated ? { NextContinuationToken: selected.at(-1) } : {}),
      };
    }
    throw new Error("unexpected command");
  };
  return {
    commands,
    objects,
    client: { send } as unknown as Pick<S3Client, "send">,
  };
};

describe("S3 secure-transfer storage", () => {
  test("uses a real conditional PutObject and never overwrites", async () => {
    const surface = fakeS3();
    const store = s3SecureTransferStore({
      bucket: "ciphertext",
      client: surface.client,
    });
    const input = {
      bytes: Uint8Array.of(1, 2, 3),
      expiresAt: 2_000,
      recordIndex: 0,
      transferId: "transfer-one",
    };
    expect(await store.putRecord(input)).toBe("created");
    expect(await store.putRecord({ ...input, bytes: Uint8Array.of(9) })).toBe(
      "exists",
    );
    expect(await store.getRecord(input)).toEqual(Uint8Array.of(1, 2, 3));
    const puts = surface.commands.filter(
      (command): command is PutObjectCommand =>
        command instanceof PutObjectCommand,
    );
    expect(puts.every((command) => command.input.IfNoneMatch === "*")).toBe(
      true,
    );
    expect(puts[0]?.input.Key).not.toContain("transfer-one");
  });

  test("retries a transient 409 without dropping the create condition", async () => {
    const surface = fakeS3();
    let conflicted = false;
    const client = {
      send: async (command: unknown) => {
        if (command instanceof PutObjectCommand && !conflicted) {
          conflicted = true;
          throw Object.assign(new Error("conditional conflict"), {
            $metadata: { httpStatusCode: 409 },
          });
        }
        return surface.client.send(command as never);
      },
    } as unknown as Pick<S3Client, "send">;
    const store = s3SecureTransferStore({ bucket: "ciphertext", client });
    expect(
      await store.putRecord({
        bytes: Uint8Array.of(1),
        expiresAt: 2_000,
        recordIndex: 0,
        transferId: "retry-me",
      }),
    ).toBe("created");
    expect(conflicted).toBe(true);
    const put = surface.commands.find(
      (command): command is PutObjectCommand =>
        command instanceof PutObjectCommand,
    );
    expect(put?.input.IfNoneMatch).toBe("*");
  });

  test("uses continuation cursors in repeatable cleanup drills", async () => {
    const surface = fakeS3();
    const store = s3SecureTransferStore({
      bucket: "ciphertext",
      client: surface.client,
      prefix: "private/",
    });
    for (const [transferId, expiresAt] of [
      ["expired-a", 100],
      ["expired-b", 200],
      ["live", 2_000],
    ] as const)
      await store.putRecord({
        bytes: Uint8Array.of(7),
        expiresAt,
        recordIndex: 0,
        transferId,
      });

    let cursor: string | undefined;
    let removed = 0;
    let result;
    do {
      result = await store.sweepExpired({
        ...(cursor === undefined ? {} : { cursor }),
        expiresAtOrBefore: 500,
        maximumRecords: 1,
      });
      cursor = result.cursor;
      removed += result.removedRecords;
    } while (result.truncated);

    expect(removed).toBe(2);
    expect(
      await store.getRecord({ recordIndex: 0, transferId: "live" }),
    ).toEqual(Uint8Array.of(7));
  });

  test("removes every paginated record for one transfer", async () => {
    const surface = fakeS3();
    const store = s3SecureTransferStore({
      bucket: "ciphertext",
      client: surface.client,
    });
    for (let recordIndex = 0; recordIndex < 3; recordIndex += 1)
      await store.putRecord({
        bytes: Uint8Array.of(recordIndex + 1),
        expiresAt: 2_000,
        recordIndex,
        transferId: "remove-me",
      });
    await store.putRecord({
      bytes: Uint8Array.of(9),
      expiresAt: 2_000,
      recordIndex: 0,
      transferId: "keep-me",
    });
    await store.removeTransfer("remove-me");
    expect(
      await store.getRecord({ recordIndex: 0, transferId: "remove-me" }),
    ).toBeUndefined();
    expect(
      await store.getRecord({ recordIndex: 0, transferId: "keep-me" }),
    ).toEqual(Uint8Array.of(9));
  });
});

describe("S3 protected receipt storage", () => {
  test("uses ETag compare-and-swap for leases and updates", async () => {
    const surface = fakeS3();
    const store = s3ProtectedReceiptStore({
      bucket: "ciphertext",
      client: surface.client,
    });
    expect(
      await store.create({
        expiresAt: 2_000,
        protectedBytes: Uint8Array.of(7, 8),
        receiptId: "receipt-one",
      }),
    ).toBe("created");
    const acquired = await store.acquire({
      leaseExpiresAt: 1_100,
      leaseId: "agent-a",
      now: 1_000,
      receiptId: "receipt-one",
    });
    expect(acquired).toMatchObject({ status: "acquired" });
    expect(
      await store.acquire({
        leaseExpiresAt: 1_100,
        leaseId: "agent-b",
        now: 1_000,
        receiptId: "receipt-one",
      }),
    ).toEqual({ status: "busy" });
    if (acquired.status !== "acquired") throw new Error("receipt not acquired");
    const updated = await store.update({
      expiresAt: 2_000,
      leaseExpiresAt: 1_200,
      leaseId: "agent-a",
      now: 1_001,
      protectedBytes: Uint8Array.of(9),
      receiptId: "receipt-one",
      version: acquired.version,
    });
    expect(updated.status).toBe("updated");
    expect(
      await store.update({
        expiresAt: 2_000,
        leaseExpiresAt: 1_200,
        leaseId: "agent-a",
        now: 1_002,
        protectedBytes: Uint8Array.of(10),
        receiptId: "receipt-one",
        version: acquired.version,
      }),
    ).toEqual({ status: "conflict" });
    const conditionalUpdates = surface.commands.filter(
      (command): command is PutObjectCommand =>
        command instanceof PutObjectCommand &&
        command.input.IfMatch !== undefined,
    );
    expect(conditionalUpdates.length).toBeGreaterThanOrEqual(2);
  });

  test("runs cursor-based expired receipt cleanup", async () => {
    const surface = fakeS3();
    const store = s3ProtectedReceiptStore({
      bucket: "ciphertext",
      client: surface.client,
    });
    for (const [receiptId, expiresAt] of [
      ["expired-a", 100],
      ["expired-b", 200],
      ["live", 2_000],
    ] as const)
      await store.create({
        expiresAt,
        protectedBytes: Uint8Array.of(1),
        receiptId,
      });
    let cursor: string | undefined;
    let removed = 0;
    let result;
    do {
      result = await store.sweepExpiredReceipts({
        ...(cursor === undefined ? {} : { cursor }),
        expiresAtOrBefore: 500,
        maximumReceipts: 1,
      });
      cursor = result.cursor;
      removed += result.removedReceipts;
    } while (result.truncated);
    expect(removed).toBe(2);
    expect(
      await store.acquire({
        leaseExpiresAt: 1_100,
        leaseId: "agent",
        now: 1_000,
        receiptId: "live",
      }),
    ).toMatchObject({ status: "acquired" });
  });
});
