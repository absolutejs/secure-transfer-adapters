import { describe, expect, test } from "bun:test";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { s3SecureTransferStore } from "../src";

type Stored = {
  readonly body: Uint8Array;
  readonly metadata: Record<string, string>;
};

const fakeS3 = () => {
  const objects = new Map<string, Stored>();
  const commands: unknown[] = [];
  const send = async (command: unknown): Promise<unknown> => {
    commands.push(command);
    if (command instanceof PutObjectCommand) {
      const key = command.input.Key!;
      if (command.input.IfNoneMatch !== "*")
        throw new Error("conditional creation was not required");
      if (objects.has(key))
        throw Object.assign(new Error("collision"), {
          $metadata: { httpStatusCode: 412 },
          name: "PreconditionFailed",
        });
      objects.set(key, {
        body: new Uint8Array(command.input.Body as Uint8Array),
        metadata: { ...(command.input.Metadata ?? {}) },
      });
      return {};
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
      };
    }
    if (command instanceof HeadObjectCommand) {
      const stored = objects.get(command.input.Key!);
      if (stored === undefined)
        throw Object.assign(new Error("missing"), {
          $metadata: { httpStatusCode: 404 },
          name: "NotFound",
        });
      return { Metadata: stored.metadata };
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
