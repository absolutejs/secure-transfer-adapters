import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { localProtectedReceiptStore, localSecureTransferStore } from "../src";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { force: true, recursive: true });
});

const surface = async () => {
  const root = await mkdtemp(join(tmpdir(), "absolute-secure-transfer-"));
  roots.push(root);
  return { root, store: localSecureTransferStore({ root }) };
};

describe("local secure-transfer storage", () => {
  test("creates records atomically and never overwrites a collision", async () => {
    const { root, store } = await surface();
    expect(
      await store.putRecord({
        bytes: Uint8Array.of(1, 2, 3),
        expiresAt: 2_000,
        recordIndex: 0,
        transferId: "transfer-one",
      }),
    ).toBe("created");
    expect(
      await store.putRecord({
        bytes: Uint8Array.of(9),
        expiresAt: 3_000,
        recordIndex: 0,
        transferId: "transfer-one",
      }),
    ).toBe("exists");
    expect(
      await store.getRecord({ recordIndex: 0, transferId: "transfer-one" }),
    ).toEqual(Uint8Array.of(1, 2, 3));
    expect((await readdir(root)).join("\n")).not.toContain("transfer-one");
  });

  test("isolates opaque IDs and removes an entire transfer", async () => {
    const { store } = await surface();
    await expect(
      store.putRecord({
        bytes: Uint8Array.of(1),
        expiresAt: 2_000,
        recordIndex: -1,
        transferId: "../../escape",
      }),
    ).rejects.toThrow("recordIndex");
    await store.putRecord({
      bytes: Uint8Array.of(1),
      expiresAt: 2_000,
      recordIndex: 0,
      transferId: "../../still-contained",
    });
    await store.removeTransfer("../../still-contained");
    expect(
      await store.getRecord({
        recordIndex: 0,
        transferId: "../../still-contained",
      }),
    ).toBeUndefined();
  });

  test("runs bounded, repeatable orphan cleanup without deleting live records", async () => {
    const { root, store } = await surface();
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
    const [transferDirectory] = await readdir(root);
    expect(transferDirectory).toBeDefined();
    await writeFile(
      join(root, transferDirectory!, ".tmp-100-interrupted"),
      Uint8Array.of(1),
    );

    let removed = 0;
    let result;
    let cursor: string | undefined;
    do {
      result = await store.sweepExpired({
        ...(cursor === undefined ? {} : { cursor }),
        expiresAtOrBefore: 500,
        maximumRecords: 1,
      });
      removed += result.removedRecords;
      cursor = result.cursor;
    } while (result.truncated);

    expect(removed).toBe(3);
    expect(
      await store.getRecord({ recordIndex: 0, transferId: "live" }),
    ).toEqual(Uint8Array.of(7));
  });
});

describe("local protected receipt storage", () => {
  test("serializes leases and enforces compare-and-swap versions", async () => {
    const { root } = await surface();
    const store = localProtectedReceiptStore({ root });
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
    expect(acquired).toMatchObject({ status: "acquired", version: "0" });
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
    expect(updated).toEqual({ status: "updated", version: "1" });
    expect(
      await store.update({
        expiresAt: 2_000,
        leaseExpiresAt: 1_200,
        leaseId: "agent-a",
        now: 1_002,
        protectedBytes: Uint8Array.of(10),
        receiptId: "receipt-one",
        version: "0",
      }),
    ).toEqual({ status: "conflict" });
  });

  test("runs cursor-based expired receipt cleanup", async () => {
    const { root } = await surface();
    const store = localProtectedReceiptStore({ root });
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
