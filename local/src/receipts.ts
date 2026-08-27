import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  SecureTransferConfigurationError,
  SecureTransferProtocolError,
  type SecureTransferProtectedReceiptLifecycleStore,
} from "@absolutejs/secure-transfer";

export type LocalProtectedReceiptStoreOptions = {
  readonly id?: string;
  readonly lockRetryMs?: number;
  readonly lockTimeoutMs?: number;
  readonly maximumLockAttempts?: number;
  /** May share the local ciphertext adapter's private root. */
  readonly root: string;
};

type StoredReceipt = {
  readonly contract: 1;
  readonly expiresAt: number;
  readonly lease?: {
    readonly expiresAt: number;
    readonly id: string;
  };
  readonly protectedBytes: string;
  readonly version: number;
};

const RECEIPT_SUFFIX = ".receipt.json";

const positiveInteger = (value: number): boolean =>
  Number.isSafeInteger(value) && value > 0;

const requireReceiptId = (receiptId: string): void => {
  const length = new TextEncoder().encode(receiptId).length;
  if (length < 1 || length > 512)
    throw new SecureTransferProtocolError(
      "receiptId must contain between 1 and 512 UTF-8 bytes.",
    );
};

const hashReceiptId = (receiptId: string): string => {
  requireReceiptId(receiptId);
  return createHash("sha256").update(receiptId).digest("hex");
};

const encodeBytes = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");

const decodeBytes = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value))
    throw new SecureTransferProtocolError(
      "Stored protected receipt is not canonical base64url.",
    );
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  if (encodeBytes(bytes) !== value)
    throw new SecureTransferProtocolError(
      "Stored protected receipt is not canonical base64url.",
    );
  return bytes;
};

const parseState = (text: string): StoredReceipt => {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new SecureTransferProtocolError(
      "Stored protected receipt state is not valid JSON.",
    );
  }
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new SecureTransferProtocolError(
      "Stored protected receipt state is invalid.",
    );
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed = new Set([
    "contract",
    "expiresAt",
    "lease",
    "protectedBytes",
    "version",
  ]);
  const lease = record.lease;
  if (
    !keys.every((key) => allowed.has(key)) ||
    record.contract !== 1 ||
    !positiveInteger(Number(record.expiresAt)) ||
    typeof record.protectedBytes !== "string" ||
    !Number.isSafeInteger(record.version) ||
    Number(record.version) < 0 ||
    (lease !== undefined &&
      (typeof lease !== "object" ||
        lease === null ||
        Array.isArray(lease) ||
        Object.keys(lease).length !== 2 ||
        !Object.hasOwn(lease, "expiresAt") ||
        !Object.hasOwn(lease, "id") ||
        !positiveInteger(
          Number((lease as Record<string, unknown>).expiresAt),
        ) ||
        typeof (lease as Record<string, unknown>).id !== "string"))
  )
    throw new SecureTransferProtocolError(
      "Stored protected receipt state is invalid.",
    );
  decodeBytes(record.protectedBytes);
  return value as StoredReceipt;
};

const delay = (milliseconds: number): Promise<void> =>
  new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

export const localProtectedReceiptStore = (
  options: LocalProtectedReceiptStoreOptions,
): SecureTransferProtectedReceiptLifecycleStore => {
  if (options.root.trim().length === 0)
    throw new SecureTransferConfigurationError("root must not be empty.");
  const id = options.id ?? "secure-transfer.receipts.local";
  if (id.trim().length === 0)
    throw new SecureTransferConfigurationError("store id must not be empty.");
  const lockRetryMs = options.lockRetryMs ?? 5;
  const lockTimeoutMs = options.lockTimeoutMs ?? 30_000;
  const maximumLockAttempts = options.maximumLockAttempts ?? 100;
  if (
    !positiveInteger(lockRetryMs) ||
    !positiveInteger(lockTimeoutMs) ||
    !positiveInteger(maximumLockAttempts)
  )
    throw new SecureTransferConfigurationError(
      "Local receipt lock limits must be positive integers.",
    );
  const directory = join(resolve(options.root), ".receipts");

  const paths = (receiptId: string) => {
    const hash = hashReceiptId(receiptId);
    return {
      lock: join(directory, `${hash}.lock`),
      receipt: join(directory, `${hash}${RECEIPT_SUFFIX}`),
    };
  };

  const readState = async (
    path: string,
  ): Promise<StoredReceipt | undefined> => {
    try {
      return parseState(await readFile(path, "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  };

  const writeState = async (
    path: string,
    state: StoredReceipt,
  ): Promise<void> => {
    const temporary = `${path}.tmp-${randomUUID()}`;
    try {
      await writeFile(temporary, JSON.stringify(state), {
        flag: "wx",
        mode: 0o600,
      });
      await rename(temporary, path);
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  };

  const withLock = async <Value>(
    lockPath: string,
    action: () => Promise<Value>,
  ): Promise<Value> => {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    for (let attempt = 0; attempt < maximumLockAttempts; attempt += 1) {
      try {
        await mkdir(lockPath, { mode: 0o700 });
        try {
          return await action();
        } finally {
          await rm(lockPath, { force: true, recursive: true }).catch(
            () => undefined,
          );
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const lockStat = await stat(lockPath).catch(() => undefined);
        if (
          lockStat !== undefined &&
          Date.now() - lockStat.mtimeMs > lockTimeoutMs
        ) {
          await rm(lockPath, { force: true, recursive: true }).catch(
            () => undefined,
          );
          continue;
        }
        await delay(lockRetryMs);
      }
    }
    throw new SecureTransferProtocolError(
      "Timed out acquiring the local protected-receipt lock.",
    );
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
      const path = paths(receiptId);
      return withLock(path.lock, async () => {
        const state = await readState(path.receipt);
        if (state === undefined || state.expiresAt <= now) {
          if (state !== undefined) await rm(path.receipt, { force: true });
          return { status: "missing" } as const;
        }
        if (
          state.lease !== undefined &&
          state.lease.id !== leaseId &&
          state.lease.expiresAt > now
        )
          return { status: "busy" } as const;
        const next: StoredReceipt = {
          ...state,
          lease: {
            expiresAt: Math.min(leaseExpiresAt, state.expiresAt),
            id: leaseId,
          },
        };
        await writeState(path.receipt, next);
        return {
          protectedBytes: decodeBytes(next.protectedBytes),
          status: "acquired",
          version: String(next.version),
        } as const;
      });
    },
    create: async ({ expiresAt, protectedBytes, receiptId }) => {
      if (!positiveInteger(expiresAt) || protectedBytes.length === 0)
        throw new SecureTransferProtocolError(
          "Protected receipt input is invalid.",
        );
      const path = paths(receiptId);
      return withLock(path.lock, async () => {
        if ((await readState(path.receipt)) !== undefined)
          return "exists" as const;
        await writeState(path.receipt, {
          contract: 1,
          expiresAt,
          protectedBytes: encodeBytes(protectedBytes),
          version: 0,
        });
        return "created" as const;
      });
    },
    release: async ({ leaseId, now, receiptId, version }) => {
      const path = paths(receiptId);
      await withLock(path.lock, async () => {
        const state = await readState(path.receipt);
        if (
          state === undefined ||
          state.lease?.id !== leaseId ||
          state.lease.expiresAt <= now ||
          state.version !== Number(version)
        )
          return;
        const { lease: _lease, ...released } = state;
        await writeState(path.receipt, released);
      });
    },
    remove: async ({ leaseId, now, receiptId, version }) => {
      const path = paths(receiptId);
      return withLock(path.lock, async () => {
        const state = await readState(path.receipt);
        if (
          state === undefined ||
          state.lease?.id !== leaseId ||
          state.lease.expiresAt <= now ||
          state.version !== Number(version)
        )
          return "conflict" as const;
        await rm(path.receipt, { force: true });
        return "removed" as const;
      });
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
      const path = paths(receiptId);
      return withLock(path.lock, async () => {
        const state = await readState(path.receipt);
        if (
          state === undefined ||
          state.expiresAt !== expiresAt ||
          state.expiresAt <= now ||
          state.lease?.id !== leaseId ||
          state.lease.expiresAt <= now ||
          state.version !== Number(version)
        )
          return { status: "conflict" } as const;
        const next: StoredReceipt = {
          ...state,
          lease: {
            expiresAt: Math.min(leaseExpiresAt, state.expiresAt),
            id: leaseId,
          },
          protectedBytes: encodeBytes(protectedBytes),
          version: state.version + 1,
        };
        await writeState(path.receipt, next);
        return { status: "updated", version: String(next.version) } as const;
      });
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
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const names = (await readdir(directory))
        .filter(
          (name) =>
            name.endsWith(RECEIPT_SUFFIX) &&
            (cursor === undefined || name > cursor),
        )
        .sort();
      const selected = names.slice(0, maximumReceipts);
      let removedReceipts = 0;
      for (const name of selected) {
        const path = join(directory, name);
        const state = await readState(path);
        if (state !== undefined && state.expiresAt <= expiresAtOrBefore) {
          await rm(path, { force: true });
          removedReceipts += 1;
        }
      }
      const truncated = names.length > selected.length;
      return {
        ...(truncated && selected.length > 0
          ? { cursor: selected.at(-1) }
          : {}),
        examinedReceipts: selected.length,
        removedReceipts,
        truncated,
      };
    },
  });
};
