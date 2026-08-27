import { createHash, randomUUID } from "node:crypto";
import {
  link,
  mkdir,
  readFile,
  readdir,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, join, relative, resolve } from "node:path";
import {
  SecureTransferConfigurationError,
  SecureTransferProtocolError,
  type SecureTransferLifecycleStore,
} from "@absolutejs/secure-transfer";

export { localProtectedReceiptStore } from "./receipts";
export type { LocalProtectedReceiptStoreOptions } from "./receipts";

export type LocalSecureTransferStoreOptions = {
  readonly id?: string;
  /** Private directory controlled by this process. */
  readonly root: string;
};

const MAGIC = new TextEncoder().encode("ABSST001");
const HEADER_BYTES = 16;
const RECORD_SUFFIX = ".record";

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

const requireExpiry = (expiresAt: number): void => {
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 1)
    throw new SecureTransferProtocolError(
      "expiresAt must be a positive safe integer.",
    );
};

const transferDirectory = (root: string, transferId: string): string => {
  requireTransferId(transferId);
  return join(root, createHash("sha256").update(transferId).digest("hex"));
};

const recordName = (recordIndex: number): string => {
  requireRecordIndex(recordIndex);
  return `${recordIndex.toString().padStart(16, "0")}${RECORD_SUFFIX}`;
};

const frameRecord = (bytes: Uint8Array, expiresAt: number): Uint8Array => {
  requireExpiry(expiresAt);
  if (bytes.length === 0)
    throw new SecureTransferProtocolError(
      "Ciphertext record must not be empty.",
    );
  const framed = new Uint8Array(HEADER_BYTES + bytes.length);
  framed.set(MAGIC);
  new DataView(framed.buffer).setBigUint64(8, BigInt(expiresAt));
  framed.set(bytes, HEADER_BYTES);
  return framed;
};

const parseRecord = (
  framed: Uint8Array,
): { readonly bytes: Uint8Array; readonly expiresAt: number } => {
  if (
    framed.length <= HEADER_BYTES ||
    !MAGIC.every((byte, index) => framed[index] === byte)
  )
    throw new SecureTransferProtocolError(
      "Stored secure-transfer record has an invalid framing header.",
    );
  const expiry = new DataView(
    framed.buffer,
    framed.byteOffset,
    framed.byteLength,
  ).getBigUint64(8);
  if (expiry > BigInt(Number.MAX_SAFE_INTEGER))
    throw new SecureTransferProtocolError(
      "Stored secure-transfer record has an invalid expiry.",
    );
  return {
    bytes: framed.slice(HEADER_BYTES),
    expiresAt: Number(expiry),
  };
};

const recordPaths = async function* (
  root: string,
  cursor?: string,
): AsyncGenerator<string> {
  let directories;
  try {
    directories = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  directories.sort((left, right) => left.name.localeCompare(right.name));
  for (const directory of directories) {
    if (!directory.isDirectory() || !/^[a-f0-9]{64}$/u.test(directory.name))
      continue;
    const directoryPath = join(root, directory.name);
    const entries = await readdir(directoryPath, { withFileTypes: true }).catch(
      (error: unknown) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
        throw error;
      },
    );
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (
        !entry.isFile() ||
        (!entry.name.endsWith(RECORD_SUFFIX) && !entry.name.startsWith(".tmp-"))
      )
        continue;
      const path = join(directoryPath, entry.name);
      if (cursor === undefined || relative(root, path) > cursor) yield path;
    }
  }
};

export const localSecureTransferStore = (
  options: LocalSecureTransferStoreOptions,
): SecureTransferLifecycleStore => {
  if (options.root.trim().length === 0)
    throw new SecureTransferConfigurationError("root must not be empty.");
  const root = resolve(options.root);
  const id = options.id ?? "secure-transfer.local";
  if (id.trim().length === 0)
    throw new SecureTransferConfigurationError("store id must not be empty.");

  return Object.freeze({
    id,
    getRecord: async ({ recordIndex, transferId }) => {
      const path = join(
        transferDirectory(root, transferId),
        recordName(recordIndex),
      );
      try {
        return parseRecord(new Uint8Array(await readFile(path))).bytes;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT")
          return undefined;
        throw error;
      }
    },
    putRecord: async ({ bytes, expiresAt, recordIndex, transferId }) => {
      const directory = transferDirectory(root, transferId);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const destination = join(directory, recordName(recordIndex));
      const temporary = join(directory, `.tmp-${expiresAt}-${randomUUID()}`);
      try {
        await writeFile(temporary, frameRecord(bytes, expiresAt), {
          flag: "wx",
          mode: 0o600,
        });
        try {
          await link(temporary, destination);
          return "created" as const;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "EEXIST")
            return "exists" as const;
          throw error;
        }
      } finally {
        await unlink(temporary).catch(() => undefined);
      }
    },
    removeTransfer: async (transferId) => {
      await rm(transferDirectory(root, transferId), {
        force: true,
        recursive: true,
      });
    },
    sweepExpired: async ({ cursor, expiresAtOrBefore, maximumRecords }) => {
      requireExpiry(expiresAtOrBefore);
      if (!Number.isSafeInteger(maximumRecords) || maximumRecords < 1)
        throw new SecureTransferProtocolError(
          "maximumRecords must be a positive safe integer.",
        );
      let examinedRecords = 0;
      let removedRecords = 0;
      let truncated = false;
      let nextCursor: string | undefined;
      for await (const path of recordPaths(root, cursor)) {
        if (examinedRecords === maximumRecords) {
          truncated = true;
          break;
        }
        let expiry: number;
        try {
          const temporaryMatch = /^\.tmp-(\d+)-/u.exec(basename(path));
          expiry =
            temporaryMatch === null
              ? parseRecord(new Uint8Array(await readFile(path))).expiresAt
              : Number(temporaryMatch[1]);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw error;
        }
        examinedRecords += 1;
        nextCursor = relative(root, path);
        if (!Number.isSafeInteger(expiry) || expiry < 1)
          throw new SecureTransferProtocolError(
            "Stored secure-transfer temporary record has an invalid expiry.",
          );
        if (expiry <= expiresAtOrBefore) {
          await unlink(path).catch((error: unknown) => {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          });
          removedRecords += 1;
        }
      }
      return {
        ...(truncated && nextCursor !== undefined
          ? { cursor: nextCursor }
          : {}),
        examinedRecords,
        removedRecords,
        truncated,
      };
    },
  });
};
