import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  bucket?: string;
  id?: string;
  prefix?: string;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "platform-engineers"],
    intents: [
      "store encrypted transfer records in AWS S3 or Cloudflare R2",
      "enforce atomic create-only encrypted record writes",
      "run repeatable orphan ciphertext cleanup drills",
    ],
    keywords: [
      "secure transfer",
      "AWS S3",
      "Cloudflare R2",
      "conditional write",
    ],
    protocols: ["S3 PutObject If-None-Match"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Conditional-write S3 and R2 storage adapter with bounded expiry sweeps for AbsoluteJS secure transfer.",
    docsUrl:
      "https://github.com/absolutejs/secure-transfer-adapters/tree/master/s3",
    name: "@absolutejs/secure-transfer-s3",
    tagline: "Store encrypted records without overwrite races.",
  },
  settings: Type.Object(
    {
      bucket: Type.Optional(Type.String({ minLength: 1, title: "Bucket" })),
      id: Type.Optional(Type.String({ minLength: 1, title: "Store ID" })),
      prefix: Type.Optional(Type.String({ title: "Object prefix" })),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
