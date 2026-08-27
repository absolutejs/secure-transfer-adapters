import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{ id?: string; root?: string }>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams"],
    intents: [
      "store encrypted transfer records on a local filesystem",
      "run repeatable orphan ciphertext cleanup drills",
    ],
    keywords: [
      "secure transfer",
      "local filesystem",
      "atomic create",
      "expiry sweep",
    ],
    protocols: ["atomic hard-link record creation"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Atomic local-filesystem storage adapter with bounded expiry sweeps for AbsoluteJS secure transfer.",
    docsUrl:
      "https://github.com/absolutejs/secure-transfer-adapters/tree/master/local",
    name: "@absolutejs/secure-transfer-local",
    tagline: "Keep encrypted transfer records local and collision-safe.",
  },
  settings: Type.Object(
    {
      id: Type.Optional(Type.String({ minLength: 1, title: "Store ID" })),
      root: Type.Optional(
        Type.String({ minLength: 1, title: "Private storage directory" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
