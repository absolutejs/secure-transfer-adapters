import { expect, test } from "bun:test";
import { readdir } from "node:fs/promises";

test("public TypeScript uses type aliases", async () => {
  for (const file of await readdir(new URL("../src", import.meta.url))) {
    if (!file.endsWith(".ts")) continue;
    const source = await Bun.file(
      new URL(`../src/${file}`, import.meta.url),
    ).text();
    expect(source).not.toMatch(/\binterface\s+[A-Za-z_$]/u);
  }
});
