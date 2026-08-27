import { expect, test } from "bun:test";

test("public TypeScript uses type aliases", async () => {
  const source = await Bun.file(
    new URL("../src/index.ts", import.meta.url),
  ).text();
  expect(source).not.toMatch(/\binterface\s+[A-Za-z_$]/u);
});
