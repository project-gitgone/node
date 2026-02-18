import { test } from "@japa/runner";
import { gitgone } from "../src/index.js";

test.group("Parse Env", () => {
  test("should parse simple env strings", ({ assert }) => {
    const raw = "KEY=VALUE\nPORT=3333";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      KEY: "VALUE",
      PORT: "3333",
    });
  });

  test("should handle quotes", ({ assert }) => {
    const raw = "KEY=\"VALUE\"\nPORT='3333'";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      KEY: "VALUE",
      PORT: "3333",
    });
  });

  test("should ignore comments", ({ assert }) => {
    const raw = "# comment\nKEY=VALUE # another comment";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      KEY: "VALUE",
    });
  });

  test("should handle spaces around =", ({ assert }) => {
    const raw = "KEY  =   VALUE";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      KEY: "VALUE",
    });
  });

  test("should handle multiple variables", ({ assert }) => {
    const raw = "A=1\nB=2\nC=3";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      A: "1",
      B: "2",
      C: "3",
    });
  });

  test("should handle JWT_SECRET specifically", ({ assert }) => {
    const raw = "JWT_SECRET=super-secret-token";
    const parsed = (gitgone as any).parseEnv(raw);

    assert.deepEqual(parsed, {
      JWT_SECRET: "super-secret-token",
    });
  });
});
