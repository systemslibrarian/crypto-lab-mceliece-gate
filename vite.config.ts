import { defineConfig } from "vitest/config";

export default defineConfig({
  base: "/crypto-lab-mceliece-gate/",
  // Pin the preview port. Without this, `vite preview` binds its default 4173 —
  // a port a dozen labs in this fleet used to share — so this lab could squat
  // on a sibling's harness even after its own scripts moved off 4173. It also
  // matches the PREVIEW_URL fallback in scripts/a11y-check.mjs.
  preview: { port: 4706, strictPort: true },
  test: {
    // Only run Vitest unit tests. The Playwright e2e specs (e2e/) must not be
    // collected by Vitest, or they throw "test() was not expected here".
    include: ["src/**/*.test.ts"]
  }
});
