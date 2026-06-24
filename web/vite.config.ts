import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// The built SPA is emitted into the Go HTTP adapter's `dist` folder so it gets
// embedded into the single binary via //go:embed. During development, /api is
// proxied to the Go server running on :8080.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "../internal/adapter/http/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
