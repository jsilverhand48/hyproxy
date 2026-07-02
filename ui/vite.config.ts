import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build is served BY the admin FastAPI app (same origin as /api/v1), so the
// app is served from the site root. In dev, proxy /api to the admin API so the
// SPA stays same-origin with it and no CORS is needed on the admin surface.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    // Hashed asset filenames keep a strict, cache-friendly CSP (script-src 'self').
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8400",
        changeOrigin: false,
      },
    },
  },
});
