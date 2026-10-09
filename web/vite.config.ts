import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The console is served by the demo server at /ui. In development, API calls are proxied to it.
const backend = "http://127.0.0.1:8000";
const proxied = ["/v1", "/idp", "/oidc", "/sts", "/gw", "/demo", "/.well-known"];

export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(proxied.map((path) => [path, { target: backend, changeOrigin: true }])),
  },
  build: { outDir: "dist", chunkSizeWarningLimit: 900 },
});
