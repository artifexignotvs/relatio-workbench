import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

function redirectRoot(server) {
  server.middlewares.use((request, response, next) => {
    if (request.url === "/") {
      response.writeHead(302, { Location: "/workspace.html" });
      response.end();
      return;
    }
    next();
  });
}

const previewHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

export default defineConfig({
  plugins: [
    react(),
    {
      name: "workspace-start",
      configureServer: redirectRoot,
      configurePreviewServer: redirectRoot,
    },
  ],
  build: {
    outDir: "dist-workspace",
    emptyOutDir: true,
    rollupOptions: {
      input: fileURLToPath(new URL("./workspace.html", import.meta.url)),
    },
  },
  server: { host: "127.0.0.1", port: 5188, strictPort: true },
  preview: {
    host: "127.0.0.1",
    port: 5188,
    strictPort: true,
    headers: previewHeaders,
  },
});
