import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defaultClientConditions, defaultServerConditions, defineConfig } from 'vite';

export default defineConfig({
  // Consume workspace packages from TypeScript source (see packages/*/package.json "source").
  resolve: { conditions: ['source', ...defaultClientConditions] },
  ssr: { resolve: { conditions: ['source', ...defaultServerConditions] } },
  plugins: [
    tailwindcss(),
    sveltekit({
      compilerOptions: {
        runes: ({ filename }) =>
          filename.split(/[/\\]/).includes('node_modules') ? undefined : true,
      },
      // Static SPA: no server-side rendering, so decrypted content can never be
      // rendered server-side and note/drop pages have no crawlable preview.
      adapter: adapter({ fallback: 'index.html', strict: true }),
      // Deterministic version (default is a timestamp) so identical sources give
      // byte-identical builds and the published build hash can be reproduced.
      version: { name: process.env.BUILD_VERSION ?? 'dev' },
    }),
  ],
  build: {
    // No inlined data: URIs — keeps every asset a same-origin file covered by CSP.
    assetsInlineLimit: 0,
    // libsodium (WASM embedded) is ~540 kB; it is only loaded by pages that need crypto.
    chunkSizeWarningLimit: 1024,
  },
});
