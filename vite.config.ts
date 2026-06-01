import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [
      react(), 
      tailwindcss(),
      {
        name: 'api-server',
        configureServer(server) {
          server.middlewares.use(async (req, res, next) => {
            const urlPath = req.url?.split('?')[0] || '';
            if (urlPath === '/api/repos') {
              try {
                const { default: handler } = await server.ssrLoadModule('./api/repos.ts');
                await handler(req, res);
              } catch (err: any) {
                console.error('Error running local Vercel Function API repos handler in Vite:', err);
                res.statusCode = 500;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: err.message || 'Internal Vite API dev-server error.' }));
              }
            } else if (urlPath === '/api' || urlPath.startsWith('/api/')) {
              try {
                const { default: handler } = await server.ssrLoadModule('./api/index.ts');
                await handler(req, res);
              } catch (err: any) {
                console.error('Error running local Vercel Function API handler in Vite:', err);
                res.statusCode = 500;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: err.message || 'Internal Vite API dev-server error.' }));
              }
            } else {
              next();
            }
          });
        }
      }
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
