import { defineConfig } from 'vite';

export default defineConfig({
  // Use relative base path so it can be deployed on GitHub Pages under any subfolder
  base: './',
  build: {
    outDir: '../dist', // output to a central dist folder at the workspace root
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    open: true,
  }
});
