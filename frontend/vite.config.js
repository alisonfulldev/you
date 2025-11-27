import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env': '{}',
  },
  build: {
    outDir: '../public/react',
    lib: {
      entry: './src/main.jsx',
      name: 'UtubeApp',
      formats: ['iife'],
      fileName: () => 'utube-app.iife.js',
    },
    rollupOptions: { external: [] },
  },
})
