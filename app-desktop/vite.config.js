import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  server: { port: 48218, strictPort: true },
  plugins: [
    react({
      babel: {
        // We use the plugin directly inside the react plugin for better coordination
        plugins: [
          ["babel-plugin-react-compiler", { target: "19" }]
        ],
      },
    }),
  ],
  // This ensures Electron/Node built-ins don't crash Vite
  optimizeDeps: {
    exclude: ['electron'],
  },
})