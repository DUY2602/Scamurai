import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  preview: {
    allowedHosts: true,
    host: '0.0.0.0',
    port: Number(process.env.PORT || 4173),
  },
})
