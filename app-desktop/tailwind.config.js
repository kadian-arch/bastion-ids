/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bastion: {
          dark: '#0b1120',
          card: '#0f172a',
          accent: '#06b6d4',
          danger: '#f43f5e',
          border: '#1e293b'
        }
      }
    },
  },
  plugins: [],
}