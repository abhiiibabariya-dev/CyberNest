/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0d1117',
          surface: '#161b22',
          card: '#161b22',
          border: '#30363d',
          accent: '#00d4ff',
          'accent-hover': '#00b8e0',
          success: '#00ff88',
          warning: '#ffaa00',
          danger: '#ff4444',
          critical: '#ff2222',
          info: '#00d4ff',
          text: '#e6edf3',
          muted: '#8b949e',
          'neon-cyan': '#00d4ff',
          'neon-green': '#00ff88',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'neon-cyan': '0 0 5px rgba(0, 212, 255, 0.3), 0 0 20px rgba(0, 212, 255, 0.1)',
        'neon-green': '0 0 5px rgba(0, 255, 136, 0.3), 0 0 20px rgba(0, 255, 136, 0.1)',
        'neon-danger': '0 0 5px rgba(255, 68, 68, 0.3), 0 0 20px rgba(255, 68, 68, 0.1)',
        'card': '0 1px 3px rgba(0, 0, 0, 0.4)',
      },
      animation: {
        'pulse-neon': 'pulse-neon 2s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'pulse-critical': 'pulse-critical 1.5s ease-in-out infinite',
        'slide-in-right': 'slide-in-right 0.3s ease-out',
      },
      keyframes: {
        'pulse-neon': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
        'glow': {
          '0%': { boxShadow: '0 0 5px rgba(0, 212, 255, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 212, 255, 0.4)' },
        },
        'pulse-critical': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
        'slide-in-right': {
          '0%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms')({
      strategy: 'class',
    }),
  ],
};
