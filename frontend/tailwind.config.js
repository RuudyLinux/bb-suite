/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:        '#06080e',
          surface:   '#0c101b',
          card:      'rgba(12, 16, 27, 0.75)',
          elevated:  '#131a2b',
          border:    'rgba(255, 255, 255, 0.07)',
          highlight: 'rgba(255, 255, 255, 0.12)',
        },
        matrix: {
          50:  '#e6ffe6',
          100: '#ccffcc',
          200: '#99ff99',
          300: '#66ff66',
          400: '#00ff88',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#064e3b',
          900: '#022c22',
          950: '#011c15',
        },
        neon: {
          emerald: '#00ff88',
          cyan:    '#00f0ff',
          blue:    '#3b82f6',
          purple:  '#a855f7',
          amber:   '#f59e0b',
          rose:    '#f43f5e',
        },
        hack: {
          bg:     '#06080e',
          card:   '#0c101b',
          border: 'rgba(16, 185, 129, 0.2)',
          dim:    '#022c22',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      animation: {
        'blink':       'blink 1s step-end infinite',
        'glitch':      'glitch 4s infinite',
        'scan':        'scan 8s linear infinite',
        'pulse-glow':  'pulse-glow 2.5s ease-in-out infinite',
        'pulse-radar': 'pulse-radar 3s ease-out infinite',
        'fade-in':     'fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'slide-up':    'slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards',
      },
      keyframes: {
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        glitch: {
          '0%,90%,100%': { textShadow: 'none', transform: 'none' },
          '91%': { textShadow: '2px 0 #f43f5e, -2px 0 #00f0ff', transform: 'translateX(1px)' },
          '92%': { textShadow: '-2px 0 #f43f5e, 2px 0 #00f0ff', transform: 'translateX(-1px)' },
          '93%': { textShadow: '2px 0 #00f0ff, -2px 0 #f43f5e', transform: 'translateX(0)' },
        },
        scan: {
          '0%':   { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '0 100vh' },
        },
        'pulse-glow': {
          '0%,100%': { boxShadow: '0 0 8px rgba(0, 255, 136, 0.25)' },
          '50%':     { boxShadow: '0 0 20px rgba(0, 255, 136, 0.5), 0 0 35px rgba(0, 255, 136, 0.2)' },
        },
        'pulse-radar': {
          '0%':   { transform: 'scale(0.95)', opacity: '0.8' },
          '100%': { transform: 'scale(1.8)', opacity: '0' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        'matrix':    '0 0 15px rgba(0, 255, 136, 0.35)',
        'matrix-sm': '0 0 8px rgba(0, 255, 136, 0.2)',
        'cyan':      '0 0 15px rgba(0, 240, 255, 0.35)',
        'crit':      '0 0 15px rgba(244, 63, 94, 0.4)',
        'glass':     '0 8px 32px 0 rgba(0, 0, 0, 0.45)',
        'glow-box':  '0 0 25px rgba(0, 255, 136, 0.15)',
      },
    },
  },
  plugins: [],
}
