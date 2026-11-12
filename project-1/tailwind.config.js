/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js"
  ],
  theme: {
    extend: {
      colors: {
        ground: "#E8EAE4",
        panel: "#F6F7F3",
        ink: "#12161D",
        muted: "#4A5260",
        line: "#C9CDC4",
        danger: "#C23A0C",
        dangerSoft: "#F08A65",
        safe: "#1D6B4C",
        suspicious: "#8A5A00",
        inkSoft: "#1E2430",
        inkLine: "#3A414D"
      },
      fontFamily: {
        sans: ['"Schibsted Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace']
      },
      borderRadius: {
        btn: "6px",
        input: "8px",
        panel: "10px",
        panelLg: "12px",
        chip: "999px"
      },
      borderWidth: {
        '1.5': '1.5px'
      },
      letterSpacing: {
        heading: '-0.025em'
      },
      lineHeight: {
        tightHeading: '1.05'
      }
    }
  },
  plugins: []
};

