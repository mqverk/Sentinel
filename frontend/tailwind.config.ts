import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#070b12",
        panel: "#0f1723",
        panel2: "#121e2f",
        edge: "#1f2b3d",
        text: "#d8e4ff",
        mute: "#8ba0c7",
        accent: "#4fd1c5",
        danger: "#f87171",
        warn: "#fbbf24",
      },
      fontFamily: {
        sans: ["'Sora'", "'IBM Plex Sans'", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      keyframes: {
        floatIn: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        floatIn: "floatIn 420ms ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
