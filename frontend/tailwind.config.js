/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#15202b",
        panel: "#f7f9fb",
        line: "#d8e0e8",
        accent: "#0f766e",
        danger: "#b42318",
        warn: "#b54708"
      },
      boxShadow: {
        panel: "0 18px 50px rgba(2, 6, 23, 0.32)"
      }
    }
  },
  plugins: []
};
