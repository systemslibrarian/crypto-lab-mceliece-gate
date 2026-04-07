import "../styles/main.css";
import { initUi } from "./ui";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("App root not found");
}

initUi(app).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown startup error";
  const p = document.createElement("p");
  p.setAttribute("role", "alert");
  p.textContent = `Failed to initialize demo: ${message}`;
  app.replaceChildren(p);
});
