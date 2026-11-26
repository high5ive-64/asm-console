import { createRoot } from "react-dom/client";
import { ToastProvider } from "./components/ui";
import { DemoView } from "./pages/Demo";
import snapshot from "./demo_snapshot.json";

createRoot(document.getElementById("root")!).render(
  <ToastProvider>
    <DemoView snap={snapshot as unknown as { scanId: string; meta: Record<string, unknown>; endpoints: Record<string, unknown> }} standalone />
  </ToastProvider>
);
