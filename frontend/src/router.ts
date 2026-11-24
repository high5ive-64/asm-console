import { useEffect, useState } from "react";

// Minimal history-API router: no dependency, no hash URLs.
const listeners = new Set<() => void>();

export function navigate(to: string) {
  if (to !== window.location.pathname) window.history.pushState({}, "", to);
  listeners.forEach((l) => l());
}

window.addEventListener("popstate", () => listeners.forEach((l) => l()));

export function usePath(): string {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const l = () => setPath(window.location.pathname);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return path;
}

export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split("/").filter(Boolean);
  const s = path.split("/").filter(Boolean);
  if (p.length !== s.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(":")) params[p[i].slice(1)] = decodeURIComponent(s[i]);
    else if (p[i] !== s[i]) return null;
  }
  return params;
}
