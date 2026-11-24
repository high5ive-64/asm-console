import { useEffect, useState } from "react";
import { api, setCsrf, setUnauthorisedHandler } from "./api";
import { Link, Brand } from "./components/ui";
import { ScanList } from "./components/ScanList";
import { match, navigate, usePath } from "./router";
import { LoginPage } from "./pages/Login";
import { HomePage } from "./pages/Home";
import { SettingsPage } from "./pages/Settings";
import { AboutPage } from "./pages/About";
import { NewScanPage } from "./pages/NewScan";
import { ScanPage } from "./pages/Scan";

const NAV = [
  { to: "/", label: "Home" },
  { to: "/scans/new", label: "New scan" },
  { to: "/settings", label: "Settings" },
  { to: "/about", label: "About" },
];

export function App() {
  const path = usePath();
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    setUnauthorisedHandler(() => {
      setCsrf(null);
      setAuthed(false);
    });
    api<{ authenticated: boolean; csrf: string | null }>("/api/auth/status")
      .then((s) => {
        setCsrf(s.csrf);
        setAuthed(s.authenticated);
      })
      .catch(() => setAuthed(false));
  }, []);

  if (authed === null) return <div className="boot">Loading…</div>;
  if (!authed)
    return (
      <LoginPage
        onLogin={(csrf) => {
          setCsrf(csrf);
          setAuthed(true);
        }}
      />
    );

  let page;
  let m: Record<string, string> | null;
  if (path === "/") page = <HomePage />;
  else if (path === "/scans/new") page = <NewScanPage />;
  else if ((m = match("/scans/:id", path))) page = <ScanPage id={m.id} />;
  else if (path.startsWith("/settings")) page = <SettingsPage />;
  else if (path === "/about") page = <AboutPage />;
  else page = <div className="page"><h1>Not found</h1></div>;

  const logout = async () => {
    await api("/api/auth/logout", { method: "POST" }).catch(() => {});
    setCsrf(null);
    setAuthed(false);
    navigate("/");
  };

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <Brand />
        <ul>
          {NAV.map((n) => {
            const active = n.to === "/" ? path === "/" : path.startsWith(n.to);
            return (
              <li key={n.to}>
                <Link to={n.to} className={active ? "nav-link active" : "nav-link"}>
                  {n.label}
                </Link>
              </li>
            );
          })}
        </ul>
        <ScanList path={path} />
        <div className="sidebar-foot">
          <span className="pill" title="Active options exist but are off unless you switch them on per scan, with a warning">Passive + light-touch by default</span>
          <button className="linklike" onClick={logout}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="main">{page}</main>
    </div>
  );
}
