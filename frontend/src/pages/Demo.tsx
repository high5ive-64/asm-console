import { useEffect, useState } from "react";
import { enableDemo, demoScan } from "../api";
import { Results } from "./Results";

type Snapshot = { scanId: string; meta: Record<string, unknown>; endpoints: Record<string, unknown> };

function DemoBanner() {
  return (
    <div className="banner banner-info" style={{ marginBottom: 12 }}>
      <strong>Demo — redacted snapshot.</strong> This is a real Outsider ASM scan of{" "}
      <a href="https://pentest-ground.com" target="_blank" rel="noreferrer">pentest-ground.com</a>, a public
      penetration-testing practice range. Every host name, IP and email has been replaced with a pseudonym
      (<code>asset-01</code>, <code>ip-07</code>, <code>email-01</code>) by the same redaction used for the share
      pack. Standards references (MITRE ATT&amp;CK/ATLAS, CWE, OWASP, NVD, EPSS, CISA KEV) are preserved so the
      mappings stay clickable. The data is a point-in-time export; report generation and raw-evidence files are
      disabled.
    </div>
  );
}

/** Mounts the real Results UI against an in-memory redacted snapshot. */
export function DemoView({ snap, standalone }: { snap: Snapshot; standalone?: boolean }) {
  // enable synchronously so Results' first data fetches resolve from the snapshot
  enableDemo(snap, standalone);
  return (
    <div className="page">
      <div className="results-head">
        <h1 className="mono">{(demoScan() as { root_domain: string }).root_domain}</h1>
        <span className="muted small">Redacted demo snapshot</span>
      </div>
      <DemoBanner />
      <Results scan={demoScan()} />
    </div>
  );
}

/** In-app Demo tab: fetches the bundled snapshot asset, then renders the demo view. */
export function DemoPage() {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    fetch("/assets/demo_snapshot.json")
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(setSnap)
      .catch(() => setErr(true));
  }, []);
  if (err) return <div className="page"><h1>Demo</h1><p className="muted">Demo snapshot not found. Rebuild the image (make build) to bundle it.</p></div>;
  if (!snap) return <div className="page boot">Loading demo…</div>;
  return <DemoView snap={snap} />;
}
