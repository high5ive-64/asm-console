import { useEffect, useState } from "react";
import { api, Scan, SecretStatus } from "../api";
import { Badge, Button, Card, Empty, fmtDate, Link } from "../components/ui";
import { navigate } from "../router";

const STATUS_TONE: Record<string, "good" | "warn" | "bad" | "info" | "muted"> = {
  draft: "muted",
  discovering: "info",
  awaiting_scope: "warn",
  ready: "info",
  running: "info",
  completed: "good",
  completed_with_errors: "warn",
  failed: "bad",
  cancelled: "muted",
  interrupted: "warn",
};

export function HomePage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [missing, setMissing] = useState<string[]>([]);
  const [hist, setHist] = useState<Record<string, { rag: string; values: Record<string, number>; severity: Record<string, number> }>>({});

  useEffect(() => {
    api<{ scans: Scan[] }>("/api/scans").then((r) => setScans(r.scans));
    api<{ scans: typeof hist }>("/api/history").then((r) => setHist(r.scans)).catch(() => {});
    api<{ secrets: SecretStatus[] }>("/api/secrets").then((r) =>
      setMissing(r.secrets.filter((s) => !s.set && ["shodan", "securitytrails", "virustotal", "censys"].includes(s.name)).map((s) => s.label))
    );
  }, []);

  return (
    <div className="page">
      <div className="page-head">
        <h1>Scans</h1>
        <Button kind="primary" onClick={() => navigate("/scans/new")}>
          New scan
        </Button>
      </div>

      {missing.length > 0 && (
        <div className="banner banner-warn">
          Discovery works best with API keys. Not set: {missing.join(", ")}. <Link to="/settings">Add keys in Settings</Link>.
        </div>
      )}

      <Card>
        {scans === null ? (
          <Empty>Loading…</Empty>
        ) : scans.length === 0 ? (
          <Empty>No scans yet. Start with a domain you're authorised to assess.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Created</th>
                <th>Root domain</th>
                <th>Status</th>
                <th>Result</th>
                <th>Hosts</th>
                <th>High / medium</th>
                <th>Unknown</th>
                <th>Finished</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="row-link" onClick={() => navigate(`/scans/${s.id}`)}>
                  <td>{fmtDate(s.created_at)}</td>
                  <td className="mono">{s.root_domain}</td>
                  <td>
                    <Badge tone={STATUS_TONE[s.status] ?? "muted"}>{s.status.replace(/_/g, " ")}</Badge>
                  </td>
                  <td>{hist[s.id] ? <span className={`rag-pill rag-pill-${hist[s.id].rag}`}>{hist[s.id].rag}</span> : ""}</td>
                  <td>{hist[s.id]?.values.hosts_in_scope ?? ""}</td>
                  <td>{hist[s.id] ? `${hist[s.id].values.high_findings} / ${hist[s.id].values.medium_findings}` : ""}</td>
                  <td>{hist[s.id]?.values.unknown_hosts ?? ""}</td>
                  <td>{fmtDate(s.finished_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
