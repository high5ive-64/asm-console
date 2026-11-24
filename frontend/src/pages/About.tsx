import { useEffect, useState } from "react";
import { About, api } from "../api";
import { Badge, Card, Empty } from "../components/ui";

export function AboutPage() {
  const [about, setAbout] = useState<About | null>(null);
  useEffect(() => {
    api<About>("/api/about").then(setAbout);
  }, []);
  if (!about) return <div className="page"><Empty>Loading…</Empty></div>;
  return (
    <div className="page">
      <h1>About</h1>
      <Card title={`Outsider ASM ${about.app_version}`}>
        <p className="muted">
          Data folder inside the container: <code>{about.data_dir}</code> (mapped to <code>./data</code> next to
          docker-compose.yml). Tool versions are recorded with every scan as audit evidence.
        </p>
        <table className="table compact">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(about.tools).map(([k, v]) => (
              <tr key={k}>
                <td>{k}</td>
                <td>{v === "not installed" ? <Badge tone="bad">not installed</Badge> : <span className="mono">{v}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">
          Reset the access token: <code>docker compose exec asm python -m asm reset-token</code>
        </p>
      </Card>
    </div>
  );
}
