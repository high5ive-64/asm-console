import { FormEvent, useState } from "react";
import { api, ApiError, Scan } from "../api";
import { Button, Card, Field } from "../components/ui";
import { navigate } from "../router";

const STEPS = ["Domain", "Discovery sources", "Scope", "Authorisation", "Options", "Review", "Run", "Results"];

export function Stepper(props: { current: number; reach?: number; onPick?: (i: number) => void; live?: number | null; natural?: number }) {
  const reach = props.reach ?? props.current;
  return (
    <ol className="stepper">
      {STEPS.map((s, i) => {
        const cls = [i === props.current ? "current" : i <= reach ? "done" : "", props.onPick && i <= reach ? "pickable" : ""].join(" ");
        const inner = (
          <>
            <span className="step-num">{props.live === i ? <span className="spinner sm" aria-hidden="true" /> : i + 1}</span>
            {s}
            {props.natural !== undefined && i === props.natural && i !== props.current && <span className="step-here" aria-label="current stage" />}
          </>
        );
        return (
          <li key={s} className={cls}>
            {props.onPick && i <= reach ? (
              <button className="step-btn" onClick={() => props.onPick!(i)} aria-current={i === props.current ? "step" : undefined}>
                {inner}
              </button>
            ) : (
              inner
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function NewScanPage() {
  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const scan = await api<Scan>("/api/scans", { method: "POST", json: { root_domain: domain } });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? (err.issues?.[0]?.message ?? err.message) : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page narrow">
      <h1>New scan</h1>
      <Stepper current={0} />
      <Card>
        <form onSubmit={submit} className="stack">
          <Field
            label="Main domain"
            hint="A bare domain such as example.com. You'll review every subdomain and related domain before anything is scanned."
            error={error}
          >
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoFocus
              spellCheck={false}
              autoCapitalize="off"
            />
          </Field>
          <div className="note">
            <strong>What happens next:</strong> passive discovery only (certificate logs, DNS records and third-party data
            sources). Nothing is sent to the domain's own servers until you confirm scope and authorisation.
          </div>
          <div className="actions">
            <Button kind="primary" type="submit" disabled={busy || domain.trim().length < 3}>
              {busy ? "Creating…" : "Continue"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
