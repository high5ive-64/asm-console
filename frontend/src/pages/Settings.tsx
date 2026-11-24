import { ChangeEvent, useEffect, useState } from "react";
import { api, ApiError, CloudlistImport, SecretStatus, Settings } from "../api";
import { Badge, Button, Card, Empty, Field, fmtDate, useToast } from "../components/ui";

const TABS = [
  { key: "keys", label: "Sources & keys" },
  { key: "ai", label: "AI models" },
  { key: "defaults", label: "Defaults" },
  { key: "cmdb", label: "CMDB" },
] as const;
type Tab = (typeof TABS)[number]["key"];

const TIER: Record<string, { label: string; tone: "good" | "info" | "warn" }> = {
  free: { label: "Free", tone: "good" },
  freemium: { label: "Free tier · paid plans", tone: "info" },
  paid: { label: "Paid", tone: "warn" },
};
const GROUPS: { key: string; title: string; intro: string }[] = [
  {
    key: "intel",
    title: "Exposure intelligence",
    intro: "Optional. Every scan works without these; each key switches on more data. Free accounts are enough except where marked Paid.",
  },
  {
    key: "cloud",
    title: "Cloud accounts (cloudlist)",
    intro:
      "Lists public IPs and DNS names straight from your cloud accounts. Either upload cloudlist's output (no keys stored here) or save read-only keys.",
  },
  { key: "discovery", title: "Discovery sources", intro: "Used by BBOT's passive discovery to find more subdomains." },
];

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>("keys");
  return (
    <div className="page">
      <h1>Settings</h1>
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} className={tab === t.key ? "tab active" : "tab"} onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "keys" && <KeysTab />}
      {tab === "ai" && (
        <Card title="AI models">
          <Empty>Local and cloud model providers arrive in milestone 7. Reports work without AI.</Empty>
        </Card>
      )}
      {tab === "defaults" && <DefaultsTab />}
      {tab === "cmdb" && <CmdbTab />}
    </div>
  );
}

function KeysTab() {
  const [secrets, setSecrets] = useState<SecretStatus[] | null>(null);
  const load = () => api<{ secrets: SecretStatus[] }>("/api/secrets").then((r) => setSecrets(r.secrets.filter((s) => !s.name.startsWith("ai:"))));
  useEffect(() => {
    load();
  }, []);
  if (!secrets) return <Empty>Loading…</Empty>;
  return (
    <div className="stack">
      {GROUPS.map((g) => (
        <section key={g.key} className="stack">
          <div>
            <h2 className="h2">{g.title}</h2>
            <p className="muted small">{g.intro}</p>
          </div>
          {g.key === "cloud" && <CloudlistCard />}
          <div className="grid-2">
            {secrets
              .filter((s) => (s.group ?? "discovery") === g.key)
              .map((s) => (
                <KeyCard key={s.name} s={s} onChange={load} />
              ))}
          </div>
        </section>
      ))}
      <Card title="SpiderFoot (self-hosted sidecar)">
        <p className="muted small">
          Free and open source. Start it with <code>docker compose --profile spiderfoot up -d</code>, then tick the SpiderFoot stage in a scan's
          options. Outsider ASM only ever runs its <em>passive</em> modules. The sidecar's own web UI (http://127.0.0.1:5001) has no login and can
          run active modules, so use it for viewing only. The address is under Defaults.
        </p>
      </Card>
      <p className="muted small">
        Keys are encrypted at rest and are write-only: once saved they're never shown again, only replaced or removed. Paid options are labelled;
        nothing paid is used unless you add its key and switch it on.
      </p>
    </div>
  );
}

function CloudlistCard() {
  const [st, setSt] = useState<CloudlistImport | null>(null);
  const toast = useToast();
  const load = () => api<CloudlistImport>("/api/imports/cloudlist").then(setSt);
  useEffect(() => {
    load();
  }, []);
  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    try {
      const r = await api<CloudlistImport>("/api/imports/cloudlist", { method: "POST", body: await f.text() });
      setSt(r);
      toast(`Imported ${r.assets} cloud assets`, "good");
    } catch (err) {
      toast(err instanceof ApiError ? err.message : "Import failed", "bad");
    }
  };
  const clear = async () => {
    setSt(await api<CloudlistImport>("/api/imports/cloudlist", { method: "DELETE" }));
  };
  return (
    <Card
      title="Upload cloudlist output"
      actions={
        <label className="btn btn-secondary btn-sm">
          Upload file
          <input type="file" accept=".json,.jsonl,.txt" hidden onChange={onFile} />
        </label>
      }
    >
      <p className="muted small">
        Run <code>cloudlist -json -o cloud.jsonl</code> wherever your cloud credentials already live, then upload the file. A plain list of IPs
        and hostnames works too. Used by every scan until you replace or remove it.
      </p>
      {st?.present ? (
        <div className="inline">
          <Badge tone="good">imported</Badge>
          <span className="small">
            {st.assets} assets · {st.public_ips} public IPs · {st.hosts} names{st.providers?.length ? ` · ${st.providers.join(", ")}` : ""} · {fmtDate(st.updated_at ?? null)}
          </span>
          <span className="spacer" />
          <Button small kind="ghost" onClick={clear}>
            Remove
          </Button>
        </div>
      ) : (
        <p className="muted small">Nothing uploaded.</p>
      )}
    </Card>
  );
}

function KeyCard(props: { s: SecretStatus; onChange: () => void }) {
  const { s } = props;
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const save = async () => {
    setBusy(true);
    try {
      await api(`/api/secrets/${s.name}`, { method: "PUT", json: { value } });
      setValue("");
      toast(`${s.label} key saved`, "good");
      props.onChange();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Save failed", "bad");
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    await api(`/api/secrets/${s.name}`, { method: "DELETE" });
    toast(`${s.label} key removed`, "info");
    props.onChange();
  };
  const test = async () => {
    setBusy(true);
    try {
      const r = await api<{ testable: boolean; ok?: boolean; message: string }>(`/api/secrets/${s.name}/test`, { method: "POST" });
      toast(r.testable ? `${s.label}: ${r.ok ? "key works" : "key rejected"} (${r.message})` : r.message, r.testable && !r.ok ? "bad" : "good");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Test failed", "bad");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title={s.label}
      actions={
        <span className="inline">
          {s.tier && <Badge tone={TIER[s.tier].tone}>{TIER[s.tier].label}</Badge>}
          {s.set ? <Badge tone="good">set</Badge> : <Badge>not set</Badge>}
        </span>
      }
    >
      <p className="muted small">
        {s.note}
        {s.signup && (
          <>
            {" "}
            <a href={s.signup} target="_blank" rel="noreferrer">
              Get a key
            </a>
          </>
        )}
      </p>
      <div className="inline">
        <input
          type="password"
          autoComplete="off"
          placeholder={s.set ? "Replace key…" : "Paste key…"}
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <Button kind="primary" small onClick={save} disabled={busy || !value.trim()}>
          Save
        </Button>
      </div>
      {s.set && (
        <div className="inline gap-top">
          <span className="muted small">Updated {fmtDate(s.updated_at)}</span>
          <span className="spacer" />
          <Button small kind="ghost" onClick={test} disabled={busy}>
            Test
          </Button>
          <Button small kind="ghost" onClick={remove} disabled={busy}>
            Remove
          </Button>
        </div>
      )}
    </Card>
  );
}

function DefaultsTab() {
  const [s, setS] = useState<Settings | null>(null);
  const [providers, setProviders] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const toast = useToast();

  useEffect(() => {
    api<Settings>("/api/settings").then((r) => {
      setS(r);
      setProviders(r.third_party_providers.join("\n"));
    });
  }, []);
  if (!s) return <Empty>Loading…</Empty>;

  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v });
  const num = (k: keyof Settings) => (e: ChangeEvent<HTMLInputElement>) => set(k, Number(e.target.value) as never);

  const save = async () => {
    setErrors({});
    try {
      const r = await api<Settings>("/api/settings", {
        method: "PUT",
        json: { ...s, third_party_providers: providers.split(/\s+/).filter(Boolean) },
      });
      setS(r);
      setProviders(r.third_party_providers.join("\n"));
      toast("Settings saved", "good");
    } catch (e) {
      if (e instanceof ApiError && e.issues) setErrors(Object.fromEntries(e.issues.map((i) => [i.field, i.message])));
      toast("Some values need fixing", "bad");
    }
  };

  return (
    <div className="stack">
      <Card title="Identity">
        <Field label="User-Agent" hint="Sent by every light-touch request, so your SOC can recognise the traffic." error={errors.user_agent}>
          <input value={s.user_agent} onChange={(e) => set("user_agent", e.target.value)} />
        </Field>
        <Field label="Company name" hint="Shown in report headers." error={errors.company_name}>
          <input value={s.company_name} onChange={(e) => set("company_name", e.target.value)} />
        </Field>
      </Card>
      <Card title="Scan limits">
        <div className="grid-3">
          <Field label="ZAP spider (minutes per host)" error={errors.zap_spider_minutes}>
            <input type="number" min={1} max={30} value={s.zap_spider_minutes} onChange={num("zap_spider_minutes")} />
          </Field>
          <Field label="ZAP AJAX spider (minutes per host)" error={errors.zap_ajax_minutes}>
            <input type="number" min={1} max={30} value={s.zap_ajax_minutes} onChange={num("zap_ajax_minutes")} />
          </Field>
          <Field label="TLS check concurrency" error={errors.tlsx_concurrency}>
            <input type="number" min={1} max={50} value={s.tlsx_concurrency} onChange={num("tlsx_concurrency")} />
          </Field>
          <Field label="Warn when scope exceeds (hosts)" error={errors.large_scope_warning}>
            <input type="number" min={10} value={s.large_scope_warning} onChange={num("large_scope_warning")} />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" checked={s.shodan_lookups} onChange={(e) => set("shodan_lookups", e.target.checked)} />
          Shodan host lookups with your key (free on a free account; InternetDB runs regardless)
        </label>
        <Field label="SpiderFoot sidecar address" hint="Only change this if you run SpiderFoot somewhere other than the bundled sidecar." error={errors.spiderfoot_url}>
          <input value={s.spiderfoot_url} onChange={(e) => set("spiderfoot_url", e.target.value)} />
        </Field>
      </Card>
      <Card title="Third-party providers">
        <Field
          label="Domains treated as third parties"
          hint="Hosts that point at these are labelled third-party: observed, never tested, and never suggested as related domains. One per line."
          error={errors.third_party_providers}
        >
          <textarea rows={8} value={providers} onChange={(e) => setProviders(e.target.value)} spellCheck={false} />
        </Field>
      </Card>
      <div className="actions">
        <Button kind="primary" onClick={save}>
          Save settings
        </Button>
      </div>
    </div>
  );
}

function CmdbTab() {
  const [entries, setEntries] = useState<{ value: string; kind: string }[] | null>(null);
  const [text, setText] = useState("");
  const toast = useToast();
  const load = () => api<{ entries: { value: string; kind: string }[] }>("/api/cmdb").then((r) => setEntries(r.entries));
  useEffect(() => {
    load();
  }, []);

  const importText = async (body: string) => {
    try {
      const r = await api<{ added: number; skipped: number; total: number }>("/api/cmdb/import", { method: "POST", body });
      toast(`Added ${r.added}, skipped ${r.skipped}. ${r.total} known assets.`, "good");
      setText("");
      load();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Import failed", "bad");
    }
  };
  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) importText(await f.text());
    e.target.value = "";
  };
  const clear = async () => {
    if (!window.confirm("Remove all known assets?")) return;
    await api("/api/cmdb", { method: "DELETE" });
    load();
  };

  return (
    <div className="stack">
      <Card title="Import known assets" actions={<label className="btn btn-secondary btn-sm">Upload file<input type="file" accept=".txt,.csv" hidden onChange={onFile} /></label>}>
        <p className="muted small">
          Hostnames and public IPs from your CMDB or asset register. Used to flag discovered assets that aren't recorded. Text or CSV; any
          column layout works.
        </p>
        <textarea rows={5} value={text} onChange={(e) => setText(e.target.value)} placeholder={"www.example.com\nshop.example.com\n203.0.113.10"} spellCheck={false} />
        <div className="actions">
          <Button kind="primary" small onClick={() => importText(text)} disabled={!text.trim()}>
            Import
          </Button>
        </div>
      </Card>
      <Card title={`Known assets (${entries?.length ?? 0})`} actions={entries?.length ? <Button kind="ghost" small onClick={clear}>Clear all</Button> : undefined}>
        {!entries ? (
          <Empty>Loading…</Empty>
        ) : entries.length === 0 ? (
          <Empty>None yet.</Empty>
        ) : (
          <ul className="chips">
            {entries.slice(0, 300).map((e) => (
              <li key={e.value} className="chip mono">
                {e.value}
              </li>
            ))}
            {entries.length > 300 && <li className="muted small">…and {entries.length - 300} more</li>}
          </ul>
        )}
      </Card>
    </div>
  );
}
