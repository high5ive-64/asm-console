import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";
import { Button, Field, Brand } from "../components/ui";

export function LoginPage(props: { onLogin: (csrf: string) => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const r = await api<{ csrf: string }>("/api/auth/login", { method: "POST", json: { token: token.trim() } });
      props.onLogin(r.csrf);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the app");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login card" onSubmit={submit}>
        <Brand large />
        <p className="muted">
          Enter the access token printed in the container log on first start. Lost it? Run{" "}
          <code>docker compose exec asm python -m asm reset-token</code>.
        </p>
        <Field label="Access token" error={error}>
          <input
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoFocus
          />
        </Field>
        <Button kind="primary" type="submit" disabled={busy || token.trim().length < 10}>
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}
