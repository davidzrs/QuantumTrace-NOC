import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { signIn, signOut, useAccount } from "../lib/account";
import { MIN_PASSWORD, usernameProblem } from "../lib/username";

/**
 * Optional account page, reached only from the "Account" link in the header. Nothing else on the
 * site asks anyone to sign in.
 */
export function Account() {
  const account = useAccount();
  return (
    <main className="mx-auto grid max-w-[640px] grid-cols-[minmax(0,1fr)] gap-6 px-4 pt-12 pb-16 sm:px-8">
      <div className="grid gap-2">
        <h1 className="font-display text-[32px] leading-tight font-bold tracking-[-0.02em]">Account</h1>
        <p className="text-ink-muted">
          Optional. An account keeps your scan history in one place, so you can open your reports from any
          computer. Scanning, reports and exports work the same without one.
        </p>
      </div>
      {account.status === "off" ? (
        <p className="text-ink-muted">Accounts aren’t set up on this deployment.</p>
      ) : account.status === "checking" ? (
        <p aria-live="polite" className="text-ink-muted">Checking your account…</p>
      ) : account.status === "signed-in" ? (
        <SignedIn username={account.username} />
      ) : (
        <SignInForm />
      )}
    </main>
  );
}

const panel = "grid gap-4 rounded-xl border border-rule bg-surface p-5 sm:px-6";
const field =
  "min-h-[38px] w-full rounded-lg border border-rule-strong bg-transparent px-3.5 text-[15px] outline-none placeholder:text-ink-faint focus:border-ink disabled:opacity-60";

function SignInForm() {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"in" | "up" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const userId = useId();
  const passId = useId();
  const hintId = useId();

  async function submit(mode: "in" | "up") {
    const problem =
      usernameProblem(username) ??
      (mode === "up" && password.length < MIN_PASSWORD
        ? `Use at least ${MIN_PASSWORD} characters for the password.`
        : !password
          ? "Enter your password."
          : null);
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    setBusy(mode);
    try {
      await signIn(username, password, mode === "up");
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "That didn’t work. Try again in a moment.");
    } finally {
      setBusy(null);
    }
  }

  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const submitter = (e.nativeEvent as SubmitEvent).submitter;
    void submit(submitter?.getAttribute("value") === "up" ? "up" : "in");
  };

  return (
    <form className={panel} onSubmit={onSubmit} aria-busy={busy !== null} noValidate>
      <div className="grid gap-1.5">
        <label htmlFor={userId} className="text-sm font-semibold">Username</label>
        <input
          id={userId}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          aria-describedby={hintId}
          disabled={busy !== null}
          className={field}
        />
      </div>
      <div className="grid gap-1.5">
        <label htmlFor={passId} className="text-sm font-semibold">Password</label>
        <input
          id={passId}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          disabled={busy !== null}
          className={field}
        />
      </div>
      <p id={hintId} className="text-sm text-ink-faint">
        Usernames are 3 to 20 letters, digits, - or _. Passwords need at least {MIN_PASSWORD} characters. There’s
        no password reset, so keep yours somewhere safe.
      </p>
      {error && (
        <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-3">
        <button type="submit" value="in" className="btn btn-primary min-w-[120px]" disabled={busy !== null}>
          {busy === "in" ? "Signing in…" : "Sign in"}
        </button>
        <button type="submit" value="up" className="btn min-w-[150px]" disabled={busy !== null}>
          {busy === "up" ? "Creating account…" : "Create account"}
        </button>
      </div>
    </form>
  );
}

function SignedIn({ username }: { username: string }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function leave() {
    setBusy(true);
    setError(null);
    try {
      await signOut();
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch {
      setError("Couldn’t sign out. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={panel}>
      <p className="text-[17px]">
        Signed in as <strong>{username}</strong>.
      </p>
      <p className="text-ink-muted">
        Scans you run while signed in, and the ones already in this browser, are saved to your account. Sign in on
        another computer to see them there. Reports are kept for 30 days after they run. Signing out leaves this
        browser’s own scans listed.
      </p>
      {error && (
        <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-3">
        <Link to="/" className="btn btn-primary">
          Back to scanning
        </Link>
        <button type="button" className="btn" onClick={() => void leave()} disabled={busy}>
          {busy ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </div>
  );
}
