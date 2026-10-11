import type { ScanSummary } from "@quantumtrace/sdk";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ScanTable } from "../components/ScanTable";
import { accountScanIds, signIn, signOut, useAccount } from "../lib/account";
import { api } from "../lib/api";
import { useDeleteScans } from "../lib/deleteScans";
import { plural } from "../lib/format";
import { MIN_PASSWORD, passwordProblem, usernameProblem } from "../lib/username";

/**
 * Optional account page, reached only from the "Account" link in the header. Nothing else on the
 * site asks anyone to sign in.
 */
export function Account() {
  const account = useAccount();
  if (account.status === "signed-in") return <SignedIn uid={account.uid} username={account.username} />;
  return (
    <main className="mx-auto grid max-w-[640px] grid-cols-[minmax(0,1fr)] gap-6 px-4 pt-12 pb-16 sm:px-8">
      <div className="grid gap-2">
        <h1 className={title}>Account</h1>
        <p className="text-ink-muted">
          Optional. An account keeps your scan history in one place, so you can open your reports from any
          computer. Scanning, reports and exports work the same without one.
        </p>
      </div>
      {account.status === "off" ? (
        <p className="text-ink-muted">Accounts aren’t set up on this deployment.</p>
      ) : account.status === "checking" ? (
        <p aria-live="polite" className="text-ink-muted">Checking your account…</p>
      ) : (
        <AccountForm />
      )}
    </main>
  );
}

const title = "font-display text-[32px] leading-tight font-bold tracking-[-0.02em]";
const panel = "grid gap-4 rounded-xl border border-rule bg-surface p-5 sm:px-6";
const field =
  "min-h-[38px] w-full rounded-lg border border-rule-strong bg-transparent px-3.5 text-[15px] outline-none placeholder:text-ink-faint focus:border-ink disabled:opacity-60";

/**
 * Signing in and creating an account are separate modes of one form, so it's always clear which one
 * the button does. Creating asks for the password twice; the username carries over between modes.
 */
function AccountForm() {
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const userId = useId();
  const passId = useId();
  const confirmId = useId();
  const hintId = useId();

  function switchMode() {
    setCreating((c) => !c);
    setPassword("");
    setConfirm("");
    setError(null);
  }

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const problem = usernameProblem(username) ?? passwordProblem(password, creating ? confirm : null);
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await signIn(username, password, creating);
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "That didn’t work. Try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form className={panel} onSubmit={(e) => void submit(e)} aria-labelledby={titleId} aria-busy={busy} noValidate>
        <div className="grid gap-1">
          <h2 id={titleId} className="font-display text-[22px] font-bold tracking-[-0.02em]">
            {creating ? "Create an account" : "Sign in"}
          </h2>
          {creating && <p className="text-[15px] text-ink-muted">Pick a username and a password. No email needed.</p>}
        </div>
        <div className="grid gap-1.5">
          <label htmlFor={userId} className="text-sm font-semibold">Username</label>
          <input
            id={userId}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            aria-describedby={creating ? hintId : undefined}
            disabled={busy}
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
            autoComplete={creating ? "new-password" : "current-password"}
            disabled={busy}
            className={field}
          />
        </div>
        {creating && (
          <>
            <div className="grid gap-1.5">
              <label htmlFor={confirmId} className="text-sm font-semibold">Confirm password</label>
              <input
                id={confirmId}
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
                disabled={busy}
                className={field}
              />
            </div>
            <p id={hintId} className="text-sm text-ink-faint">
              Usernames are 3 to 20 letters, digits, - or _. Passwords need at least {MIN_PASSWORD} characters.
              There’s no password reset, so keep yours somewhere safe.
            </p>
          </>
        )}
        {error && (
          <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
            {error}
          </p>
        )}
        <div>
          <button type="submit" className="btn btn-primary min-w-[150px]" disabled={busy}>
            {creating ? (busy ? "Creating account…" : "Create account") : busy ? "Signing in…" : "Sign in"}
          </button>
        </div>
      </form>
      <p className="text-ink-muted">
        {creating ? "Already have an account? " : "No account yet? "}
        <button type="button" onClick={switchMode} disabled={busy} className="link font-semibold disabled:opacity-50">
          {creating ? "Sign in" : "Create one"}
        </button>
      </p>
    </>
  );
}

/** Signed in: the account's own scans, the same on every computer, and a way out. */
function SignedIn({ uid, username }: { uid: string; username: string }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Only what's saved to the account, not this browser's history: this is what follows you around.
  const scans = useQuery({
    queryKey: ["scans", "account", uid],
    queryFn: async () => {
      const ids = await accountScanIds();
      if (!ids.length) return [];
      const found = await api.listScans(ids);
      return found.sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
  });
  const deleteScans = useDeleteScans();

  async function leave() {
    setBusy(true);
    setError(null);
    try {
      await signOut();
      queryClient.removeQueries({ queryKey: ["scans", "account"] });
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch {
      setError("Couldn’t sign out. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto grid max-w-[1240px] grid-cols-[minmax(0,1fr)] gap-10 px-4 pt-12 pb-16 sm:px-8">
      <div className="grid gap-4">
        <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
          <div className="grid gap-2">
            <h1 className={title}>Account</h1>
            <p className="max-w-[68ch] text-ink-muted">
              Signed in as <strong className="text-ink">{username}</strong>. Scans you run while signed in are saved
              here, so they follow you to any computer you sign in from. The scan page keeps listing what was run
              in this browser.
            </p>
          </div>
          <button type="button" className="btn" onClick={() => void leave()} disabled={busy}>
            {busy ? "Signing out…" : "Sign out"}
          </button>
        </div>
        {error && (
          <p role="alert" className="border-l-2 border-critical pl-4 text-[15px]">
            {error}
          </p>
        )}
      </div>

      <section aria-labelledby="account-history-title" className="grid grid-cols-[minmax(0,1fr)] gap-4">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="account-history-title" className="font-display text-[22px] font-bold tracking-[-0.02em]">
            Scan history
          </h2>
          <span className="text-sm text-ink-faint">Reports are kept for 30 days after they run</span>
        </div>
        {scans.isPending ? (
          <p aria-live="polite" className="text-ink-muted">Loading your scans…</p>
        ) : scans.isError ? (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
            <p role="alert" className="border-l-2 border-critical pl-4">
              Couldn’t load your scans. Check your connection and that the scanner is online, then try again.
            </p>
            <button type="button" className="btn" onClick={() => void scans.refetch()} disabled={scans.isFetching}>
              Try again
            </button>
          </div>
        ) : scans.data.length ? (
          <>
            <p className="text-[17px]">{historySentence(scans.data)}</p>
            {deleteScans.error && (
              <p role="alert" className="border-l-2 border-critical pl-4">
                {deleteScans.error.message}. Check that the scanner is online and try again.
              </p>
            )}
            <ScanTable scans={scans.data} onDelete={(id) => deleteScans.mutate([id])} deleting={deleteScans.isPending} />
          </>
        ) : (
          <div className="grid justify-items-start gap-4">
            <p className="text-ink-muted">
              Nothing saved yet. Scans you run while signed in show up here, on any computer.
            </p>
            <Link to="/" className="btn btn-primary">
              Run a scan
            </Link>
          </div>
        )}
      </section>
    </main>
  );
}

/** "6 scans saved. 4 of them found cryptography that breaks under Shor’s algorithm." */
function historySentence(scans: ScanSummary[]): string {
  const saved = `${plural(scans.length, "scan")} saved.`;
  const shor = scans.filter((s) => s.score.counts.critical > 0).length;
  const one = scans.length === 1;
  if (!shor) return `${saved} ${one ? "It didn’t find" : "None of them found"} cryptography that breaks under Shor’s algorithm.`;
  const who = one ? "It" : shor === scans.length ? "All of them" : `${shor} of them`;
  return `${saved} ${who} found cryptography that breaks under Shor’s algorithm.`;
}
