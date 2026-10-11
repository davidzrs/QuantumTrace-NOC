import type { ScanSummary } from "@quantumtrace/sdk";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ScanTable } from "../components/ScanTable";
import { accountScanIds, signIn, signOut, useAccount } from "../lib/account";
import { api } from "../lib/api";
import { useDeleteScans } from "../lib/deleteScans";
import { plural } from "../lib/format";
import { MIN_PASSWORD, usernameProblem } from "../lib/username";

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
        <SignInForm />
      )}
    </main>
  );
}

const title = "font-display text-[32px] leading-tight font-bold tracking-[-0.02em]";
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
