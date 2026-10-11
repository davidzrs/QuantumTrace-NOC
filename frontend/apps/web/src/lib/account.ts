/**
 * Optional accounts (Firebase Auth + Firestore). Nothing in the scan flow depends on this: with no
 * Firebase config, or nobody signed in, the site works exactly the same.
 *
 * Firebase is loaded on demand, only when someone signs in or this browser already holds a
 * signed-in session (the HINT key), so visitors who never use accounts never download it.
 * An account stores the ids of its scans at users/{uid}/scans/{scanId}; the reports stay in the API.
 */
import { useSyncExternalStore } from "react";
import type { Auth } from "firebase/auth";
import type { CollectionReference, Firestore } from "firebase/firestore";
import { api } from "./api";
import { MAX_HISTORY, readHistory } from "./history";
import { authMessage, emailFor, usernameOf } from "./username";

const config = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};
/** False on a deployment without Firebase config: the Account link is hidden. */
export const accountsEnabled = Object.values(config).every(Boolean);

const HINT = "quantumtrace:account";

export type AccountState =
  | { status: "off" }
  | { status: "signed-out" }
  | { status: "checking" } // restoring a session on page load
  | { status: "signed-in"; uid: string; username: string };

/** A failure the user can act on; the message is safe to show. */
export class AccountError extends Error {}

export interface AccountScan {
  id: string;
  created_at: string;
  targets: string[];
}

// ---------------------------------------------------------------- state
const listeners = new Set<() => void>();
let state: AccountState = !accountsEnabled ? { status: "off" } : hasHint() ? { status: "checking" } : { status: "signed-out" };

function set(next: AccountState): void {
  state = next;
  for (const listener of listeners) listener();
}

export function accountState(): AccountState {
  return state;
}

export function useAccount(): AccountState {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    () => state,
  );
}

function hasHint(): boolean {
  try {
    return localStorage.getItem(HINT) === "1";
  } catch {
    return false;
  }
}

function setHint(on: boolean): void {
  try {
    if (on) localStorage.setItem(HINT, "1");
    else localStorage.removeItem(HINT);
  } catch {
    // Without storage the session still works until the tab closes.
  }
}

// ---------------------------------------------------------------- Firebase, on demand
interface Services {
  auth: Auth;
  db: Firestore;
  authApi: typeof import("firebase/auth");
  store: typeof import("firebase/firestore");
}
let services: Promise<Services> | undefined;

function load(): Promise<Services> {
  services ??= (async () => {
    const [{ initializeApp }, authApi, store] = await Promise.all([
      import("firebase/app"),
      import("firebase/auth"),
      import("firebase/firestore"),
    ]);
    const app = initializeApp(config);
    const auth = authApi.getAuth(app);
    const db = store.getFirestore(app);
    authApi.onAuthStateChanged(auth, (user) => {
      setHint(user !== null);
      set(user ? { status: "signed-in", uid: user.uid, username: usernameOf(user.email) } : { status: "signed-out" });
    });
    return { auth, db, authApi, store };
  })().catch((err: unknown) => {
    services = undefined; // let a later attempt retry
    throw err;
  });
  return services;
}

if (state.status === "checking") {
  load().catch(() => set({ status: "signed-out" }));
}

function codeOf(err: unknown): string | undefined {
  return typeof err === "object" && err !== null && "code" in err ? String(err.code) : undefined;
}

// ---------------------------------------------------------------- sign in / out
/**
 * Sign in, or create the account first. Then copy this browser's scan history into the account.
 * Returns how many scans were added.
 */
export async function signIn(username: string, password: string, create: boolean): Promise<number> {
  let s: Services;
  try {
    s = await load();
  } catch {
    throw new AccountError("Couldn’t load the account service. Check your connection and try again.");
  }
  try {
    const email = emailFor(username);
    if (create) await s.authApi.createUserWithEmailAndPassword(s.auth, email, password);
    else await s.authApi.signInWithEmailAndPassword(s.auth, email, password);
  } catch (err) {
    throw new AccountError(authMessage(codeOf(err)));
  }
  return copyBrowserHistory().catch(() => 0);
}

export async function signOut(): Promise<void> {
  const s = await load();
  await s.authApi.signOut(s.auth);
}

// ---------------------------------------------------------------- the account's scans
async function scans(): Promise<{ s: Services; col: CollectionReference }> {
  const s = await load();
  await s.auth.authStateReady();
  const user = s.auth.currentUser;
  if (!user) throw new AccountError("Not signed in.");
  return { s, col: s.store.collection(s.db, "users", user.uid, "scans") };
}

/** The account's newest scan ids. */
export async function accountScanIds(): Promise<string[]> {
  const { s, col } = await scans();
  const snap = await s.store.getDocs(
    s.store.query(col, s.store.orderBy("created_at", "desc"), s.store.limit(MAX_HISTORY)),
  );
  return snap.docs.map((d) => d.id);
}

export async function saveScans(list: AccountScan[]): Promise<void> {
  if (!list.length) return;
  const { s, col } = await scans();
  const batch = s.store.writeBatch(s.db);
  for (const { id, created_at, targets } of list) {
    batch.set(s.store.doc(col, id), { created_at, targets });
  }
  await batch.commit();
}

export async function removeScans(ids: string[]): Promise<void> {
  if (!ids.length) return;
  const { s, col } = await scans();
  const batch = s.store.writeBatch(s.db);
  for (const id of ids) batch.delete(s.store.doc(col, id));
  await batch.commit();
}

/** Signed in, so the scans already in this browser join the account. */
async function copyBrowserHistory(): Promise<number> {
  const ids = readHistory();
  if (!ids.length) return 0;
  const found = await api.listScans(ids);
  await saveScans(found.map(({ id, created_at, targets }) => ({ id, created_at, targets })));
  return found.length;
}
