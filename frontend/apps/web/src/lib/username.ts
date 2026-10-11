/**
 * Accounts are username + password. Firebase Auth signs in with an email, so each username maps
 * to an address on a domain nobody receives mail for: no email is ever sent. Pure, so it's tested.
 */
const DOMAIN = "users.quantumtrace.app";
const PATTERN = /^[a-z0-9_-]{3,20}$/;
export const MIN_PASSWORD = 6; // Firebase's own minimum

export function normaliseUsername(name: string): string {
  return name.trim().toLowerCase();
}

/** Why a username can't be used, or null when it can. */
export function usernameProblem(name: string): string | null {
  const n = normaliseUsername(name);
  if (!n) return "Enter a username.";
  if (n.length < 3 || n.length > 20) return "Usernames are 3 to 20 characters long.";
  if (!PATTERN.test(n)) return "Usernames use only letters, digits, - and _.";
  return null;
}

/**
 * Why a password can't be used, or null when it can. `confirm` is the second copy typed when
 * creating an account; null when signing in, where only Firebase knows if it's right.
 */
export function passwordProblem(password: string, confirm: string | null): string | null {
  if (confirm === null) return password ? null : "Enter your password.";
  if (!password) return "Choose a password.";
  if (password.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters for the password.`;
  if (!confirm) return "Type the password again to confirm it.";
  if (confirm !== password) return "The two passwords don’t match. Type them again.";
  return null;
}

export function emailFor(name: string): string {
  return `${normaliseUsername(name)}@${DOMAIN}`;
}

export function usernameOf(email: string | null | undefined): string {
  return (email ?? "").replace(`@${DOMAIN}`, "");
}

/** Plain-language messages for the Firebase error codes a user can actually cause. */
export function authMessage(code: string | undefined): string {
  switch (code) {
    case "auth/email-already-in-use":
      return "That username is taken. Pick another, or sign in if it’s yours.";
    case "auth/invalid-credential":
    case "auth/invalid-login-credentials":
    case "auth/wrong-password":
    case "auth/user-not-found":
      return "Wrong username or password.";
    case "auth/weak-password":
    case "auth/password-does-not-meet-requirements":
      return `Use at least ${MIN_PASSWORD} characters for the password.`;
    case "auth/too-many-requests":
      return "Too many attempts. Wait a minute, then try again.";
    case "auth/network-request-failed":
      return "Couldn’t reach the account service. Check your connection and try again.";
    case "auth/operation-not-allowed":
    case "auth/configuration-not-found":
      return "Accounts aren’t switched on for this site yet. Everything else works without one.";
    case "auth/user-disabled":
      return "This account has been disabled.";
    default:
      return "That didn’t work. Try again in a moment.";
  }
}
