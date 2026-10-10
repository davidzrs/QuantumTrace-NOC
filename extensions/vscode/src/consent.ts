/** Whether the user allowed their code to be sent to an API, remembered per API address. */
import type { Store } from "./dismissals";

const STATE_KEY = "quantumtrace.apiConsent";

type Answer = "granted" | "declined";

/** Scheme, host and port: consent for one API says nothing about another. */
export function originOf(apiUrl: string): string {
  try {
    return new URL(apiUrl).origin;
  } catch {
    return apiUrl;
  }
}

export class ApiConsent {
  constructor(private readonly store: Store) {}

  private get answers(): Record<string, Answer> {
    return this.store.get<Record<string, Answer>>(STATE_KEY, {});
  }

  /** True or false once the user has answered for this API; undefined while they have not. */
  answerFor(apiUrl: string): boolean | undefined {
    const answer = this.answers[originOf(apiUrl)];
    return answer === undefined ? undefined : answer === "granted";
  }

  record(apiUrl: string, granted: boolean): PromiseLike<void> {
    return this.store.update(STATE_KEY, {
      ...this.answers,
      [originOf(apiUrl)]: granted ? "granted" : "declined",
    });
  }
}
