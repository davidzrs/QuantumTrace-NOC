import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { api, API_URL } from "../lib/api";

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

const STATE = {
  online: { word: "Online", title: "Scanner online", dot: "bg-safe shadow-[0_0_0_4px_rgba(67,209,177,0.15)]" },
  offline: { word: "Offline", title: "Scanner unreachable", dot: "bg-critical shadow-[0_0_0_4px_rgba(255,93,82,0.15)]" },
  checking: { word: "Connecting", title: "Connecting to the scanner", dot: "bg-rule-strong" },
} as const;

/**
 * The header's scanner status: a dot and one word. Clicking it shows what the web app knows about
 * the API it talks to: where it is, what it allows, and why it can't be reached when it can't.
 */
export function ApiStatus() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0 });
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const state = STATE[health.isSuccess ? "online" : health.isError ? "offline" : "checking"];

  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => {
      if (e.target instanceof Node && !box.current?.contains(e.target)) setOpen(false);
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", away);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  const checkedAt = health.dataUpdatedAt || health.errorUpdatedAt;
  const h = health.data;

  return (
    <div ref={box} className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm text-ink-muted hover:bg-raise hover:text-ink aria-expanded:bg-raise aria-expanded:text-ink"
      >
        <span aria-hidden className={`size-2 rounded-full ${state.dot}`} />
        <span aria-live="polite">
          <span className="sr-only">Scanner </span>
          {state.word}
        </span>
      </button>
      {open && (
        <div
          id={panelId}
          role="region"
          aria-label="Scanner status"
          className="absolute top-full right-0 z-40 mt-2 grid w-[min(360px,calc(100vw-32px))] gap-3 rounded-xl border border-rule-strong bg-surface p-4 text-sm shadow-[0_16px_48px_rgba(0,0,0,0.5)]"
        >
          <div className="flex items-baseline justify-between gap-3">
            <span className="font-semibold text-ink">{state.title}</span>
            <button
              type="button"
              onClick={() => void health.refetch()}
              disabled={health.isFetching}
              className="link text-[13px] font-semibold text-ink-muted disabled:opacity-50"
            >
              {health.isFetching ? "Checking…" : "Check again"}
            </button>
          </div>
          {health.isError && (
            <p role="alert" className="border-l-2 border-critical pl-3 text-ink-soft">
              It didn’t answer: {health.error.message}. Scans, reports and history need it, so try again in a
              moment.
            </p>
          )}
          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 border-t border-rule pt-3">
            <Row label="Address">
              <span className="font-mono text-[12.5px] break-all">{API_URL}</span>
            </Row>
            {h && (
              <>
                <Row label="Version">v{h.version}</Row>
                <Row label="Reports">{h.persistent ? "Kept for 30 days" : "In memory, gone when it restarts"}</Row>
                <Row label="Fix code with AI">{h.ai_fix ? "On" : "Off, no Gemini key set"}</Row>
                <Row label="Uploads">
                  Up to {h.max_upload_mb} MB sent, {h.max_unpacked_mb} MB unpacked
                </Row>
                <Row label="GitHub repositories">Up to {h.max_repo_mb} MB</Row>
              </>
            )}
            {checkedAt > 0 && <Row label="Checked">{timeFmt.format(checkedAt)}</Row>}
          </dl>
        </div>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-ink-muted">{label}</dt>
      <dd className="text-ink-soft">{children}</dd>
    </>
  );
}
