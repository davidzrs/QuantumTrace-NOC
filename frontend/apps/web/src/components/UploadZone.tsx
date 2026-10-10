import { useId, useRef, useState } from "react";

export function UploadZone({ onFiles, busy }: { onFiles: (files: File[]) => void; busy?: boolean }) {
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const hintId = useId();

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (!busy && e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]);
      }}
      aria-busy={busy}
      className={`grid justify-items-start gap-5 border border-dashed px-6 py-10 transition-colors sm:px-10 sm:py-14 ${
        dragging ? "border-ink bg-surface" : "border-rule-strong"
      }`}
    >
      <div className="grid gap-2">
        <p className="text-lg font-semibold">
          {busy ? "Scanning…" : dragging ? "Drop to scan" : "Drop files here, or choose them"}
        </p>
        <p id={hintId} className="max-w-[62ch] text-ink-muted">
          AWS exports (KMS, ACM, load balancer policies), Python, Java and Go source, and .pcap
          captures. Zip archives are unpacked. Nothing is kept except the report.
        </p>
      </div>
      <button
        type="button"
        disabled={busy}
        aria-describedby={hintId}
        onClick={() => input.current?.click()}
        className="bg-ink px-4 py-2 font-semibold text-ground hover:opacity-90 disabled:opacity-50"
      >
        {busy ? "Scanning…" : "Choose files"}
      </button>
      <input
        ref={input}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          if (e.target.files?.length) onFiles([...e.target.files]);
          e.target.value = "";
        }}
      />
    </div>
  );
}
