import { useId, useRef, useState } from "react";

export function UploadZone({
  onFiles,
  disabled,
}: {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
}) {
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
        if (!disabled && e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]);
      }}
      className={`flex flex-col items-start gap-3 border border-dashed px-5 py-6 transition-colors sm:flex-row sm:items-center sm:justify-between ${
        dragging ? "border-ink bg-surface" : "border-rule-strong"
      }`}
    >
      <p id={hintId} className="max-w-prose text-ink-muted">
        Drop your own exports, code or captures here. Zip archives are unpacked; nothing is kept
        after the scan.
      </p>
      <button
        type="button"
        disabled={disabled}
        aria-describedby={hintId}
        onClick={() => input.current?.click()}
        className="shrink-0 border border-ink px-4 py-2 font-semibold hover:bg-ink hover:text-ground disabled:opacity-50"
      >
        Choose files
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
