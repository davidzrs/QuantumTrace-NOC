import type { ScanResult } from "@quantumtrace/sdk";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { UploadZone } from "../components/UploadZone";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import { forget, readHistory, remember, writeHistory } from "../lib/history";

const MB = 1024 * 1024;

export function Home() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => {
      const ids = readHistory();
      if (!ids.length) return [];
      const found = await api.listScans(ids);
      // Forget scans the API no longer has (they expire after 7 days).
      writeHistory(found.map((s) => s.id));
      return found;
    },
  });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0 });
  const [tooLarge, setTooLarge] = useState<string | null>(null);

  const uploadScan = useMutation({
    mutationFn: api.scanFiles,
    onSuccess: (result: ScanResult) => {
      remember(result.id);
      queryClient.setQueryData(["scan", result.id], result);
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void navigate(`/scans/${result.id}`);
    },
  });

  const deleteScans = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => api.deleteScan(id)));
      const deleted = ids.filter((_, i) => results[i]?.status === "fulfilled");
      forget(deleted);
      for (const id of deleted) queryClient.removeQueries({ queryKey: ["scan", id] });
      if (deleted.length < ids.length) {
        throw new Error(`${ids.length - deleted.length} of ${ids.length} scans couldn’t be deleted`);
      }
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });
  const deleteAll = () => {
    const ids = scans.data?.map((s) => s.id) ?? [];
    const n = ids.length;
    const prompt =
      n === 1
        ? "Delete this scan? Its report and link stop working."
        : `Delete all ${n} scans? Their reports and links stop working.`;
    if (n && window.confirm(prompt)) {
      deleteScans.mutate(ids);
    }
  };

  // Check the size here: a host that rejects the body before the API sees it (Vercel caps
  // requests at 4.5 MB) answers without CORS headers, which the browser reports as a network error.
  const onFiles = (files: File[]) => {
    const limit = health.data?.max_upload_mb;
    const total = files.reduce((n, f) => n + f.size, 0);
    if (limit && total > limit * MB) {
      setTooLarge(
        `These files add up to ${(total / MB).toFixed(1)} MB and this scanner takes up to ${limit} MB per scan. Zip them or scan fewer at a time.`,
      );
      return;
    }
    setTooLarge(null);
    uploadScan.mutate(files);
  };

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-16">
      <section className="max-w-3xl">
        <h1 className="text-4xl leading-[1.08] font-extrabold tracking-[-0.025em] text-balance sm:text-6xl">
          Find the cryptography a quantum computer will break.
        </h1>
        <p className="mt-5 max-w-[62ch] text-lg leading-relaxed text-ink-muted">
          QuantumTrace inventories every algorithm in your cloud exports, code and packet captures,
          ranks each one by quantum risk, and maps it to its NIST post-quantum replacement. The
          result exports as a CycloneDX&nbsp;1.6 CBOM.
        </p>
      </section>

      <section aria-labelledby="scan" className="grid grid-cols-[minmax(0,1fr)] gap-4">
        <h2 id="scan" className="text-xl font-bold">
          Scan your files
        </h2>
        <UploadZone busy={uploadScan.isPending} onFiles={onFiles} />
        {tooLarge && (
          <p role="alert" className="text-critical">
            {tooLarge}
          </p>
        )}
        {uploadScan.error && (
          <p role="alert" className="text-critical">
            The scan didn’t run: {uploadScan.error.message}. Check that the scanner is online and try again.
          </p>
        )}
      </section>

      <section aria-labelledby="history" className="grid grid-cols-[minmax(0,1fr)] gap-4">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="history" className="text-xl font-bold">
            Your scans
          </h2>
          {!!scans.data?.length && (
            <button
              type="button"
              onClick={deleteAll}
              disabled={deleteScans.isPending}
              className="font-semibold underline decoration-rule-strong underline-offset-4 hover:decoration-ink disabled:opacity-50"
            >
              Delete all
            </button>
          )}
        </div>
        {deleteScans.error && (
          <p role="alert" className="text-critical">
            {deleteScans.error.message}. Check that the scanner is online and try again.
          </p>
        )}
        {scans.data?.length ? (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[36rem] text-left">
              <thead className="text-sm text-ink-muted">
                <tr className="border-b border-rule-strong">
                  <th className="py-2 pr-4 font-medium">Ran</th>
                  <th className="py-2 pr-4 font-medium">Scanned</th>
                  <th className="py-2 pr-4 text-right font-medium">Findings</th>
                  <th className="py-2 pr-4 text-right font-medium">Shor-exposed</th>
                  <th className="py-2 pr-4 text-right font-medium">Risk score</th>
                  <th className="w-px py-2"><span className="sr-only">Delete</span></th>
                </tr>
              </thead>
              <tbody>
                {scans.data.map((s) => (
                  <tr key={s.id} className="border-b border-rule hover:bg-surface">
                    <td className="py-2.5 pr-4 whitespace-nowrap">
                      <Link to={`/scans/${s.id}`} className="font-semibold underline decoration-rule-strong underline-offset-4 hover:decoration-ink">
                        {formatDate(s.created_at)}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-sm text-ink-muted">{s.targets.join(", ")}</td>
                    <td className="py-2.5 pr-4 text-right">{s.findings}</td>
                    <td className="py-2.5 pr-4 text-right text-critical">{s.score.counts.critical}</td>
                    <td className="py-2.5 pr-4 text-right">{s.score.value}</td>
                    <td className="py-1.5 text-right">
                      <button
                        type="button"
                        onClick={() => deleteScans.mutate([s.id])}
                        disabled={deleteScans.isPending}
                        aria-label={`Delete the scan from ${formatDate(s.created_at)}`}
                        className="px-2 py-1 text-sm font-semibold text-ink-muted hover:text-critical disabled:opacity-50"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-ink-muted">
            {scans.isError
              ? "Scan history is unavailable while the scanner is offline."
              : "Nothing yet. Scans you run in this browser show up here, and only here."}
          </p>
        )}
      </section>
    </div>
  );
}
