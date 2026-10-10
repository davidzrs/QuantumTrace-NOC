import type { ScanResult } from "@quantumtrace/sdk";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { UploadZone } from "../components/UploadZone";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";

const MB = 1024 * 1024;

export function Home() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const scans = useQuery({ queryKey: ["scans"], queryFn: () => api.listScans() });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, retry: 0 });
  const [tooLarge, setTooLarge] = useState<string | null>(null);

  const uploadScan = useMutation({
    mutationFn: api.scanFiles,
    onSuccess: (result: ScanResult) => {
      queryClient.setQueryData(["scan", result.id], result);
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void navigate(`/scans/${result.id}`);
    },
  });

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
        <h2 id="history" className="text-xl font-bold">
          Earlier scans
        </h2>
        {scans.data?.length ? (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[36rem] text-left">
              <thead className="text-sm text-ink-muted">
                <tr className="border-b border-rule-strong">
                  <th className="py-2 pr-4 font-medium">Ran</th>
                  <th className="py-2 pr-4 font-medium">Scanned</th>
                  <th className="py-2 pr-4 text-right font-medium">Findings</th>
                  <th className="py-2 pr-4 text-right font-medium">Shor-exposed</th>
                  <th className="py-2 text-right font-medium">Risk score</th>
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
                    <td className="py-2.5 text-right">{s.score.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-ink-muted">
            {scans.isError
              ? "Scan history is unavailable while the scanner is offline."
              : health.data?.persistent
                ? "Nothing yet. Drop files above to see a report; scans are kept for 7 days."
                : "Nothing yet. Drop files above to see a report; history lives in memory until the scanner restarts."}
          </p>
        )}
      </section>
    </div>
  );
}
