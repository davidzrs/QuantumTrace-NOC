import type { ScanResult } from "@quantumtrace/sdk";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { UploadZone } from "../components/UploadZone";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";

/** The three ingestion vectors from the brief. */
const SOURCES = [
  {
    sample: "cloud-posture",
    title: "Cloud posture",
    body: "AWS KMS keys, ACM certificates and load balancer TLS policies.",
    status: "Ready",
  },
  {
    sample: "sample-repos",
    title: "Source code",
    body: "Python, Java and Go: key generation, signatures, ciphers, digests and misuse such as ECB or weak randomness.",
    status: "Ready",
  },
  {
    sample: "network-capture",
    title: "Network capture",
    body: "TLS and SSH handshakes in .pcap files on any port, including STARTTLS, plus cleartext protocols.",
    status: "Ready",
  },
] as const;

export function Home() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const scans = useQuery({ queryKey: ["scans"], queryFn: () => api.listScans() });

  const onDone = (result: ScanResult) => {
    queryClient.setQueryData(["scan", result.id], result);
    void queryClient.invalidateQueries({ queryKey: ["scans"] });
    void navigate(`/scans/${result.id}`);
  };
  const sampleScan = useMutation({ mutationFn: api.scanSample, onSuccess: onDone });
  const uploadScan = useMutation({ mutationFn: api.scanFiles, onSuccess: onDone });
  const busy = sampleScan.isPending || uploadScan.isPending;
  const error = sampleScan.error ?? uploadScan.error;

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

      <section aria-labelledby="sources" className="grid grid-cols-[minmax(0,1fr)] gap-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="sources" className="text-xl font-bold">
            Scan the challenge data
          </h2>
          <button
            type="button"
            disabled={busy}
            onClick={() => sampleScan.mutate("all")}
            className="font-semibold underline decoration-rule-strong underline-offset-4 hover:decoration-ink disabled:opacity-50"
          >
            Scan everything at once
          </button>
        </div>
        <ul className="divide-y divide-rule border-y border-rule">
          {SOURCES.map((s) => (
            <li key={s.sample} className="grid gap-3 py-5 sm:grid-cols-[14rem_1fr_auto] sm:items-center sm:gap-8">
              <div>
                <h3 className="font-bold">{s.title}</h3>
                <p className={`text-sm ${s.status === "Ready" ? "text-safe" : "text-ink-faint"}`}>{s.status}</p>
              </div>
              <p className="max-w-[56ch] text-ink-muted">{s.body}</p>
              <button
                type="button"
                disabled={busy}
                onClick={() => sampleScan.mutate(s.sample)}
                className="justify-self-start bg-ink px-4 py-2 font-semibold text-ground hover:opacity-90 disabled:opacity-50 sm:justify-self-end"
              >
                {sampleScan.isPending && sampleScan.variables === s.sample ? "Scanning…" : "Scan sample"}
              </button>
            </li>
          ))}
        </ul>
        <UploadZone disabled={busy} onFiles={(files) => uploadScan.mutate(files)} />
        {error && (
          <p role="alert" className="text-critical">
            The scan didn’t run: {error.message}. Check that the API is reachable and try again.
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
              : "Nothing yet. Scan a sample above to see a report; history lives in memory until the API restarts."}
          </p>
        )}
      </section>
    </div>
  );
}
