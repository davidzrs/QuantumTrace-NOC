import type { ScanResult } from "@quantumtrace/sdk";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { ScanBench } from "../components/ScanBench";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import { forget, readHistory, remember, writeHistory } from "../lib/history";

const READS = [
  { what: "Code", detail: "Library calls, key sizes, modes, hand-rolled primitives", files: ".py .java .go" },
  { what: "Cloud", detail: "AWS KMS keys, ACM certificates, load balancer TLS policies", files: ".json" },
  { what: "Network", detail: "TLS and SSH handshakes, including hybrid ML‑KEM", files: ".pcap .pcapng" },
];

const sampleLabel = (name: string) =>
  name === "all" ? "All of them" : name.charAt(0).toUpperCase() + name.slice(1).replace(/-/g, " ");

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
  // The deployed API has no samples (they sit outside its root), so this is often empty.
  const samples = useQuery({ queryKey: ["samples"], queryFn: api.samples, retry: 0 });

  const onScanned = (result: ScanResult) => {
    remember(result.id);
    queryClient.setQueryData(["scan", result.id], result);
    void queryClient.invalidateQueries({ queryKey: ["scans"] });
    void navigate(`/scans/${result.id}`);
  };
  const uploadScan = useMutation({ mutationFn: api.scanFiles, onSuccess: onScanned });
  const sampleScan = useMutation({ mutationFn: api.scanSample, onSuccess: onScanned });
  const scanning = uploadScan.isPending || sampleScan.isPending;
  const scanError = uploadScan.error ?? sampleScan.error;

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

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-16">
      <section className="grid gap-x-16 gap-y-10 lg:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)] lg:items-end">
        <div>
          <h1 className="max-w-[16ch] text-[2.6rem] leading-[1.03] font-extrabold tracking-[-0.03em] text-balance sm:text-[3.9rem]">
            Find the cryptography a quantum computer will break.
          </h1>
          <p className="mt-6 max-w-[56ch] text-lg leading-relaxed text-ink-muted">
            Point QuantumTrace at a codebase, cloud exports or a packet capture. It inventories
            every algorithm, ranks each by quantum risk, and maps it to its NIST post-quantum
            replacement, exportable as a CycloneDX&nbsp;1.6 CBOM.
          </p>
        </div>
        <dl className="grid grid-cols-[minmax(0,1fr)] border-t border-ink text-sm">
          {READS.map((r) => (
            <div key={r.what} className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-4 border-b border-rule py-3">
              <dt className="font-semibold">{r.what}</dt>
              <dd className="text-ink-muted">
                {r.detail}
                <span className="mt-0.5 block font-mono text-xs text-ink-faint">{r.files}</span>
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <section aria-labelledby="scan" className="grid grid-cols-[minmax(0,1fr)] gap-4">
        <h2 id="scan" className="text-2xl font-bold tracking-tight">
          Run a scan
        </h2>
        <ScanBench limitMb={health.data?.max_upload_mb} busy={scanning} onScan={(items) => uploadScan.mutate(items)} />
        {scanError && (
          <p role="alert" className="text-critical">
            The scan didn’t run: {scanError.message}. Check that the scanner is online and try again.
          </p>
        )}
        {!!samples.data?.length && (
          <div className="flex flex-wrap items-baseline gap-x-5 gap-y-2">
            <p className="text-ink-muted">No files to hand? Scan a sample:</p>
            {[...samples.data.map((s) => s.name), "all"].map((name) => (
              <button
                key={name}
                type="button"
                disabled={scanning}
                onClick={() => sampleScan.mutate(name)}
                className="font-semibold underline decoration-rule-strong underline-offset-4 hover:decoration-ink disabled:opacity-50"
              >
                {sampleScan.isPending && sampleScan.variables === name ? "Scanning…" : sampleLabel(name)}
              </button>
            ))}
          </div>
        )}
      </section>

      <section aria-labelledby="history" className="grid grid-cols-[minmax(0,1fr)] gap-4">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="history" className="text-2xl font-bold tracking-tight">
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
