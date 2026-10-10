/**
 * @quantumtrace/sdk — the only way TypeScript clients (web, VS Code, browser extension)
 * talk to the QuantumTrace API. Types are generated from the backend OpenAPI spec:
 * run `make gen-sdk` after changing any API route or model.
 */
import createFetchClient from "openapi-fetch";
import type { components, paths } from "./schema";

export type { components, paths };
type Schemas = components["schemas"];
export type ScanResult = Schemas["ScanResult"];
export type ScanSummary = Schemas["ScanSummary"];
export type Finding = Schemas["Finding"];
export type CryptoAsset = Schemas["CryptoAsset"];
export type Classification = Schemas["Classification"];
export type RiskTier = Schemas["RiskTier"];
export type RiskScore = Schemas["RiskScore"];
export type Rule = Schemas["Rule"];
export type Sample = Schemas["Sample"];
export type ScanNote = Schemas["ScanNote"];
export type Observation = Schemas["Observation"];
export type Confidence = Schemas["Confidence"];

/** A file and its path inside the folder it came from. */
export interface UploadItem {
  file: File;
  path: string;
}

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: typeof fetch;
}

export class QuantumTraceError extends Error {
  constructor(
    readonly status: number,
    readonly detail: unknown,
  ) {
    super(typeof detail === "string" ? detail : `QuantumTrace API error ${status}`);
  }
}

export function createClient({ baseUrl, apiKey, fetch: fetchImpl }: ClientOptions) {
  const http = createFetchClient<paths>({
    baseUrl: baseUrl.replace(/\/$/, ""),
    headers: apiKey ? { "X-API-Key": apiKey } : undefined,
    fetch: fetchImpl,
  });

  async function unwrap<T>(
    p: Promise<{ data?: T; error?: unknown; response: Response }>,
  ): Promise<T> {
    const { data, error, response } = await p;
    if (error !== undefined || data === undefined) {
      const detail = (error as { detail?: unknown } | undefined)?.detail ?? error;
      throw new QuantumTraceError(response.status, detail);
    }
    return data;
  }

  return {
    http,
    health: () => unwrap(http.GET("/api/v1/health")),
    rules: () => unwrap(http.GET("/api/v1/rules")),
    samples: () => unwrap(http.GET("/api/v1/samples")),
    /** Summaries of the given scans. The API never lists other people's scans. */
    listScans: (ids: string[]) =>
      unwrap(http.GET("/api/v1/scans", { params: { query: { ids } } })),
    getScan: (scanId: string) =>
      unwrap(http.GET("/api/v1/scans/{scan_id}", { params: { path: { scan_id: scanId } } })),
    /** Delete a scan and its report. Succeeds if it is already gone. */
    deleteScan: async (scanId: string): Promise<void> => {
      const { error, response } = await http.DELETE("/api/v1/scans/{scan_id}", {
        params: { path: { scan_id: scanId } },
      });
      if (!response.ok) {
        const detail = (error as { detail?: unknown } | undefined)?.detail ?? error;
        throw new QuantumTraceError(response.status, detail);
      }
    },
    getCbom: (scanId: string) =>
      unwrap(
        http.GET("/api/v1/scans/{scan_id}/cbom", { params: { path: { scan_id: scanId } } }),
      ),
    scanSample: (sample: string) =>
      unwrap(http.POST("/api/v1/scans/sample", { body: { sample } })),
    /** Handshake with a live host from the API and classify what it negotiates. */
    probeTls: (host: string, port = 443) =>
      unwrap(http.POST("/api/v1/probes/tls", { body: { host, port } })),
    /**
     * Scan a public GitHub repository by URL: the API downloads it, so nothing is uploaded.
     * Also takes a branch, tag, commit or folder (`https://github.com/owner/repo/tree/main/src`).
     */
    scanGithub: (url: string) =>
      unwrap(http.POST("/api/v1/scans/github", { body: { url } })),
    /**
     * Upload files, folders or .zip archives. Pass `{ file, path }` to keep a file's place in a
     * folder (`repo/src/auth.py`): evidence then points at that path. The API takes at most
     * 1000 files per scan. Uses raw fetch because of multipart bodies.
     */
    scanFiles: async (files: Array<File | UploadItem>): Promise<ScanResult> => {
      const form = new FormData();
      for (const f of files) {
        if (f instanceof File) form.append("files", f, f.name);
        else form.append("files", f.file, f.path);
      }
      const res = await (fetchImpl ?? fetch)(`${baseUrl.replace(/\/$/, "")}/api/v1/scans`, {
        method: "POST",
        body: form,
        headers: apiKey ? { "X-API-Key": apiKey } : undefined,
      });
      const body: unknown = await res.json().catch(() => undefined);
      if (!res.ok) {
        throw new QuantumTraceError(res.status, (body as { detail?: unknown })?.detail ?? body);
      }
      return body as ScanResult;
    },
  };
}

export type QuantumTraceClient = ReturnType<typeof createClient>;
