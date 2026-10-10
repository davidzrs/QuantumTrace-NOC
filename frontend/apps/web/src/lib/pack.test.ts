// @vitest-environment node
// Real File.stream() and CompressionStream: jsdom has neither.
import { describe, expect, it } from "vitest";
import { gzipItem, pack, UploadTooLarge } from "./pack";

const item = (path: string, body: string) => ({ file: new File([body], path.split("/").pop()!), path });

async function gunzip(file: File): Promise<string> {
  const stream = file.stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}

describe("pack", () => {
  it("gzips files and appends .gz to their path", async () => {
    const source = "import hashlib\n".repeat(5000);
    const out = await gzipItem(item("repo/src/app.py", source));
    expect(out.path).toBe("repo/src/app.py.gz");
    expect(out.file.name).toBe("app.py.gz");
    expect(out.file.size).toBeLessThan(source.length / 10);
    expect(await gunzip(out.file)).toBe(source);
  });

  it("leaves zips alone", async () => {
    const zip = item("bundle.zip", "PK\u0003\u0004");
    expect(await gzipItem(zip)).toBe(zip);
  });

  it("refuses when even the compressed upload is too big", async () => {
    const random = Array.from({ length: 4000 }, () => Math.random().toString(36)).join("");
    await expect(pack([item("a.py", random)], 1024)).rejects.toBeInstanceOf(UploadTooLarge);
    await expect(pack([item("a.py", "x".repeat(100_000))], 1024)).resolves.toHaveLength(1);
  });
});
