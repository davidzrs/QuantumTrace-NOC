import { describe, expect, it } from "vitest";
import { MAX_CODE_BYTES, mergePicked, planIntake, type Picked } from "./intake";

const pick = (path: string, size = 10): Picked => ({ file: new File(["x".repeat(size)], path), path });

describe("planIntake", () => {
  it("sends only what a scanner reads, keeping folder paths", () => {
    const plan = planIntake([
      pick("repo/src/auth.py"),
      pick("repo/src/Cipher.java"),
      pick("repo/cmd/main.go"),
      pick("repo/infra/kms.json"),
      pick("repo/README.md"),
      pick("repo/logo.png"),
      pick("repo/web/app.ts"),
      pick("repo/web/other.ts"),
    ]);
    expect(plan.send.map((p) => p.path)).toEqual([
      "repo/src/auth.py",
      "repo/src/Cipher.java",
      "repo/cmd/main.go",
      "repo/infra/kms.json",
    ]);
    expect(plan.counts).toEqual({ code: 3, cloud: 1, capture: 0, archive: 0 });
    expect(plan.skipped.total).toBe(4);
    expect(plan.skipped.byExt[0]).toEqual([".ts", 2]);
    expect(plan.roots).toEqual(["repo/"]);
  });

  it("leaves out dependency folders, lockfiles and oversized source", () => {
    const plan = planIntake(
      [
        pick("repo/node_modules/lib/index.py"),
        pick("repo/.git/config.json"),
        pick("repo/package-lock.json"),
        pick("repo/gen/huge.py", MAX_CODE_BYTES + 1),
        pick("repo/app.py"),
      ],
      ["vendor-cache"],
    );
    expect(plan.send.map((p) => p.path)).toEqual(["repo/app.py"]);
    expect(plan.skipped.dirs).toEqual([".git", "node_modules", "vendor-cache"]);
    expect(plan.skipped.oversized).toBe(1);
    expect(plan.skipped.total).toBe(4);
  });

  it("names loose files and folders as the roots", () => {
    const plan = planIntake([pick("capture.pcap"), pick("repo/a.go"), pick("posture.zip")]);
    expect(plan.roots).toEqual(["capture.pcap", "repo/", "posture.zip"]);
    expect(plan.counts).toEqual({ code: 1, cloud: 0, capture: 1, archive: 1 });
    expect(plan.bytes).toBe(30);
  });
});

describe("mergePicked", () => {
  const f = (path: string) => ({ file: new File(["x"], path.split("/").pop()!), path });

  it("adds a zip to a folder pick and keeps one copy of repeats", () => {
    const merged = mergePicked([f("repo/a.py"), f("repo/b.go")], [f("captures.zip"), f("repo/a.py")]);
    expect(merged.map((p) => p.path)).toEqual(["captures.zip", "repo/a.py", "repo/b.go"]);
  });
});
