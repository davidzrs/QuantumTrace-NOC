import { describe, expect, it } from "vitest";
import { targetFromUrl } from "./target";

describe("targetFromUrl", () => {
  it("probes HTTPS pages on 443 by default", () => {
    expect(targetFromUrl("https://github.com/org/repo?x=1")).toEqual({
      kind: "probe",
      host: "github.com",
      port: 443,
      key: "github.com:443",
    });
  });

  it("keeps an explicit port", () => {
    expect(targetFromUrl("https://example.com:8443/")).toMatchObject({ port: 8443 });
  });

  it("strips IPv6 brackets", () => {
    expect(targetFromUrl("https://[2606:4700::1]/")).toMatchObject({ host: "2606:4700::1" });
  });

  it("reports plain HTTP as cleartext", () => {
    expect(targetFromUrl("http://neverssl.com/")).toEqual({ kind: "cleartext", host: "neverssl.com" });
  });

  it.each([undefined, "", "chrome://extensions", "file:///tmp/a.html", "not a url"])(
    "can't check %s",
    (url) => expect(targetFromUrl(url)).toEqual({ kind: "unsupported" }),
  );
});
