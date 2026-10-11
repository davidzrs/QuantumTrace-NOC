import { describe, expect, it } from "vitest";
import { siteLabel, siteTarget } from "./site";

describe("website links", () => {
  it.each([
    ["https://example.com", "example.com", 443],
    ["https://Example.com/login?next=/", "example.com", 443],
    ["example.com", "example.com", 443],
    ["  www.example.com/path  ", "www.example.com", 443],
    ["example.com:8443", "example.com", 8443],
    ["https://example.com:8443/x", "example.com", 8443],
    // plain HTTP has no TLS: check where the site's HTTPS would answer
    ["http://example.com", "example.com", 443],
    ["http://example.com:8080", "example.com", 443],
    ["https://[2606:4700::1111]/", "2606:4700::1111", 443],
  ])("reads %j as %s:%i", (input, host, port) => {
    expect(siteTarget(input)).toEqual({ host, port });
  });

  it.each(["", "   ", "ftp://example.com", "https://exa mple.com", "https://"])("turns %j away with a reason", (input) => {
    expect(siteTarget(input)).toHaveProperty("problem", expect.stringContaining("https://example.com"));
  });

  it("labels a site without the default port", () => {
    expect(siteLabel({ host: "example.com", port: 443 })).toBe("example.com");
    expect(siteLabel({ host: "example.com", port: 8443 })).toBe("example.com:8443");
    expect(siteLabel({ host: "2606:4700::1111", port: 8443 })).toBe("[2606:4700::1111]:8443");
  });
});
