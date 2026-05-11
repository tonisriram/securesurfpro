import { describe, it, expect } from "vitest";
import { analyzeUrl, computeThreatScore, generateScanResult } from "../lib/heuristics";

describe("URL Scanner", () => {
  describe("analyzeUrl", () => {
    it("should detect HTTPS enabled for secure URLs", async () => {
      const results = await analyzeUrl("https://google.com");
      const httpsCheck = results.find(r => r.name === "HTTPS Enabled");
      expect(httpsCheck).toBeDefined();
      expect(httpsCheck?.severity).toBe("safe");
    }, 10000);

    it("should detect no HTTPS for insecure URLs", async () => {
      const results = await analyzeUrl("http://example.com");
      const httpsCheck = results.find(r => r.name === "No HTTPS");
      expect(httpsCheck).toBeDefined();
      expect(httpsCheck?.severity).toBe("danger");
    }, 10000);

    it("should detect IP-based URLs as dangerous", async () => {
      const results = await analyzeUrl("http://192.168.1.1/login");
      const ipCheck = results.find(r => r.name === "IP-Based URL");
      expect(ipCheck).toBeDefined();
      expect(ipCheck?.severity).toBe("danger");
    }, 10000);

    it("should detect phishing keywords", async () => {
      // Test with a clearly fake phishing URL that contains multiple suspicious keywords
      const results = await analyzeUrl("http://paypal-login-secure-verify-account.com/update");
      const phishingCheck = results.find(r => r.name === "Phishing Keywords");
      expect(phishingCheck).toBeDefined();
      expect(phishingCheck?.severity).toBe("danger");
    }, 15000); // Longer timeout for network checks

    it("should recognize known safe domains", async () => {
      const results = await analyzeUrl("https://github.com/user/repo");
      const safeCheck = results.find(r => r.name === "Known Domain");
      expect(safeCheck).toBeDefined();
      expect(safeCheck?.severity).toBe("safe");
    }, 10000);
  });

  describe("computeThreatScore", () => {
    it("should calculate threat score correctly", () => {
      const heuristics = [
        { name: "Test 1", description: "", severity: "danger" as const, score: 20 },
        { name: "Test 2", description: "", severity: "warning" as const, score: 10 },
        { name: "Test 3", description: "", severity: "safe" as const, score: -5 },
      ];
      const score = computeThreatScore(heuristics);
      expect(score).toBe(45); // 20 (base) + 20 + 10 - 5 = 45
    });

    it("should clamp score between 0 and 100", () => {
      const highScore = [
        { name: "High", description: "", severity: "danger" as const, score: 200 },
      ];
      const lowScore = [
        { name: "Low", description: "", severity: "safe" as const, score: -100 },
      ];
      expect(computeThreatScore(highScore)).toBe(100);
      expect(computeThreatScore(lowScore)).toBe(0);
    });
  });

  describe("generateScanResult", () => {
    it("should generate a complete scan result", async () => {
      const result = await generateScanResult("https://google.com");
      expect(result).toHaveProperty("url", "https://google.com");
      expect(result).toHaveProperty("threatScore");
      expect(result).toHaveProperty("status");
      expect(result).toHaveProperty("heuristics");
      expect(result).toHaveProperty("aiExplanation");
      expect(result).toHaveProperty("domainInfo");
      expect(result).toHaveProperty("httpsInfo");
      expect(result).toHaveProperty("apiIntel");
      expect(result).toHaveProperty("timestamp");
    }, 10000);

    it("should classify safe URLs correctly", async () => {
      const result = await generateScanResult("https://google.com");
      // Google should have a relatively low threat score due to being a known safe domain
      expect(result.threatScore).toBeLessThan(50);
      // Status could be safe or warning depending on network checks
      expect(["safe", "warning"]).toContain(result.status);
    }, 10000);

    it("should classify dangerous URLs correctly", async () => {
      const result = await generateScanResult("http://192.168.1.1/login/verify");
      expect(result.threatScore).toBeGreaterThan(50); // Should be dangerous due to IP + phishing keywords
      // The status depends on the exact score, but it should be at least warning
      expect(["warning", "danger"]).toContain(result.status);
    }, 10000);
  });
});
