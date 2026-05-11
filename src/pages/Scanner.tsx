import { useState, useEffect, useRef, useCallback } from "react";
import { Search, Shield, Globe, Lock, AlertTriangle, CheckCircle, XCircle, Brain, Server, FileText, Download, Sparkles, Clock, Zap } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import ThreatGauge from "@/components/ThreatGauge";
import ScoreBreakdown from "@/components/ScoreBreakdown";
import { generateScanResult, type ScanResult } from "@/lib/heuristics";
import { generateScanReport } from "@/lib/generateReport";
import { supabase } from "@/integrations/supabase/client";

const demoUrls = [
  { url: "https://google.com", label: "Safe" },
  { url: "http://192.168.1.1/login/verify-account", label: "Suspicious" },
  { url: "http://paypal-secure-login.suspicious-site.com/verify", label: "Dangerous" },
];

// Validate URL format
function isValidUrl(urlString: string): boolean {
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

// Debounce hook for real-time scanning
function useDebounce<T>(value: T, delay: number) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const handler = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(handler);
  }, [value, delay]);
  return debouncedValue;
}

type VirusTotalScan = NonNullable<ScanResult["virus_total"]>;

const VIRUSTOTAL_API_KEY = import.meta.env.VITE_VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_API_BASE = "/vtapi";

function toBase64Url(input: string) {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function virusTotalFetch(path: string, init: RequestInit = {}) {
  if (!VIRUSTOTAL_API_KEY) throw new Error("Missing VITE_VIRUSTOTAL_API_KEY in .env");

  const res = await fetch(`${VIRUSTOTAL_API_BASE}${path}`, {
    ...init,
    headers: {
      "x-apikey": VIRUSTOTAL_API_KEY,
      ...(init.headers ?? {}),
    },
  });

  if (res.status === 429) throw new Error("VirusTotal rate limit reached. Wait a minute and scan again.");
  return res;
}

function parseVirusTotal(data: any, source: "url" | "analysis", submitted = false): VirusTotalScan {
  const attrs = data?.data?.attributes ?? {};
  const stats = source === "analysis" ? attrs.stats ?? {} : attrs.last_analysis_stats ?? {};
  const results = source === "analysis" ? attrs.results ?? {} : attrs.last_analysis_results ?? {};

  return {
    checked: true,
    found: true,
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    engines: Object.entries(results)
      .filter(([, result]: any) => result?.category === "malicious" || result?.category === "suspicious")
      .map(([name]) => name)
      .slice(0, 10),
    submitted,
  };
}

async function fetchVirusTotalScan(url: string, signal?: AbortSignal): Promise<VirusTotalScan> {
  if (import.meta.env.PROD) {
    const res = await fetch("/api/virustotal-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal,
    });

    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error(data?.error ?? `VirusTotal scan failed with status ${res.status}`);
    return data.virus_total;
  }

  const lookupRes = await virusTotalFetch(`/urls/${toBase64Url(url)}`, { signal });

  if (lookupRes.ok) return parseVirusTotal(await lookupRes.json(), "url");
  if (lookupRes.status !== 404) throw new Error(`VirusTotal lookup failed with status ${lookupRes.status}`);

  const submitRes = await virusTotalFetch("/urls", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `url=${encodeURIComponent(url)}`,
    signal,
  });

  if (!submitRes.ok) throw new Error(`VirusTotal submit failed with status ${submitRes.status}`);

  const analysisId = (await submitRes.json())?.data?.id;
  if (!analysisId) {
    return { checked: true, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, engines: [], submitted: true };
  }

  for (let attempt = 0; attempt < 4; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, attempt === 0 ? 1200 : 1800));
    const analysisRes = await virusTotalFetch(`/analyses/${analysisId}`, { signal });
    if (!analysisRes.ok) continue;

    const analysisData = await analysisRes.json();
    if (analysisData?.data?.attributes?.status !== "completed") continue;
    return parseVirusTotal(analysisData, "analysis", true);
  }

  return { checked: true, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, engines: [], submitted: true };
}

function scoreVirusTotal(vt: VirusTotalScan) {
  const detections = vt.malicious + vt.suspicious;
  if (!vt.found) return 35;
  if (detections >= 2) return 100;
  if (detections === 1) return 55;
  return 0;
}

function categoryForVirusTotal(vt: VirusTotalScan): "safe" | "phishing" | "malware" | "suspicious" {
  if (!vt.found) return "suspicious";
  if (vt.malicious > 0) return "malware";
  if (vt.suspicious > 0) return "suspicious";
  return "safe";
}

function recommendationFor(status: string) {
  if (status === "safe") return "Safe to visit - no VirusTotal detections.";
  if (status === "warning") return "Proceed with caution - VirusTotal has limited or suspicious evidence.";
  return "Block immediately - VirusTotal security engines detected risk.";
}

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [meta, setMeta] = useState<{ confidence?: number; cached?: boolean; breakdown?: Array<{ source: string; score: number; weight: number; available: boolean; contribution: number }> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [showRealTimeHint, setShowRealTimeHint] = useState(false);
  const debouncedUrl = useDebounce(url, 1500); // Debounce input by 1.5s
  const abortControllerRef = useRef<AbortController | null>(null);
  const scanHistoryRef = useRef<Map<string, { result: ScanResult; meta: any; timestamp: number }>>(new Map());
  const MAX_RETRIES = 3;
  const RETRY_DELAY = 1000; // exponential backoff starts at 1s

  // Auto-scan on URL change (debounced)
  useEffect(() => {
    if (!debouncedUrl.trim() || !isValidUrl(debouncedUrl)) {
      return;
    }
    // Auto-trigger scan for valid URLs typed
    handleScan(debouncedUrl, true);
  }, [debouncedUrl]);

  // Retry with exponential backoff
  const retryWithBackoff = async (
    fn: () => Promise<any>,
    attempt: number = 0
  ): Promise<any> => {
    try {
      return await fn();
    } catch (err: any) {
      if (attempt < MAX_RETRIES && (err?.status === 503 || err?.message?.includes("timeout"))) {
        const delay = RETRY_DELAY * Math.pow(2, attempt);
        console.log(`Retry attempt ${attempt + 1}/${MAX_RETRIES} after ${delay}ms`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        return retryWithBackoff(fn, attempt + 1);
      }
      throw err;
    }
  };

  const handleScan = useCallback(
    async (targetUrl?: string, isAutoScan: boolean = false) => {
      const scanUrl = targetUrl || url;
      if (!scanUrl.trim()) return;

      // Check cache first
      const cached = scanHistoryRef.current.get(scanUrl);
      if (isAutoScan && cached && Date.now() - cached.timestamp < 300000) { // 5 min cache for auto-scan only
        setResult(cached.result);
        setMeta(cached.meta);
        setError(null);
        setShowRealTimeHint(false);
        return;
      }

      if (!isValidUrl(scanUrl)) {
        setError("Invalid URL format");
        setResult(null);
        return;
      }

      // Cancel previous request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      abortControllerRef.current = new AbortController();

      setError(null);
      setResult(null);
      setScanning(true);
      setRetryCount(0);

      // Show real-time hint for manual scans
      if (!isAutoScan) {
        setShowRealTimeHint(true);
        setTimeout(() => setShowRealTimeHint(false), 3000);
      }

      // Get heuristic result immediately (fast path)
      const baseResult = await generateScanResult(scanUrl);

      try {
        const responsePromise = retryWithBackoff(async () => {
          const controller = abortControllerRef.current;
          if (controller?.signal.aborted) throw new Error("Scan cancelled");

          const vt = await fetchVirusTotalScan(scanUrl, controller?.signal);
          const score = scoreVirusTotal(vt);
          const status = score < 30 ? "safe" : score < 60 ? "warning" : "danger";
          const category = categoryForVirusTotal(vt);
          const total = vt.malicious + vt.suspicious + vt.harmless + vt.undetected;
          return {
            score,
            status,
            category,
            explanation: vt.found
              ? `VirusTotal scanned this URL across ${total} engines. Results: ${vt.malicious} malicious, ${vt.suspicious} suspicious, ${vt.harmless} harmless, and ${vt.undetected} undetected.`
              : "VirusTotal accepted this URL for analysis, but a completed verdict is not available yet. Scan again in a moment for final engine results.",
            signals: [
              `VirusTotal: ${vt.malicious} malicious`,
              `VirusTotal: ${vt.suspicious} suspicious`,
              ...vt.engines.map((engine) => `VT: ${engine}`),
            ],
            confidence: vt.found ? 100 : 50,
            cached: false,
            breakdown: [{ source: "VirusTotal", score, weight: 1, available: true, contribution: score }],
            safe_browsing: { checked: false, listed: false, threats: [] },
            virus_total: vt,
          };
        });

        // Set timeout for edge function
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Scan timeout (>15s)")), 15000)
        );

        let data;
        try {
          data = await Promise.race([responsePromise, timeoutPromise]);
        } catch (timeoutErr) {
          throw timeoutErr;
        }

        // Merge AI assessment with heuristic data
        const recommendationFor = (status: string) =>
          status === "safe"
            ? "✅ Safe to visit — no threats detected."
            : status === "warning"
            ? "⚠️ Proceed with caution — avoid entering sensitive data."
            : "🚫 Block immediately — do not visit this website.";

        const merged: ScanResult = {
          ...baseResult,
          threatScore: data.score ?? baseResult.threatScore,
          status: data.status ?? baseResult.status,
          aiExplanation: data.explanation ?? baseResult.aiExplanation,
          aiRecommendation: recommendationFor(data.status ?? baseResult.status),
          apiIntel: {
            ...baseResult.apiIntel,
            virusTotal: {
              positives: (data.virus_total?.malicious ?? 0) + (data.virus_total?.suspicious ?? 0),
              total:
                (data.virus_total?.malicious ?? 0) +
                (data.virus_total?.suspicious ?? 0) +
                (data.virus_total?.harmless ?? 0) +
                (data.virus_total?.undetected ?? 0),
              detail: data.virus_total?.checked
                ? data.virus_total?.found
                  ? `${data.virus_total.malicious} malicious / ${data.virus_total.suspicious} suspicious`
                  : data.virus_total?.submitted
                  ? "Submitted for analysis"
                  : "Not in VirusTotal database"
                : baseResult.apiIntel.virusTotal.detail,
            },
          },
          safe_browsing: data.safe_browsing,
          virus_total: data.virus_total,
          cached: data.cached ?? false,
          timestamp: data.timestamp ?? baseResult.timestamp,
          heuristics: [
            ...baseResult.heuristics,
            ...(data.signals ?? []).map((s: string) => ({
              name: s,
              description: `AI-detected signal (${data.category})`,
              severity:
                data.status === "danger"
                  ? ("danger" as const)
                  : data.status === "warning"
                  ? ("warning" as const)
                  : ("safe" as const),
              score: 0,
            })),
          ],
        };

        setResult(merged);
        setMeta({ confidence: data.confidence, cached: data.cached, breakdown: data.breakdown });

        // Cache result
        scanHistoryRef.current.set(scanUrl, {
          result: merged,
          meta: { confidence: data.confidence, cached: data.cached, breakdown: data.breakdown },
          timestamp: Date.now(),
        });

        try {
          const { data: auth } = await supabase.auth.getUser();
          if (auth.user) {
            const { error: saveError } = await supabase.from("scan_history").insert({
              user_id: auth.user.id,
              url: scanUrl,
              score: merged.threatScore,
              status: merged.status,
              category: data.category ?? null,
              explanation: merged.aiExplanation,
              ai_used: false,
              signals: {
                source: "virustotal",
                signals: data.signals ?? [],
                virus_total: data.virus_total,
                safe_browsing: data.safe_browsing,
                confidence: data.confidence,
                breakdown: data.breakdown,
                cached: data.cached,
                timestamp: merged.timestamp,
              } as any,
            });

            if (saveError) {
              console.warn("Could not save scan to Supabase", saveError.message);
            }
          }
        } catch (saveErr) {
          console.warn("Could not save scan to Supabase", saveErr);
        }

      } catch (err: any) {
        if (err?.message === "Scan cancelled") {
          console.log("Scan cancelled by user");
          return;
        }

        console.error("Scan failed:", err);
        setError(err?.message ?? "VirusTotal scan failed");
        setResult(null);
        setMeta(null);

        toast.error("VirusTotal scan failed", {
          description: err?.message ?? "No accurate API result is available",
        });
      } finally {
        setScanning(false);
      }
    },
    [url]
  );

  const statusConfig = {
    safe: { icon: CheckCircle, color: "text-safe", bg: "bg-safe/10", border: "border-safe/30", label: "SAFE" },
    warning: { icon: AlertTriangle, color: "text-warning", bg: "bg-warning/10", border: "border-warning/30", label: "WARNING" },
    danger: { icon: XCircle, color: "text-danger", bg: "bg-danger/10", border: "border-danger/30", label: "DANGEROUS" },
  };

  return (
    <div className="container py-12 max-w-5xl">
      <div className="text-center mb-10">
        <h1 className="text-3xl font-display font-bold mb-2">URL Scanner</h1>
        <p className="text-muted-foreground">Real-time threat analysis powered by Gemini AI</p>
        <div className="inline-flex items-center gap-1.5 mt-3 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-medium">
          <Zap className="w-3 h-3" /> Real-time Scanning Enabled
        </div>
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && handleScan(undefined, false)}
          placeholder="https://example.com"
          className="w-full h-14 pl-12 pr-32 rounded-2xl bg-card border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-sm"
        />
        <button
          onClick={() => handleScan(undefined, false)}
          disabled={scanning || !isValidUrl(url)}
          className="absolute right-2 top-1/2 -translate-y-1/2 px-6 py-2.5 rounded-xl bg-primary text-primary-foreground font-semibold text-sm hover:brightness-110 transition disabled:opacity-50"
        >
          {scanning ? "Scanning..." : "Scan"}
        </button>
      </div>

      {/* Real-time scanning hint */}
      <AnimatePresence>
        {showRealTimeHint && url && isValidUrl(url) && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="mb-4 p-3 rounded-lg bg-primary/10 border border-primary/20 text-primary text-xs font-medium flex items-center gap-2"
          >
            <Clock className="w-3 h-3 animate-spin" /> Real-time scan triggered automatically
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error message */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="mb-4 p-3 rounded-lg bg-warning/10 border border-warning/20 text-warning text-xs flex items-center justify-between"
          >
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-warning/60 hover:text-warning">
              ✕
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Demo URLs */}
      <div className="flex flex-wrap gap-2 mb-10 justify-center">
        <span className="text-xs text-muted-foreground mr-1 self-center">Try:</span>
        {demoUrls.map((d) => (
          <button
            key={d.url}
            onClick={() => {
              setUrl(d.url);
              handleScan(d.url, false);
            }}
            className="px-3 py-1.5 rounded-lg bg-secondary text-secondary-foreground text-xs font-mono hover:bg-secondary/80 transition border border-border"
          >
            {d.label}
          </button>
        ))}
      </div>

      {/* Scanning animation */}
      <AnimatePresence>
        {scanning && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center py-16">
            <div className="w-20 h-20 mx-auto rounded-full border-4 border-primary/20 border-t-primary animate-spin mb-6" />
            <p className="text-muted-foreground animate-pulse">Analyzing URL across multiple threat signals...</p>
            {meta?.cached && <p className="text-xs text-muted-foreground mt-2">Retrieving from cache...</p>}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results */}
      <AnimatePresence>
        {result && !scanning && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            {/* Score + Status */}
            <div className="p-8 rounded-2xl bg-card border border-border text-center">
              <ThreatGauge score={result.threatScore} />
              <div className="mt-4">
                {(() => {
                  const cfg = statusConfig[result.status];
                  return (
                    <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-full ${cfg.bg} ${cfg.border} border ${cfg.color} font-bold text-sm`}>
                      <cfg.icon className="w-4 h-4" /> {cfg.label}
                    </span>
                  );
                })()}
              </div>
              <p className="text-xs text-muted-foreground mt-3 font-mono break-all">{result.url}</p>
              <button
                onClick={() => generateScanReport(result)}
                className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-secondary text-secondary-foreground text-sm font-medium hover:bg-secondary/80 border border-border transition"
              >
                <Download className="w-4 h-4" /> Download PDF Report
              </button>
            </div>

            {/* AI Explanation */}
            <div className="p-6 rounded-2xl bg-amber-500/5 border border-amber-500/20">
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-5 h-5 text-amber-400" />
                <h3 className="font-display font-semibold">AI Analysis</h3>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">{result.aiExplanation}</p>
              <p className="text-sm font-semibold">{result.aiRecommendation}</p>
            </div>

            {/* Confidence + Evidence Breakdown */}
            {meta?.breakdown && (
              <div className="p-6 rounded-2xl bg-card border border-border">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Server className="w-5 h-5 text-primary" />
                    <h3 className="font-display font-semibold">Evidence Breakdown</h3>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    {meta.cached && (
                      <span className="px-2 py-1 rounded-md bg-primary/10 text-primary border border-primary/20">Cached</span>
                    )}
                    <span className="text-muted-foreground">
                      Confidence: <span className="font-semibold text-foreground">{meta.confidence ?? 0}%</span>
                    </span>
                  </div>
                </div>
                <div className="space-y-3">
                  {meta.breakdown.map((b) => (
                    <div key={b.source}>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className={b.available ? "text-foreground" : "text-muted-foreground line-through"}>
                          {b.source} <span className="text-muted-foreground">· weight {Math.round(b.weight * 100)}%</span>
                        </span>
                        <span className="font-mono text-muted-foreground">
                          {b.available ? `${b.score}/100` : "unavailable"}
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full bg-secondary overflow-hidden">
                        <div
                          className={`h-full ${b.score >= 60 ? "bg-danger" : b.score >= 30 ? "bg-warning" : "bg-safe"}`}
                          style={{ width: `${b.available ? b.score : 0}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Score Breakdown */}
            <ScoreBreakdown result={result} />

            {/* VirusTotal Detailed Analysis */}
            {(() => {
              const vt = (result as any).virus_total as any;
              const totalEngines = (vt?.malicious ?? 0) + (vt?.suspicious ?? 0) + (vt?.harmless ?? 0) + (vt?.undetected ?? 0);
              const hasDetections = (vt?.malicious ?? 0) + (vt?.suspicious ?? 0) > 0;
              
              if (vt?.checked && totalEngines > 0) {
                return (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-6 rounded-2xl bg-card border border-border">
                    <div className="flex items-center gap-2 mb-4">
                      <Server className="w-5 h-5 text-accent" />
                      <h3 className="font-display font-semibold">VirusTotal Scan Results</h3>
                      <span className="text-xs px-2 py-1 rounded bg-muted text-muted-foreground ml-auto">{totalEngines} engines scanned</span>
                    </div>
                    
                    <div className="grid md:grid-cols-2 gap-4 mb-4">
                      <div className={`p-3 rounded-lg ${hasDetections ? 'bg-danger/10 border border-danger/20' : 'bg-safe/10 border border-safe/20'}`}>
                        <p className="text-xs text-muted-foreground mb-1">Malicious</p>
                        <p className={`text-2xl font-bold ${hasDetections ? 'text-danger' : 'text-safe'}`}>{vt?.malicious ?? 0}</p>
                      </div>
                      <div className={`p-3 rounded-lg ${(vt?.suspicious ?? 0) > 0 ? 'bg-warning/10 border border-warning/20' : 'bg-safe/10 border border-safe/20'}`}>
                        <p className="text-xs text-muted-foreground mb-1">Suspicious</p>
                        <p className={`text-2xl font-bold ${(vt?.suspicious ?? 0) > 0 ? 'text-warning' : 'text-safe'}`}>{vt?.suspicious ?? 0}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-safe/10 border border-safe/20">
                        <p className="text-xs text-muted-foreground mb-1">Clean</p>
                        <p className="text-2xl font-bold text-safe">{vt?.harmless ?? 0}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/20 border border-muted/30">
                        <p className="text-xs text-muted-foreground mb-1">Undetected</p>
                        <p className="text-2xl font-bold text-muted-foreground">{vt?.undetected ?? 0}</p>
                      </div>
                    </div>

                    {vt?.engines && vt.engines.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">Flagged by engines</p>
                        <div className="flex flex-wrap gap-2">
                          {vt.engines.map((engine: string, idx: number) => (
                            <span key={idx} className="text-xs px-2.5 py-1 rounded bg-danger/15 text-danger border border-danger/30 font-mono">
                              {engine}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </motion.div>
                );
              }
              return null;
            })()}

            <div className="grid md:grid-cols-2 gap-6">
              {/* Heuristic Analysis */}
              <div className="p-6 rounded-2xl bg-card border border-border">
                <div className="flex items-center gap-2 mb-4">
                  <Shield className="w-5 h-5 text-primary" />
                  <h3 className="font-display font-semibold">Heuristic Analysis</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {result.heuristics.map((h, i) => {
                    const colors = {
                      safe: "bg-safe/10 text-safe border-safe/20",
                      warning: "bg-warning/10 text-warning border-warning/20",
                      danger: "bg-danger/10 text-danger border-danger/20",
                    };
                    return (
                      <span key={i} className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${colors[h.severity]}`} title={h.description}>
                        {h.name}
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* API Intelligence */}
              <div className="p-6 rounded-2xl bg-card border border-border">
                <div className="flex items-center gap-2 mb-4">
                  <Server className="w-5 h-5 text-accent" />
                  <h3 className="font-display font-semibold">API Intelligence</h3>
                </div>
                <div className="space-y-3">
                  {(() => {
                    const sb = (result as any).safe_browsing as
                      | { checked: boolean; listed: boolean; threats: string[] }
                      | undefined;
                    const sbDetail = !sb || !sb.checked
                      ? "Unavailable"
                      : sb.listed
                      ? sb.threats.join(", ")
                      : "Clean";
                    const sbFlagged = !!sb?.listed;
                    return (
                      <div className="flex items-center justify-between text-sm">
                        <span className="font-medium">Google Safe Browsing</span>
                        <span className={`text-xs ${sbFlagged ? "text-danger" : sb?.checked ? "text-safe" : "text-muted-foreground"}`}>
                          {sbDetail}
                        </span>
                      </div>
                    );
                  })()}
                  {(() => {
                    const vt = (result as any).virus_total as
                      | { checked: boolean; found: boolean; malicious: number; suspicious: number; harmless: number; undetected: number; engines: string[]; submitted: boolean }
                      | undefined;
                    const flagged = !!vt && (vt.malicious + vt.suspicious) > 0;
                    const totalEngines = (vt?.malicious ?? 0) + (vt?.suspicious ?? 0) + (vt?.harmless ?? 0) + (vt?.undetected ?? 0);
                    
                    let detail = "Unavailable";
                    if (vt?.checked) {
                      if (vt?.submitted && !vt?.found) {
                        detail = "Submitted for analysis...";
                      } else if (!vt?.found) {
                        detail = "Not in database";
                      } else {
                        const total = totalEngines || "?";
                        detail = flagged
                          ? `${vt.malicious}M / ${vt.suspicious}S (${total} engines)`
                          : `Clean (${vt?.harmless ?? 0}/${total} engines)`;
                      }
                    }
                    
                    return (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">VirusTotal</span>
                            {vt?.submitted && <span className="text-xs px-2 py-1 rounded bg-primary/10 text-primary">Scanning</span>}
                          </div>
                          <span className={`text-xs font-mono ${flagged ? "text-danger font-bold" : vt?.checked && vt?.found ? "text-safe" : "text-muted-foreground"}`}>
                            {detail}
                          </span>
                        </div>
                        {vt?.engines && vt.engines.length > 0 && (
                          <div className="pl-4 border-l border-muted">
                            <p className="text-xs text-muted-foreground mb-2">Detections by engine:</p>
                            <div className="flex flex-wrap gap-1">
                              {vt.engines.slice(0, 5).map((engine) => (
                                <span key={engine} className="text-xs px-2 py-1 rounded bg-danger/10 text-danger border border-danger/20">
                                  {engine.split("/")[0] || engine}
                                </span>
                              ))}
                              {vt.engines.length > 5 && (
                                <span className="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                                  +{vt.engines.length - 5} more
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                  {[
                    { name: "PhishTank", detail: result.apiIntel.phishTank.detail, flagged: result.apiIntel.phishTank.listed },
                    { name: "MalwareBazaar", detail: result.apiIntel.malwareBazaar.detail, flagged: result.apiIntel.malwareBazaar.listed },
                  ].map((api) => (
                    <div key={api.name} className="flex items-center justify-between text-sm">
                      <span className="font-medium">{api.name}</span>
                      <span className={`text-xs ${api.flagged ? "text-danger" : "text-safe"}`}>{api.detail}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Domain Intelligence */}
              <div className="p-6 rounded-2xl bg-card border border-border">
                <div className="flex items-center gap-2 mb-4">
                  <Globe className="w-5 h-5 text-primary" />
                  <h3 className="font-display font-semibold">Domain Intelligence</h3>
                </div>
                <div className="space-y-2 text-sm">
                  {Object.entries(result.domainInfo).map(([key, val]) => (
                    <div key={key} className="flex justify-between">
                      <span className="text-muted-foreground capitalize">{key.replace(/([A-Z])/g, " $1")}</span>
                      <span className="font-mono text-xs">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* HTTPS Certificate */}
              <div className="p-6 rounded-2xl bg-card border border-border">
                <div className="flex items-center gap-2 mb-4">
                  <Lock className="w-5 h-5 text-primary" />
                  <h3 className="font-display font-semibold">HTTPS Certificate</h3>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Issuer</span>
                    <span className="font-mono text-xs">{result.httpsInfo.issuer}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Expiry</span>
                    <span className="font-mono text-xs">{result.httpsInfo.expiry}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Grade</span>
                    <span className={`font-bold ${result.httpsInfo.grade === "A+" ? "text-safe" : "text-danger"}`}>{result.httpsInfo.grade}</span>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
