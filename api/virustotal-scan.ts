const VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3";
const MAX_URL_LENGTH = 2048;

type VirusTotalScan = {
  checked: boolean;
  found: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  engines: string[];
  submitted?: boolean;
};

function validateUrl(input: unknown): string {
  if (!input || typeof input !== "string") throw new Error("URL is required");
  if (input.length > MAX_URL_LENGTH) throw new Error(`URL exceeds ${MAX_URL_LENGTH} characters`);

  const parsed = new URL(input);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https URLs are supported");
  }
  return parsed.toString();
}

function toBase64Url(input: string) {
  return Buffer.from(input, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function virusTotalFetch(path: string, init: RequestInit = {}) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY ?? process.env.VITE_VIRUSTOTAL_API_KEY;
  if (!apiKey) throw new Error("Missing VIRUSTOTAL_API_KEY on Vercel");

  const res = await fetch(`${VIRUSTOTAL_API_BASE}${path}`, {
    ...init,
    headers: {
      "x-apikey": apiKey,
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

async function scanUrl(url: string): Promise<VirusTotalScan> {
  const lookupRes = await virusTotalFetch(`/urls/${toBase64Url(url)}`);

  if (lookupRes.ok) return parseVirusTotal(await lookupRes.json(), "url");
  if (lookupRes.status !== 404) throw new Error(`VirusTotal lookup failed with status ${lookupRes.status}`);

  const submitRes = await virusTotalFetch("/urls", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `url=${encodeURIComponent(url)}`,
  });

  if (!submitRes.ok) throw new Error(`VirusTotal submit failed with status ${submitRes.status}`);

  const analysisId = (await submitRes.json())?.data?.id;
  if (!analysisId) {
    return { checked: true, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, engines: [], submitted: true };
  }

  for (let attempt = 0; attempt < 4; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, attempt === 0 ? 1200 : 1800));
    const analysisRes = await virusTotalFetch(`/analyses/${analysisId}`);
    if (!analysisRes.ok) continue;

    const analysisData = await analysisRes.json();
    if (analysisData?.data?.attributes?.status !== "completed") continue;
    return parseVirusTotal(analysisData, "analysis", true);
  }

  return { checked: true, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, engines: [], submitted: true };
}

export default async function handler(req: any, res: any) {
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const url = validateUrl(req.body?.url);
    const virusTotal = await scanUrl(url);
    return res.status(200).json({ virus_total: virusTotal });
  } catch (error) {
    const message = error instanceof Error ? error.message : "VirusTotal scan failed";
    return res.status(400).json({ error: message });
  }
}
