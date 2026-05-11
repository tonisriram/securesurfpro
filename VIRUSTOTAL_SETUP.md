# VirusTotal Integration Setup Guide

## Overview

The SecureSurf scanner now integrates with **VirusTotal API** to perform real vulnerability and malware scanning. This provides:

- ✅ Multi-engine malware detection (70+ antivirus engines)
- ✅ Real-time URL reputation checking
- ✅ Vulnerability and threat assessment
- ✅ Detection of phishing, trojans, worms, and other malware
- ✅ Community threat feedback integration

## Getting VirusTotal API Key

### Step 1: Create VirusTotal Account

1. Go to [https://www.virustotal.com/](https://www.virustotal.com/)
2. Click **"Sign in"** → **"Sign up"** to create a free account
3. Verify your email address

### Step 2: Generate API Key

1. After login, go to your **Profile** (click your username in top-right)
2. Navigate to **API Key** section
3. Copy your API Key (keep it secret!)

**API Tier:**
- **Free Tier**: 4 requests/minute, sufficient for most use cases
- **Premium**: Higher rate limits and advanced features

## Configuration

### Option 1: Manual Setup

1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Navigate to your project → **Project Settings** → **Secrets**
3. Add a new secret:
   ```
   Name: VIRUSTOTAL_API_KEY
   Value: <your_api_key_here>
   ```
4. Save and redeploy the edge function

### Option 2: Using Supabase CLI

```bash
supabase secrets set VIRUSTOTAL_API_KEY=<your_api_key_here>
```

## Deploy Edge Function

After adding the API key:

```bash
# From your project root
supabase functions deploy scan-url
```

## How It Works

### URL Scanning Flow

1. **Check Existing Analysis**: Scanner first checks if the URL is already in VirusTotal's database
2. **Submit for Scanning**: If not found, the URL is submitted for analysis
3. **Get Results**: Initial results are returned (more detailed analysis continues in background)
4. **Combine with Other Checks**: VirusTotal results are weighted with:
   - Google Safe Browsing
   - Gemini AI Analysis
   - Local heuristics

### Scoring System

```
VirusTotal Contribution to Final Score:
- Malicious engines: 25 points each
- Suspicious engines: 10 points each
- Weight: 35% of final decision

Example:
- 2 malicious detections = 50 points + weight = ~17.5% of score
- 1 malicious + 3 suspicious = 25 + 30 = 55 points
```

## Results Display

The Scanner displays VirusTotal results in the **"API Intelligence"** section:

```
VirusTotal: [status]
├─ Clean (0 detections)
├─ Not in database
├─ Found (shows detection counts)
└─ Engines (displays top 10 flagging engines)
```

## Testing the Integration

### Test URLs

```bash
# Safe URL (should return 0 detections)
https://google.com

# Known malware (high detections expected)
http://eicar.org/download/eicar.com

# Suspicious/phishing (may have some detections)
https://malicious-phishing-site.example.com
```

### Check Live Results

1. Open the Scanner
2. Enter a test URL
3. Click "Scan" or wait for auto-scan (1.5s debounce)
4. View results in "API Intelligence" section

## API Limits & Best Practices

### Rate Limiting
- **Free tier**: 4 requests/minute
- **Premium**: 500+ requests/minute
- Cache prevents excessive API calls

### Best Practices
1. **Enable caching** (6-hour TTL default) - reduces API usage
2. **Submit URLs for analysis** - improves quality on recheck
3. **Monitor rate limits** - implement backoff strategies
4. **Handle timeouts gracefully** - fallback to heuristics

### Upgrade to Premium (Optional)

For production applications with high traffic:
1. Visit [VirusTotal Intelligence](https://www.virustotal.com/gui/home/upload)
2. Upgrade account plan
3. Update `VIRUSTOTAL_API_KEY` with premium key
4. Increase request rate to 500/min or higher

## Troubleshooting

### "Missing VirusTotal key" Error
- Solution: Add `VIRUSTOTAL_API_KEY` to Supabase secrets
- Verify: `supabase secrets list`

### Rate Limited (429 Status)
- Check request rate (4/min on free tier)
- Caching prevents most duplicate requests
- Wait 1 minute before retrying

### URL Not Found (404)
- Normal for new URLs
- Scanner automatically submits for analysis
- Results available within seconds/minutes

### "Connection Timeout"
- VirusTotal API may be slow
- Scanner falls back to other checks
- Try again in a few moments

## Feature Details

### Real-Time Vulnerability Assessment

The edge function now:

1. **Checks Cache First** - Returns cached results if available
2. **Queries Existing Analysis** - Looks up URL in VirusTotal database
3. **Submits New URLs** - Auto-submits unknown URLs for analysis
4. **Gets Analysis Results** - Retrieves detection counts by engine
5. **Extracts Engines** - Identifies top malicious/suspicious detections
6. **Scores & Weights** - Combines with other intelligence sources

### Integration Architecture

```
User Input (URL)
    ↓
Local Heuristics (instant)
    ↓
Parallel Checks:
├─ Google Safe Browsing
├─ VirusTotal Scan
├─ Gemini AI Analysis
    ↓
Weighted Scoring Engine (combines all sources)
    ↓
Final Verdict + Recommendations
    ↓
Results Cached (6 hours)
```

## Next Steps

1. ✅ Get VirusTotal API key
2. ✅ Add to Supabase secrets
3. ✅ Deploy edge function: `supabase functions deploy scan-url`
4. ✅ Test with sample URLs
5. ✅ Monitor logs: `supabase functions logs scan-url`

## Support

- **VirusTotal Docs**: https://developers.virustotal.com/reference
- **Common Issues**: https://support.virustotal.com/
- **API Status**: Check VirusTotal status page for incidents

## Monitoring

Check edge function logs for integration status:

```bash
supabase functions logs scan-url --follow
```

Look for:
- ✅ "VirusTotal found existing analysis"
- ✅ "URL submitted to VirusTotal"
- ✅ "VirusTotal analysis initiated"
- ⚠️ "VirusTotal rate limited"
- ❌ "VirusTotal check failed"

---

**Your scanner is now powered by VirusTotal's 70+ security engines!** 🛡️
