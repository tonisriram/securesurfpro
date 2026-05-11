# Environment Setup Guide - SecureSurf Scanner

## Overview

This guide explains how to set up all required environment variables and API keys for the SecureSurf vulnerability scanner to work with full integrations.

## Required API Keys

### 1. VirusTotal API Key (VIRUSTOTAL_API_KEY)

**Purpose**: Multi-engine malware and vulnerability detection

#### Getting Your Key
1. Visit [https://www.virustotal.com/](https://www.virustotal.com/)
2. Sign up for a free account
3. Go to Profile → API Key
4. Copy your API key

#### Tier Options
- **Free**: 4 requests/minute (sufficient for testing/demo)
- **Premium**: 500+ requests/minute (for production)

#### Configuration
```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

### 2. Google Safe Browsing API Key (GOOGLE_SAFE_BROWSING_API_KEY)

**Purpose**: Detect phishing, malware, and unwanted software

#### Getting Your Key
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Search for "Safe Browsing API" and enable it
4. Create an API key (Credentials → Create Credentials → API Key)
5. Copy the key

#### Configuration
```env
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
```

### 3. Gemini AI API Key (GEMINI_API_KEY)

**Purpose**: AI-powered threat analysis and recommendations

#### Getting Your Key
1. Visit [Google AI Studio](https://aistudio.google.com/)
2. Click "Get API Key"
3. Create new API key in Google Cloud Console
4. Copy the key

#### Configuration
```env
GEMINI_API_KEY=your_api_key_here
```

### 4. Supabase Configuration

#### SUPABASE_URL
- Found in Supabase Dashboard → Project Settings
- Format: `https://[project-id].supabase.co`

#### SUPABASE_SERVICE_ROLE_KEY
- Found in Supabase Dashboard → Project Settings → API Keys
- Keep this secret! Only use server-side.

#### Configuration
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

## Deployment: Setting Secrets in Supabase

### Using Supabase Dashboard

1. Go to your Supabase project
2. Navigate to **Project Settings** → **Secrets**
3. Add each secret:

```
VIRUSTOTAL_API_KEY=<your_key>
GOOGLE_SAFE_BROWSING_API_KEY=<your_key>
GEMINI_API_KEY=<your_key>
SUPABASE_URL=<your_url>
SUPABASE_SERVICE_ROLE_KEY=<your_key>
```

4. Click "Save"
5. Redeploy edge function: `supabase functions deploy scan-url`

### Using Supabase CLI

```bash
# Set individual secrets
supabase secrets set VIRUSTOTAL_API_KEY=your_key_here
supabase secrets set GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
supabase secrets set GEMINI_API_KEY=your_key_here
supabase secrets set SUPABASE_URL=your_url_here
supabase secrets set SUPABASE_SERVICE_ROLE_KEY=your_key_here

# Verify secrets are set
supabase secrets list

# Deploy function with new secrets
supabase functions deploy scan-url
```

## Frontend Environment Variables

Create `.env.local` in project root:

```env
# Frontend Supabase Configuration (public - safe to expose)
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
VITE_SUPABASE_PROJECT_ID=your_project_id
```

**Note**: These use `VITE_` prefix to be exposed to frontend. The publishable key (anon) is safe to expose.

## Development Setup

### Local Testing

1. Create `.env.local`:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your_publishable_key
```

2. Run development server:

```bash
npm run dev
```

### Testing Edge Function Locally

```bash
# Start Supabase local environment
supabase start

# Run function locally
supabase functions serve

# Make test request
curl -X POST http://localhost:54321/functions/v1/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com"}'
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] All API keys obtained and working
- [ ] Secrets set in Supabase dashboard
- [ ] Edge function deployed: `supabase functions deploy scan-url`
- [ ] Frontend built: `npm run build`
- [ ] Database tables created: `scan_history`, `scan_cache`
- [ ] CORS headers configured

### Deployment Steps

```bash
# 1. Verify all secrets are set
supabase secrets list

# 2. Deploy edge function
supabase functions deploy scan-url

# 3. Build frontend
npm run build

# 4. Deploy to hosting (Vercel, Netlify, etc.)
vercel deploy  # or your hosting provider

# 5. Test production
# Visit your deployed app and test URL scanning
```

## API Rate Limits & Quotas

### VirusTotal
- **Free**: 4 requests/minute
- **Premium**: 500+ requests/minute
- **Cache**: 6-hour TTL prevents most requests

### Google Safe Browsing
- **Free tier**: Up to 10,000 requests/day
- **Premium**: Contact sales for higher limits
- **Quota tracking**: [Google Cloud Console](https://console.cloud.google.com/)

### Gemini AI
- **Free tier**: Limited requests
- **Premium**: Pay-per-request after free credits
- **Rate limit**: Check your API quota

### Supabase
- **Free tier**: 50,000 DB rows, rate limited
- **Pro**: $25/month, 500,000 rows

## Troubleshooting

### "Invalid API Key" Error

**Solution**: Verify key format and ensure it's copied completely

```bash
# Check key is set
supabase secrets list | grep VIRUSTOTAL

# Redeploy function
supabase functions deploy scan-url
```

### Rate Limiting (429 Error)

**Solutions**:
1. Upgrade to premium tier
2. Increase cache TTL (reduces API calls)
3. Implement request queuing
4. Wait before retrying

### "Connection Timeout" in Edge Function

**Solutions**:
1. Check internet connection
2. Verify API is accessible from Supabase region
3. Increase timeout value (currently 4-5s)
4. Check API status page

### Secrets Not Applied

**Solution**: 
1. Redeploy function: `supabase functions deploy scan-url`
2. Wait 30 seconds for propagation
3. Test with new request

## Monitoring & Logging

### View Edge Function Logs

```bash
supabase functions logs scan-url --follow
```

### Check API Usage

**VirusTotal**: Dashboard → Statistics  
**Google Safe Browsing**: [Google Cloud Console](https://console.cloud.google.com/) → API & Services  
**Gemini AI**: Check usage in Google AI Studio

## Security Best Practices

1. **Never commit API keys** to git
2. **Use environment variables** for all secrets
3. **Rotate keys regularly** (quarterly recommended)
4. **Monitor API usage** for unusual activity
5. **Use separate keys** for dev/staging/prod
6. **Enable API restrictions**:
   - VirusTotal: Restrict to your domain
   - Google APIs: Restrict to specific APIs
   - Gemini: Restrict to your service

## Upgrade Path

### Free → Premium

As your application grows:

1. **VirusTotal Premium**: $25-50/month
   - 500 requests/minute
   - Priority support
   - Advanced features

2. **Google Cloud Premium**: Based on usage
   - Variable pricing
   - Volume discounts
   - Dedicated support

3. **Gemini API Premium**: Based on usage
   - Pay-per-request model
   - Higher rate limits
   - API access to newer models

## Next Steps

1. ✅ Obtain all API keys
2. ✅ Set secrets in Supabase
3. ✅ Deploy edge function
4. ✅ Test URL scanning
5. ✅ Deploy to production
6. ✅ Monitor logs and usage

## Support Resources

- **VirusTotal**: https://developers.virustotal.com/
- **Google Safe Browsing**: https://developers.google.com/safe-browsing
- **Gemini AI**: https://ai.google.dev/
- **Supabase**: https://supabase.com/docs

---

**Your SecureSurf scanner is now production-ready with real threat intelligence!** 🛡️
