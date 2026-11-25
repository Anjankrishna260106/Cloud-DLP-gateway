# HTTPS Deployment Guide — CloudGuard Pre-Storage DLP Gateway

Because browser demos, webhook callbacks, and secure JWT transport require **HTTPS** (not `localhost`), two production-ready HTTPS deployment options are configured below.

---

## Option 1 (Recommended for Live Seminar Demo): Ngrok HTTPS Tunnel over Local/Docker Stack
**Why this is fastest & safest for a seminar:** Zero cold starts, instant switching between `vulnerable` and `remediated` modes, no free-tier build timeouts, and Vite/Nginx already proxies `/api/*` on the same origin—meaning **one** `https://` URL serves both the React UI and FastAPI backend with zero CORS or mixed-content issues.

### Commands (In Exact Order)
```powershell
# 1. Start FastAPI Backend (Terminal 1)
.\.venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# 2. Start React Frontend (Terminal 2)
npm --prefix frontend run dev

# 3. Expose via Ngrok HTTPS (Terminal 3)
ngrok http 5173
```
*(Or using Docker Compose: `docker compose -f docker/docker-compose.yml up --build -d` followed by `ngrok http 3000`)*

**Expected Output:**
Ngrok displays a forwarding URL such as:
`Forwarding  https://a1b2-203-0-113-42.ngrok-free.app -> http://localhost:5173`
Open that `https://...` URL in any browser or phone to demo over HTTPS.

---

## Option 2 (Permanent Cloud Subdomains): Render (Backend) + Vercel (Frontend)
1. Push this repository to GitHub.
2. **Backend on Render**:
   - Create a New Blueprint / Web Service on [render.com](https://render.com) using `render.yaml`.
   - Set environment variables (`MONGODB_URI` for Atlas, optional `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).
   - Render provides an HTTPS URL: `https://cloudguard-dlp-backend.onrender.com`.
3. **Frontend on Vercel**:
   - Update the destination URL inside `frontend/vercel.json` to your Render HTTPS URL.
   - Deploy from `frontend/`:
     ```powershell
     npx vercel --prod
     ```
   - Vercel provides an HTTPS URL: `https://cloudguard-dlp.vercel.app`.

---

## Fallbacks (If Option 1 or Option 2 Hits a Free-Tier Limit)
1. **If Ngrok hits a session/bandwidth limit**: Use **Cloudflare Quick Tunnel** (completely free, no account required, no interstitial warning screen):
   ```powershell
   cloudflared tunnel --url http://localhost:5173
   ```
   Expected output: `https://<random-words>.trycloudflare.com`
2. **If Render free tier spins down (50s cold start) or hits monthly 750h limit**: Run `docker compose -f docker/docker-compose.yml up -d` locally and expose port `3000` with `cloudflared tunnel --url http://localhost:3000`.
3. **If Vercel hits build quota**: Serve the pre-built `frontend/dist` bundle directly via Nginx in Docker (`docker compose -f docker/docker-compose.yml up -d`) behind `ngrok` or `cloudflared`.
