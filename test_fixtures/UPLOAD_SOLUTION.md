# Solution: Upload CSV with Admin Access

## The Problem

The app requires HTTP headers for access control:
- `X-Tenant-ID`: Tenant identifier (default: "public")
- `X-Access-Role`: Role level ("viewer", "auditor", or "admin")
- `X-Actor-ID`: User identifier (optional)

The `/analyze` endpoint (CSV upload) requires **"admin"** role.

---

## Solution 1: Use cURL (Easiest for Developers)

```bash
curl -X POST http://localhost:8000/analyze \
  -H "X-Tenant-ID: public" \
  -H "X-Access-Role: admin" \
  -H "X-Actor-ID: dev-user" \
  -F "file=@test_data_full_alerts.csv"
```

**Then navigate to:** http://localhost:8000/dashboard

---

## Solution 2: Use a Browser Extension to Add Headers

### Option A: ModHeader (Chrome/Edge/Firefox)

1. Install [ModHeader extension](https://modheader.com/)
2. Add these request headers:
   - Name: `X-Tenant-ID`, Value: `public`
   - Name: `X-Access-Role`, Value: `admin`
   - Name: `X-Actor-ID`, Value: `dev-user`
3. Reload the page and upload normally

### Option B: Simple Modify Headers (Firefox)

1. Install "Simple Modify Headers" extension
2. Add the same headers as above
3. Enable the extension
4. Reload and upload

---

## Solution 3: Python Script (Automated Upload)

Save this as `upload_test_data.py`:

```python
import requests

url = "http://localhost:8000/analyze"
headers = {
    "X-Tenant-ID": "public",
    "X-Access-Role": "admin",
    "X-Actor-ID": "dev-user"
}

with open("test_data_full_alerts.csv", "rb") as f:
    files = {"file": ("test_data_full_alerts.csv", f, "text/csv")}
    response = requests.post(url, headers=headers, files=files)

if response.status_code == 200 or response.status_code == 302:
    print("✅ Upload successful!")
    print(f"Status: {response.status_code}")
    if response.status_code == 302:
        print(f"Redirect to: {response.headers.get('Location', 'N/A')}")
else:
    print(f"❌ Upload failed: {response.status_code}")
    print(response.text)
```

Run with:
```bash
python upload_test_data.py
```

---

## Solution 4: Modify app.py Temporarily (Dev Override)

Add this near line 3560 in `app.py`, right before the `_require_role` check:

```python
@app.post("/analyze")
async def analyze(request: Request, file: UploadFile = File(...)):
    # DEV OVERRIDE - Comment out in production!
    import os
    if os.getenv("DEV_MODE", "").lower() == "true":
        # Bypass access control for local development
        request.headers.__dict__["_list"] = [
            (b"x-tenant-id", b"public"),
            (b"x-access-role", b"admin"),
            (b"x-actor-id", b"dev-user"),
        ] + request.headers.__dict__.get("_list", [])

    _require_role(request, "admin", "create", "run:analyze")
    # ... rest of function
```

Then start the server with:
```bash
DEV_MODE=true python app.py
```

---

## Solution 5: Use Postman/Insomnia

1. Open Postman or Insomnia
2. Create new POST request to `http://localhost:8000/analyze`
3. Add headers:
   - `X-Tenant-ID`: `public`
   - `X-Access-Role`: `admin`
   - `X-Actor-ID`: `dev-user`
4. Set body type to "Form Data"
5. Add field: `file` → select `test_data_full_alerts.csv`
6. Send request

---

## Recommended Quick Start

**For Mac/Linux developers:**

```bash
cd /Users/gabrielperrone/Downloads/SME_Early_Warning_fixed-2

# Upload the test CSV
curl -X POST http://localhost:8000/analyze \
  -H "X-Tenant-ID: public" \
  -H "X-Access-Role: admin" \
  -H "X-Actor-ID: dev-user" \
  -F "file=@test_data_full_alerts.csv"

# Then open browser to view results
open http://localhost:8000/dashboard
```

The response should be a redirect (302) to the dashboard, and you'll see all 7 alerts triggered.

---

## After Upload

Once you've uploaded with the headers, the session should persist and you can navigate normally in the browser to see:

- **Dashboard** (`/dashboard`) - Run overview with KPIs
- **Summary** (`/insights`) - Detailed metrics and alerts
- **Alerts** (`/alerts`) - All triggered alerts with status badges
- **History** (`/history`) - List of all runs
- **Weekly Summary** (`/digest/weekly`) - Weekly event digest

All pages will show the P0-P2.1 UI improvements!

---

## Troubleshooting

**If curl fails:**
- Make sure the server is running: `python app.py` or `uvicorn app:app --reload`
- Check the port matches (default 8000)
- Verify the CSV file path is correct

**If browser still shows "Access context required":**
- Add the headers using a browser extension
- The headers are only needed for the `/analyze` POST request
- Once uploaded, viewing pages should work normally

**If you get "forbidden" error:**
- Verify the role is set to `admin` (not `viewer` or `auditor`)
- Check headers are being sent correctly