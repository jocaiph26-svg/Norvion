#!/usr/bin/env python3
"""
Quick upload script for test_data_full_alerts.csv
Bypasses browser header limitations by sending headers directly.
"""
import sys

try:
    import requests
except ImportError:
    print("❌ requests library not found. Install with:")
    print("   pip install requests")
    sys.exit(1)

# Configuration
URL = "http://localhost:8000/analyze"
CSV_FILE = "test_data_full_alerts.csv"

# Access headers (required by app)
HEADERS = {
    "X-Tenant-ID": "public",
    "X-Access-Role": "admin",
    "X-Actor-ID": "dev-user"
}

def main():
    print("🚀 Uploading test data to SME Early Warning system...")
    print(f"   URL: {URL}")
    print(f"   File: {CSV_FILE}")
    print(f"   Tenant: {HEADERS['X-Tenant-ID']}")
    print(f"   Role: {HEADERS['X-Access-Role']}")
    print()

    try:
        with open(CSV_FILE, "rb") as f:
            files = {"file": (CSV_FILE, f, "text/csv")}
            print("📤 Sending request...")
            response = requests.post(URL, headers=HEADERS, files=files, allow_redirects=False)

        print()
        if response.status_code == 200:
            print("✅ Upload successful!")
            print(response.text)
        elif response.status_code == 302:
            redirect_url = response.headers.get("Location", "")
            print("✅ Upload successful! (Redirecting...)")
            print(f"   Redirect to: {redirect_url}")
            print()
            print("🎯 Next steps:")
            print("   1. Open your browser to: http://localhost:8000/dashboard")
            print("   2. View all 7 triggered alerts")
            print("   3. Check status badge colors, critical emphasis, and table improvements")
        else:
            print(f"❌ Upload failed with status {response.status_code}")
            print()
            print("Response:")
            print(response.text[:500])

            if response.status_code == 403:
                print()
                print("💡 Tip: This is likely an access control issue.")
                print("   The app requires admin role to upload CSVs.")
                print("   Try using the curl command instead:")
                print()
                print("   curl -X POST http://localhost:8000/analyze \\")
                print("     -H \"X-Tenant-ID: public\" \\")
                print("     -H \"X-Access-Role: admin\" \\")
                print("     -H \"X-Actor-ID: dev-user\" \\")
                print("     -F \"file=@test_data_full_alerts.csv\"")

    except FileNotFoundError:
        print(f"❌ Error: Could not find {CSV_FILE}")
        print(f"   Make sure you're running this script from: /Users/gabrielperrone/Downloads/SME_Early_Warning_fixed-2")
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to server")
        print("   Make sure the app is running:")
        print("   python app.py")
        print("   or")
        print("   uvicorn app:app --reload")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
