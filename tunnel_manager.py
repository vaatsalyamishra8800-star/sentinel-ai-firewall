#!/usr/bin/env python3
"""
Sentinel Gateway - Cloudflare Online Tunnel Manager
Automatically manages Sentinel server & Cloudflare tunnel, captures the live URL,
updates public_url.txt, and presents phone connection links.
"""

import os
import sys
import re
import time
import socket
import signal
import subprocess
import urllib.request

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ROOT = os.path.dirname(os.path.abspath(__file__))
CLOUDFLARED = os.path.join(ROOT, "cloudflared.exe")
PUBLIC_URL_FILE = os.path.join(ROOT, "public_url.txt")
SERVER_SCRIPT = os.path.join(ROOT, "server.py")
PORT = 8080

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def is_server_listening(port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(('127.0.0.1', port)) == 0

def main():
    print("=" * 72)
    print("  🛡️  SENTINEL AI GATEWAY - CLOUDFLARE ONLINE TUNNEL MANAGER v3.0")
    print("=" * 72)

    if not os.path.exists(CLOUDFLARED):
        print(f"\n[ERROR] cloudflared.exe not found in {ROOT}!")
        input("\nPress Enter to exit...")
        sys.exit(1)

    server_proc = None
    if not is_server_listening(PORT):
        print(f"\n[*] Sentinel Gateway server is not running on port {PORT}.")
        print("[*] Launching server.py automatically...")
        try:
            server_proc = subprocess.Popen(
                [sys.executable, SERVER_SCRIPT],
                cwd=ROOT
            )
            # Wait for server to bind
            for _ in range(10):
                time.sleep(0.5)
                if is_server_listening(PORT):
                    print(f"[✓] Sentinel Gateway online on http://127.0.0.1:{PORT}")
                    break
        except Exception as e:
            print(f"[WARN] Could not auto-start server: {e}")
            print("[!] Please ensure 'python server.py' is running in another window.")
    else:
        print(f"[✓] Detected active Sentinel Gateway listening on port {PORT}")

    lan_ip = get_lan_ip()
    print("\n[*] Starting Cloudflare Quick Tunnel for http://127.0.0.1:8080...")
    print("[*] Contacting Cloudflare edge network to obtain public HTTPS domain...\n")

    cloudflared_proc = subprocess.Popen(
        [CLOUDFLARED, "tunnel", "--url", f"http://127.0.0.1:{PORT}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace"
    )

    tunnel_url = None
    start_time = time.time()

    def cleanup():
        print("\n\n[*] Shutting down Cloudflare Tunnel...")
        try:
            cloudflared_proc.terminate()
            cloudflared_proc.wait(timeout=3)
        except Exception:
            pass
        if server_proc:
            print("[*] Stopping background Sentinel server...")
            try:
                server_proc.terminate()
                server_proc.wait(timeout=3)
            except Exception:
                pass
        # Clear public_url.txt so stale links don't confuse users
        try:
            if os.path.exists(PUBLIC_URL_FILE):
                os.remove(PUBLIC_URL_FILE)
        except Exception:
            pass
        print("[✓] Clean shutdown complete.")

    try:
        while True:
            line = cloudflared_proc.stdout.readline()
            if not line:
                break
            
            # Print Cloudflare info lines so user knows connection is progressing
            line_str = line.strip()
            if not tunnel_url:
                if "INF" in line_str or "Requesting" in line_str:
                    print(f"    [Cloudflare] {line_str}")
                    sys.stdout.flush()

            # Look for the trycloudflare URL
            match = re.search(r'(https://[a-zA-Z0-9-]+\.trycloudflare\.com)', line)
            if match and not tunnel_url:
                tunnel_url = match.group(1)
                
                # Write to public_url.txt
                with open(PUBLIC_URL_FILE, "w", encoding="utf-8") as f:
                    f.write(tunnel_url + "\n")

                print("\n" + "=" * 72)
                print("  🎉 LIVE CLOUDFLARE TUNNEL ESTABLISHED SUCCESSFULLY!")
                print("=" * 72)
                print(f"\n  📱 PHONE / INTERNET ACCESS (Works on 5G / 4G / Any Network):")
                print(f"     👉  {tunnel_url}")
                print(f"\n  💻 LOCAL PC ACCESS:")
                print(f"     👉  http://127.0.0.1:{PORT}/")
                print(f"\n  🏠 HOME WI-FI (Same Router):")
                print(f"     👉  http://{lan_ip}:{PORT}/")
                print("\n" + "=" * 72)
                print("  ✓ public_url.txt has been updated with the current live link.")
                print("  ✓ Dashboard QR Code and Mobile Access modal updated automatically.")
                print("  ⚠️  KEEP THIS WINDOW OPEN to maintain the live tunnel connection.")
                print("  ⚠️  Press Ctrl+C when you want to stop the tunnel.")
                print("=" * 72 + "\n")
                sys.stdout.flush()
            
            # Print error notices if any
            if "ERR" in line:
                print(f"[Tunnel Log] {line_str}")
                sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()
