LovableZone Key Grabber — Desktop App
======================================

QUICK START (already have .exe)
-------------------------------
1. Put LovableZoneGrabber.exe in any folder
2. Create proxy.txt in the SAME folder (or edit inside the app)
3. Double-click LovableZoneGrabber.exe
4. Paste proxies -> Save proxies
5. Set Count / Delay / Scheme (socks5 for Decodo)
6. Click Start
7. Keys appear under "All keys" and auto-save to license.txt
8. Use Copy all or Export

BUILD .EXE ON WINDOWS (from source)
-----------------------------------
1. Install Python 3.10+ from python.org
   - CHECK "Add Python to PATH"
2. Open this folder in File Explorer
3. Double-click build_windows.bat
   OR in PowerShell:
      cd path\to\lz_gui
      .\build_windows.bat
4. Find exe in the dist\ folder:
      dist\LovableZoneGrabber.exe

RUN WITHOUT BUILDING
--------------------
python LovableZoneGrabber.py

DECODO / SOCKS5
---------------
- Scheme: socks5
- Do NOT enable "Session-rot" unless you know Decodo username session format
- Do NOT enable "Random port" for Decodo (port is fixed)
- Format:
    socks5://YOUR_USER:YOUR_PASS@gate.decodo.com:10000

FILES CREATED NEXT TO EXE
-------------------------
proxy.txt     your proxies
license.txt   saved keys (auto)
config.json   UI settings

TROUBLESHOOTING
---------------
SOCKS5 authentication failed  -> wrong user/pass, or Session-rot ON by mistake
24 hours rate limit           -> need more exit IPs / more proxies
No module socks               -> pip install pysocks  (or rebuild exe)
Antivirus blocks exe          -> PyInstaller false positive; allow / exclude folder
