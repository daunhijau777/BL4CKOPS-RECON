#!/bin/bash
echo "[+] Installing HTTP/JS Recon Tools..."

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/lc/gau@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/tools/gf-patterns && cp ~/tools/gf-patterns/*.json ~/.gf/

# JS recon
git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ~/tools/xnLinkFinder 2>/dev/null || true
cd ~/tools/xnLinkFinder && pip3 install -r requirements.txt && python3 setup.py install && cd ~

git clone https://github.com/xnl-h4ck3r/waymore.git ~/tools/waymore 2>/dev/null || true

pip3 install arjun

echo "[✓] HTTP fuzz / JS recon tools installed."
