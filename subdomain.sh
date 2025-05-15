#!/bin/bash
echo "[+] Installing Subdomain Enumeration Tools..."

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "[+] Installing puredns..."
git clone https://github.com/d3mondev/puredns.git ~/tools/puredns 2>/dev/null || true
cd ~/tools/puredns && go build -o puredns . && sudo mv puredns /usr/local/bin/ && cd ~

echo "[✓] Subdomain modules installed."

