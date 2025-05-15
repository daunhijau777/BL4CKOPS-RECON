#!/bin/bash
echo "[+] Installing Vulnerability Scanners & Misconfig Tools..."

go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip3 install wafw00f

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh 2>/dev/null || true
sudo ln -sf ~/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# smuggler
git clone https://github.com/defparam/smuggler.git ~/tools/smuggler 2>/dev/null || true

# corsy
git clone https://github.com/s0md3v/Corsy.git ~/tools/corsy 2>/dev/null || true

# gospider
go install github.com/jaeles-project/gospider@latest

# crlfuzz
git clone https://github.com/dwisiswant0/crlfuzz.git ~/tools/crlfuzz 2>/dev/null || true
cd ~/tools/crlfuzz && go build . && sudo mv crlfuzz /usr/local/bin && cd ~

echo "[✓] Vuln scanners installed."
