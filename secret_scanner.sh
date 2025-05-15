#!/bin/bash
echo "[+] Installing Git & Secrets Scanners..."

mkdir -p ~/tools

# Gitleaks binary (auto fetch latest tested)
echo "[~] Installing Gitleaks..."
GL_LATEST=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
  | grep browser_download_url | grep linux-amd64.tar.gz | cut -d '"' -f 4)
wget -q "$GL_LATEST" -O gitleaks.tar.gz
mkdir -p gitleaks && tar -xzf gitleaks.tar.gz -C gitleaks
sudo mv gitleaks/gitleaks /usr/local/bin/
rm -rf gitleaks.tar.gz gitleaks
gitleaks version && echo "[✓] Gitleaks installed."

# Trufflehog
echo "[~] Installing Trufflehog..."
go install github.com/trufflesecurity/trufflehog@latest

# GitDorksGo
echo "[~] Installing GitDorksGo..."
go install github.com/damit5/gitdorks_go@latest

# Shhgit (lightweight GitHub secret scanner)
echo "[~] Installing shhgit..."
git clone https://github.com/eth0izzle/shhgit.git ~/tools/shhgit 2>/dev/null || true
cd ~/tools/shhgit && go build && sudo mv shhgit /usr/local/bin/ && cd ~
echo "[✓] Shhgit installed."

# GitGraber (secret leaks via regex + dorks)
echo "[~] Installing GitGraber..."
git clone https://github.com/hisxo/gitGraber.git ~/tools/gitGraber 2>/dev/null || true
cd ~/tools/gitGraber && pip3 install -r requirements.txt && cd ~
echo "[✓] GitGraber installed."

# GitHub-Search (Python recon tool for secret hunting)
echo "[~] Installing GitHub-Search..."
git clone https://github.com/gwen001/github-search.git ~/tools/github-search 2>/dev/null || true
cd ~/tools/github-search && pip3 install -r requirements.txt && cd ~
echo "[✓] GitHub-Search installed."

echo "[✓] All secrets scanning tools installed successfully."
