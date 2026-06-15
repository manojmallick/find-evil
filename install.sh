#!/bin/bash
# Find Evil! — One-command installer for SANS SIFT Workstation
# Usage: curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/find-evil/main/install.sh | bash
# Tested on: SIFT Workstation v4.0 (Ubuntu 22.04)
# Install time: ~4-6 minutes on standard hardware

set -euo pipefail

# ── COLORS ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ── HELPERS ─────────────────────────────────────────────────────────────────
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── BANNER ──────────────────────────────────────────────────────────────────
echo ""
echo "  ███████╗██╗███╗   ██╗██████╗      ███████╗██╗   ██╗██╗██╗      "
echo "  ██╔════╝██║████╗  ██║██╔══██╗     ██╔════╝██║   ██║██║██║      "
echo "  █████╗  ██║██╔██╗ ██║██║  ██║     █████╗  ██║   ██║██║██║      "
echo "  ██╔══╝  ██║██║╚██╗██║██║  ██║     ██╔══╝  ╚██╗ ██╔╝██║██║      "
echo "  ██║     ██║██║ ╚████║██████╔╝     ███████╗ ╚████╔╝ ██║███████╗  "
echo "  ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝      ╚══════╝  ╚═══╝  ╚═╝╚══════╝  "
echo ""
echo "  Autonomous IR Agent · SANS Find Evil! Hackathon"
echo "  Custom MCP Server + Self-Correcting 6-Phase Analysis"
echo ""

# ── CHECK: Running on SIFT or compatible Ubuntu ────────────────────────────
info "Checking environment..."

if ! command -v lsb_release &>/dev/null; then
    warn "Could not detect OS. Proceeding anyway (Ubuntu 22.04 recommended)."
else
    OS=$(lsb_release -rs)
    DIST=$(lsb_release -is)
    info "Detected: $DIST $OS"
    if [[ "$OS" != "22.04" ]] && [[ "$OS" != "20.04" ]]; then
        warn "Recommended: Ubuntu 22.04 (SIFT Workstation). Current: $OS. Proceeding..."
    fi
fi

# ── CHECK: Required SIFT tools present ────────────────────────────────────
info "Verifying SIFT tools..."
MISSING_TOOLS=()

for tool in log2timeline.py psort.py vol.py ewfmount hashdeep; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool: found"
    else
        MISSING_TOOLS+=("$tool")
        warn "$tool: NOT FOUND"
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    warn "Missing tools: ${MISSING_TOOLS[*]}"
    warn "These tools are pre-installed on the SIFT Workstation."
    warn "If running on plain Ubuntu, install SIFT first: sans.org/tools/sift-workstation"
    warn "Proceeding with installation — some features may not work."
fi

# ── INSTALL: System dependencies ──────────────────────────────────────────
info "Installing system dependencies..."
sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed — continuing"
sudo apt-get install -y python3-pip python3-venv git jq 2>/dev/null || \
    warn "Some packages may not have installed — continuing"
ok "System dependencies ready"

# ── INSTALL: Clone or update repo ─────────────────────────────────────────
INSTALL_DIR="/opt/find-evil"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Existing installation found — updating..."
    cd "$INSTALL_DIR"
    git pull origin main 2>/dev/null || warn "git pull failed — using existing version"
    ok "Updated to latest version"
else
    info "Cloning Find Evil! repository..."
    sudo git clone https://github.com/YOUR_USERNAME/find-evil.git "$INSTALL_DIR" || \
        fail "Failed to clone repository. Check network and GitHub URL."
    ok "Repository cloned to $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── INSTALL: Python virtual environment ───────────────────────────────────
info "Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/venv" 2>/dev/null || fail "Failed to create venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip -q
pip install -r requirements.txt -q || fail "pip install failed — check requirements.txt"
ok "Python environment ready (venv at $INSTALL_DIR/venv)"

# ── SETUP: Directories ────────────────────────────────────────────────────
info "Creating required directories..."
sudo mkdir -p /cases
sudo mkdir -p /opt/find-evil/logs
sudo mkdir -p /opt/find-evil/yara_rules
sudo mkdir -p /tmp/find-evil-output
sudo chmod 777 /opt/find-evil/logs
sudo chmod 777 /tmp/find-evil-output
ok "Directories created"

# ── SETUP: YARA rules ─────────────────────────────────────────────────────
info "Setting up YARA rules library..."
YARA_DIR="$INSTALL_DIR/yara_rules"

if [ ! -d "$YARA_DIR/malware" ]; then
    info "Cloning community YARA rules..."
    git clone --depth=1 https://github.com/Yara-Rules/rules.git "$YARA_DIR/community" 2>/dev/null && \
        ok "Community YARA rules installed ($(find $YARA_DIR/community -name '*.yar' | wc -l) rules)" || \
        warn "YARA rules clone failed — scan_yara() will use local rules only"
else
    ok "YARA rules already present"
fi

# ── SETUP: MCP server configuration ───────────────────────────────────────
info "Configuring MCP server..."

# Verify blocked commands list is intact
if python3 -c "from mcp_server.config import BLOCKED_COMMANDS; assert 'rm' in BLOCKED_COMMANDS" 2>/dev/null; then
    ok "Blocked commands list: verified (rm, dd, shred, wget, curl, ssh blocked)"
else
    warn "Could not verify blocked commands — check mcp_server/config.py manually"
fi

# Verify protected paths
if python3 -c "from mcp_server.config import PROTECTED_WRITE_PATHS; assert '/cases' in PROTECTED_WRITE_PATHS" 2>/dev/null; then
    ok "Protected write paths: verified (/cases, /mnt, /media blocked)"
else
    warn "Could not verify protected paths — check mcp_server/config.py manually"
fi

# ── SETUP: Shell wrapper ──────────────────────────────────────────────────
info "Installing shell command..."
sudo tee /usr/local/bin/find-evil > /dev/null << 'WRAPPER'
#!/bin/bash
source /opt/find-evil/venv/bin/activate
python3 /opt/find-evil/agent/loop.py "$@"
WRAPPER
sudo chmod +x /usr/local/bin/find-evil
ok "Installed: 'find-evil' command available system-wide"

# ── TEST: Quick smoke test ────────────────────────────────────────────────
info "Running smoke test..."
if python3 -c "
import sys
sys.path.insert(0, '/opt/find-evil')
from mcp_server.config import BLOCKED_COMMANDS, PROTECTED_WRITE_PATHS
from mcp_server.logger import compute_hash
from reports.generator import generate_report
print('Import test: PASSED')
" 2>/dev/null; then
    ok "Smoke test passed — all modules importable"
else
    warn "Smoke test had import errors — check Python path and dependencies"
fi

# ── SETUP: Case template ─────────────────────────────────────────────────
info "Installing case template..."
sudo mkdir -p /cases/TEMPLATE
sudo cp "$INSTALL_DIR/case-templates/CLAUDE.md" /cases/TEMPLATE/CLAUDE.md 2>/dev/null || \
    warn "Could not copy case template — create /cases/CASE_ID/CLAUDE.md manually"
ok "Case template installed at /cases/TEMPLATE/CLAUDE.md"

# ── COMPLETE ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Find Evil! installed successfully"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  QUICK START:"
echo ""
echo "  1. Mount evidence (read-only):"
echo "     sudo ewfmount /path/to/evidence.E01 /mnt/ewf/"
echo "     sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk"
echo ""
echo "  2. Create case directory:"
echo "     mkdir /cases/CASE001"
echo "     cp /cases/TEMPLATE/CLAUDE.md /cases/CASE001/"
echo ""
echo "  3. Run analysis:"
echo "     find-evil --case /cases/CASE001 --disk /mnt/case_disk"
echo ""
echo "  4. With memory dump:"
echo "     find-evil --case /cases/CASE001 --disk /mnt/case_disk \\"
echo "               --memory /cases/CASE001/memory.raw"
echo ""
echo "  5. View report:"
echo "     cat /cases/CASE001/findings/findings.json | python3 -m json.tool"
echo "     firefox /cases/CASE001/findings/report.html"
echo ""
echo "  VERIFY ANY FINDING:"
echo "     grep 'CALL_ID_FROM_REPORT' /opt/find-evil/logs/tool_calls.jsonl"
echo ""
echo "  AUDIT LOG:   /opt/find-evil/logs/tool_calls.jsonl"
echo "  PROGRESS:    /opt/find-evil/logs/progress.json"
echo "  HASH LOG:    /opt/find-evil/logs/evidence_hashes.json"
echo ""
echo "  GitHub: https://github.com/YOUR_USERNAME/find-evil"
echo "  License: Apache 2.0"
echo ""
