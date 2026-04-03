#!/bin/bash
#
# setup-agents.sh — Initialize PKI and TOTP for all agents
#
# Usage:
#   ./setup-agents.sh alice bob charlie
#

set -e

KEYS_DIR="${1:-.}/agent-keys"
AGENTS="${@:2}"

if [ -z "$AGENTS" ]; then
    echo "Usage: $0 <keys_dir> <agent1> [agent2] [agent3] ..."
    echo "Example: $0 ./agent-keys alice bob charlie"
    exit 1
fi

mkdir -p "$KEYS_DIR"

echo "Generating keypairs and TOTP seeds for agents..."
echo ""

for agent in $AGENTS; do
    echo "▶ Setting up $agent..."
    
    python3 << PYEOF
from a2a_redis import PKIStore, example_agent_setup
import sys

pki = PKIStore("$KEYS_DIR")
try:
    totp_seed = example_agent_setup("$agent", pki)
    print(f"  ✓ Keypair generated")
    print(f"  ✓ TOTP Seed: {totp_seed}")
except Exception as e:
    print(f"  ✗ Error: {e}")
    sys.exit(1)
PYEOF
    
    echo ""
done

echo "✅ All agents initialized"
echo ""
echo "Next steps:"
echo "1. Store TOTP seeds in your secrets management (Vault, K8s Secrets, etc.)"
echo "2. Mount $KEYS_DIR as read-only volume in containers"
echo "3. Set environment variables for each agent:"
echo "   export AGENT_NAME=alice"
echo "   export TOTP_SEED=<seed_from_above>"
echo "   export PKI_PATH=$KEYS_DIR"
echo ""
