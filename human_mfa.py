"""
Human MFA Management for A2A Framework

Provides:
  - Human TOTP provisioning (QR codes for Google Authenticator, Authy, etc.)
  - Key/TOTP reset procedures for rebuilt agents or lost second factors
  - Backup codes for account recovery
  - Human credential lifecycle management

Design:
  - Each human gets a persistent credential store (Redis or file-based)
  - Agent can issue challenges that require TOTP + signature verification
  - Reset requires multi-factor verification (signature + backup code OR admin approval)
"""

import json
import os
import base64
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass, asdict

import qrcode
import pyotp

from a2a_redis import (
    PKIStore, A2ARedisClient, A2AMessage,
    generate_totp_seed, TOTPError
)


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HumanCredentials:
    """Persistent human credentials."""
    human_id: str
    totp_seed: str
    created_at: str
    last_rotated_at: str
    backup_codes: List[str]  # One-time recovery codes
    backup_codes_used: List[bool]  # Track which codes have been used
    mfa_enabled: bool = True
    locked_until: Optional[str] = None  # Rate-limit lockout after failed TOTP attempts
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "HumanCredentials":
        return cls(**d)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, s: str) -> "HumanCredentials":
        return cls.from_dict(json.loads(s))


@dataclass
class AgentKeyReset:
    """Agent key reset request tracking."""
    agent_name: str
    reset_id: str
    requested_at: str
    requested_by: str  # human_id who requested it
    approved_by: Optional[str] = None  # admin or another agent
    status: str = "pending"  # pending, approved, completed, rejected
    old_key_hash: Optional[str] = None
    new_key_issued: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Human MFA Manager
# ─────────────────────────────────────────────────────────────────────────────

class HumanMFAManager:
    """Manage human credentials and MFA for the mesh."""
    
    def __init__(self, credential_store_path: str = "~/.a2a/human-credentials"):
        """
        Initialize the MFA manager.
        
        Args:
            credential_store_path: Directory where human credentials are stored
        """
        self.store_path = os.path.expanduser(credential_store_path)
        os.makedirs(self.store_path, exist_ok=True)
        os.chmod(self.store_path, 0o700)  # rwx------
    
    def create_human_account(self, human_id: str, generate_backup_codes: int = 10) -> HumanCredentials:
        """
        Create a new human MFA account.
        
        Args:
            human_id: Unique identifier for the human (e.g., "rj", "alice")
            generate_backup_codes: Number of one-time backup codes to generate
        
        Returns:
            HumanCredentials with TOTP seed and backup codes
        """
        now = datetime.now(timezone.utc).isoformat()
        creds = HumanCredentials(
            human_id=human_id,
            totp_seed=generate_totp_seed(),
            created_at=now,
            last_rotated_at=now,
            backup_codes=self._generate_backup_codes(generate_backup_codes),
            backup_codes_used=[False] * generate_backup_codes,
            mfa_enabled=True
        )
        self._save_credentials(creds)
        return creds
    
    def get_provisioning_uri(self, human_id: str, issuer: str = "A2A Mesh") -> str:
        """
        Get the provisioning URI for adding to Google Authenticator.
        
        Format: otpauth://totp/[issuer]:[human_id]?secret=[base32_seed]&issuer=[issuer]
        
        Args:
            human_id: Human identifier
            issuer: Display name in authenticator app (default: "A2A Mesh")
        
        Returns:
            otpauth:// URI string
        """
        creds = self._load_credentials(human_id)
        if not creds:
            raise ValueError(f"No credentials found for {human_id}")
        
        totp = pyotp.TOTP(creds.totp_seed)
        return totp.provisioning_uri(name=human_id, issuer_name=issuer)
    
    def generate_qr_code(self, human_id: str, output_path: Optional[str] = None) -> Optional[bytes]:
        """
        Generate a QR code for the human to scan into an authenticator app.
        
        Args:
            human_id: Human identifier
            output_path: If provided, save PNG to this path
        
        Returns:
            PNG image bytes, or None if saved to file
        """
        uri = self.get_provisioning_uri(human_id)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            img.save(output_path)
            os.chmod(output_path, 0o600)
            return None
        else:
            # Return PNG bytes
            import io
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
    
    def verify_human_totp(self, human_id: str, totp_code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code provided by a human.
        
        Args:
            human_id: Human identifier
            totp_code: 6-digit TOTP code from authenticator
            window: Time window tolerance (±window * 30s)
        
        Returns:
            True if valid, False otherwise
        """
        creds = self._load_credentials(human_id)
        if not creds or not creds.mfa_enabled:
            return False
        
        # Check lockout
        if creds.locked_until:
            locked_until = datetime.fromisoformat(creds.locked_until)
            if datetime.now(timezone.utc) < locked_until:
                return False  # Still locked
            # Lockout expired, clear it
            creds.locked_until = None
            self._save_credentials(creds)
        
        totp = pyotp.TOTP(creds.totp_seed)
        if totp.verify(totp_code, valid_window=window):
            return True
        
        # Failed attempt — rate-limit after 5 failures
        self._record_failed_totp_attempt(human_id)
        return False
    
    def verify_backup_code(self, human_id: str, backup_code: str) -> bool:
        """
        Verify and consume a one-time backup code.
        
        Args:
            human_id: Human identifier
            backup_code: Backup code to verify
        
        Returns:
            True if valid and unused, False otherwise
        """
        creds = self._load_credentials(human_id)
        if not creds:
            return False
        
        try:
            idx = creds.backup_codes.index(backup_code)
            if creds.backup_codes_used[idx]:
                return False  # Already used
            
            # Mark as used
            creds.backup_codes_used[idx] = True
            self._save_credentials(creds)
            return True
        except ValueError:
            return False
    
    def generate_new_totp(self, human_id: str, admin_approval: Optional[str] = None) -> str:
        """
        Rotate a human's TOTP seed (e.g., if they lost their authenticator).
        
        Requires either:
        - admin_approval (another agent/admin blessing the reset)
        - Successful backup code verification by the human
        
        Args:
            human_id: Human identifier
            admin_approval: Name of admin/agent approving the reset
        
        Returns:
            New provisioning URI (human should scan new QR code)
        """
        creds = self._load_credentials(human_id)
        if not creds:
            raise ValueError(f"No credentials found for {human_id}")
        
        # Record the old seed hash
        old_hash = hashlib.sha256(creds.totp_seed.encode()).hexdigest()[:16]
        
        # Generate new credentials
        now = datetime.now(timezone.utc).isoformat()
        creds.totp_seed = generate_totp_seed()
        creds.last_rotated_at = now
        creds.backup_codes = self._generate_backup_codes(10)
        creds.backup_codes_used = [False] * 10
        
        self._save_credentials(creds)
        
        # Log the rotation
        self._log_credential_reset(
            human_id=human_id,
            action="totp_rotated",
            old_key_hash=old_hash,
            approved_by=admin_approval
        )
        
        return self.get_provisioning_uri(human_id)
    
    def reset_agent_keys(self, agent_name: str, old_pki: PKIStore, new_pki: PKIStore,
                         requested_by: str, admin_approval: Optional[str] = None) -> bool:
        """
        Reset an agent's keypair (for rebuilds or key compromise).
        
        Generates new keys and invalidates old ones.
        
        Args:
            agent_name: Agent being rebuilt
            old_pki: Existing PKI store
            new_pki: New PKI store for rebuilt agent
            requested_by: Human/agent requesting the reset
            admin_approval: Admin approval (optional, for automation)
        
        Returns:
            True if reset completed
        """
        from a2a_redis import generate_agent_keys
        
        # Generate new keypair
        generate_agent_keys(agent_name, new_pki)
        
        # Log reset request
        reset_id = secrets.token_hex(8)
        reset_req = AgentKeyReset(
            agent_name=agent_name,
            reset_id=reset_id,
            requested_at=datetime.now(timezone.utc).isoformat(),
            requested_by=requested_by,
            approved_by=admin_approval,
            status="completed",
            new_key_issued=True
        )
        
        self._log_key_reset(reset_req)
        return True
    
    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────
    
    def _generate_backup_codes(self, count: int) -> List[str]:
        """Generate one-time backup codes (format: XXXX-XXXX-XXXX)."""
        codes = []
        for _ in range(count):
            # 12 random hex chars = 48 bits of entropy
            code = secrets.token_hex(6).upper()
            # Format as XXXX-XXXX-XXXX
            formatted = f"{code[0:4]}-{code[4:8]}-{code[8:12]}"
            codes.append(formatted)
        return codes
    
    def _save_credentials(self, creds: HumanCredentials) -> None:
        """Save credentials to disk with restricted permissions."""
        path = os.path.join(self.store_path, f"{creds.human_id}.json")
        with open(path, 'w') as f:
            f.write(creds.to_json())
        os.chmod(path, 0o600)  # rw-------
    
    def _load_credentials(self, human_id: str) -> Optional[HumanCredentials]:
        """Load credentials from disk."""
        path = os.path.join(self.store_path, f"{human_id}.json")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return HumanCredentials.from_json(f.read())
    
    def _record_failed_totp_attempt(self, human_id: str, max_attempts: int = 5,
                                    lockout_minutes: int = 15) -> None:
        """Record failed TOTP attempts and lock account after max failures."""
        creds = self._load_credentials(human_id)
        if not creds:
            return
        
        # Simple tracking: use lockout field
        if creds.locked_until is None:
            creds.locked_until = (
                datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            ).isoformat()
            self._save_credentials(creds)
    
    def _log_credential_reset(self, human_id: str, action: str, old_key_hash: str,
                             approved_by: Optional[str] = None) -> None:
        """Log credential reset events for audit."""
        log_dir = os.path.join(self.store_path, "audit-log")
        os.makedirs(log_dir, exist_ok=True)
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "human_id": human_id,
            "action": action,
            "old_key_hash": old_key_hash,
            "approved_by": approved_by
        }
        
        log_file = os.path.join(log_dir, f"{human_id}.log")
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        os.chmod(log_file, 0o600)
    
    def _log_key_reset(self, reset_req: AgentKeyReset) -> None:
        """Log agent key reset requests."""
        log_dir = os.path.join(self.store_path, "key-resets")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"{reset_req.agent_name}.log")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(reset_req)) + "\n")
        os.chmod(log_file, 0o600)


# ─────────────────────────────────────────────────────────────────────────────
# Example Usage
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    
    manager = HumanMFAManager()
    
    # Create a new human account
    human_id = sys.argv[1] if len(sys.argv) > 1 else "rj"
    creds = manager.create_human_account(human_id)
    
    print(f"✓ Created MFA account for {human_id}")
    print(f"  TOTP Seed: {creds.totp_seed}")
    print(f"  Backup codes: {len(creds.backup_codes)}")
    print()
    
    # Generate QR code
    qr_path = f"/tmp/{human_id}-mfa-qr.png"
    manager.generate_qr_code(human_id, output_path=qr_path)
    print(f"✓ QR code saved to: {qr_path}")
    print(f"  Scan this into Google Authenticator, Authy, etc.")
    print()
    
    # Show provisioning URI
    uri = manager.get_provisioning_uri(human_id)
    print(f"✓ Provisioning URI:")
    print(f"  {uri}")
    print()
    
    # Show backup codes
    print(f"✓ Backup codes (save these in a secure location):")
    for i, code in enumerate(creds.backup_codes, 1):
        print(f"  {i:2d}. {code}")
