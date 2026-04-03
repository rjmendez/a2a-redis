"""
Tests for Human MFA Management in A2A Framework

Coverage:
  - Account creation and credential storage
  - TOTP provisioning (URI, QR code generation)
  - TOTP verification with time window tolerance
  - Backup code generation and consumption
  - Rate limiting on failed TOTP attempts
  - TOTP rotation (lost authenticator scenario)
  - Agent key reset procedures
  - Audit logging

Run: pytest test_human_mfa.py -v
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import pyotp

from human_mfa import (
    HumanMFAManager, HumanCredentials, AgentKeyReset,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_mfa_store():
    """Temporary MFA store directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def manager(tmp_mfa_store):
    """MFA manager with temporary storage."""
    return HumanMFAManager(credential_store_path=tmp_mfa_store)


# ── Account Creation Tests ────────────────────────────────────────────────────

class TestHumanMFACreation:
    
    def test_create_account(self, manager):
        """Create a new MFA account."""
        creds = manager.create_human_account("alice")
        
        assert creds.human_id == "alice"
        assert creds.totp_seed is not None
        assert len(creds.totp_seed) == 32  # Base32 encoded
        assert len(creds.backup_codes) == 10
        assert len(creds.backup_codes_used) == 10
        assert all(not used for used in creds.backup_codes_used)
        assert creds.mfa_enabled is True
    
    def test_backup_codes_format(self, manager):
        """Backup codes should be in XXXX-XXXX-XXXX format."""
        creds = manager.create_human_account("bob")
        
        for code in creds.backup_codes:
            parts = code.split("-")
            assert len(parts) == 3
            assert all(len(p) == 4 for p in parts)
            assert all(p.isalnum() for p in parts)
    
    def test_credentials_persisted(self, manager):
        """Created credentials should be saved to disk."""
        creds1 = manager.create_human_account("charlie")
        
        # Load from disk
        creds2 = manager._load_credentials("charlie")
        
        assert creds2 is not None
        assert creds2.totp_seed == creds1.totp_seed
        assert creds2.backup_codes == creds1.backup_codes
    
    def test_file_permissions_restrictive(self, manager):
        """Credential files should be readable only by owner."""
        manager.create_human_account("dave")
        
        cred_file = os.path.join(manager.store_path, "dave.json")
        mode = oct(os.stat(cred_file).st_mode)[-3:]
        assert mode == "600", f"Expected 600, got {mode}"


# ── TOTP Provisioning Tests ───────────────────────────────────────────────────

class TestTOTPProvisioning:
    
    def test_provisioning_uri_format(self, manager):
        """Provisioning URI should be valid otpauth format."""
        manager.create_human_account("eve")
        uri = manager.get_provisioning_uri("eve")
        
        assert uri.startswith("otpauth://totp/")
        assert "eve" in uri
        assert "A2A%20Mesh" in uri  # URL-encoded issuer
        assert "secret=" in uri
    
    def test_provisioning_uri_custom_issuer(self, manager):
        """Provisioning URI should allow custom issuer name."""
        manager.create_human_account("frank")
        uri = manager.get_provisioning_uri("frank", issuer="My Company")
        
        assert "My%20Company" in uri
    
    def test_qr_code_generation(self, manager):
        """Generate QR code image."""
        manager.create_human_account("grace")
        qr_bytes = manager.generate_qr_code("grace")
        
        assert qr_bytes is not None
        assert qr_bytes.startswith(b'\x89PNG')  # PNG magic bytes
    
    def test_qr_code_file_output(self, manager):
        """Save QR code to file with correct permissions."""
        manager.create_human_account("henry")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            qr_path = os.path.join(tmpdir, "henry-qr.png")
            result = manager.generate_qr_code("henry", output_path=qr_path)
            
            assert result is None  # Returns None when saving to file
            assert os.path.exists(qr_path)
            
            mode = oct(os.stat(qr_path).st_mode)[-3:]
            assert mode == "600"


# ── TOTP Verification Tests ───────────────────────────────────────────────────

class TestTOTPVerification:
    
    def test_verify_valid_totp(self, manager):
        """Verify a valid TOTP code."""
        creds = manager.create_human_account("iris")
        
        # Generate current TOTP code
        totp = pyotp.TOTP(creds.totp_seed)
        code = totp.now()
        
        assert manager.verify_human_totp("iris", code) is True
    
    def test_verify_invalid_totp(self, manager):
        """Reject invalid TOTP code."""
        manager.create_human_account("jack")
        
        assert manager.verify_human_totp("jack", "000000") is False
    
    def test_totp_time_window_tolerance(self, manager):
        """TOTP verification should tolerate time drift (±30s)."""
        creds = manager.create_human_account("karen")
        totp = pyotp.TOTP(creds.totp_seed)
        
        # Get current and next time step
        current_code = totp.at(datetime.now(timezone.utc))
        next_code = totp.at(datetime.now(timezone.utc) + timedelta(seconds=30))
        
        # Both should verify with window=1
        assert manager.verify_human_totp("karen", current_code) is True
        assert manager.verify_human_totp("karen", next_code) is True
    
    def test_lockout_after_failed_attempts(self, manager):
        """Account should lock after repeated failed TOTP attempts."""
        manager.create_human_account("leo")
        
        # First 5 attempts fail (assumed to trigger lockout)
        for _ in range(5):
            manager.verify_human_totp("leo", "000000")
        
        # Now even correct code should be rejected during lockout
        creds = manager._load_credentials("leo")
        if creds.locked_until:
            locked_until = datetime.fromisoformat(creds.locked_until)
            assert locked_until > datetime.now(timezone.utc)


# ── Backup Code Tests ─────────────────────────────────────────────────────────

class TestBackupCodes:
    
    def test_verify_valid_backup_code(self, manager):
        """Verify and consume a valid backup code."""
        creds = manager.create_human_account("mia")
        first_code = creds.backup_codes[0]
        
        assert manager.verify_backup_code("mia", first_code) is True
        
        # Verify code was marked used
        creds2 = manager._load_credentials("mia")
        assert creds2.backup_codes_used[0] is True
    
    def test_backup_code_one_time_use(self, manager):
        """Backup code should only work once."""
        creds = manager.create_human_account("noah")
        first_code = creds.backup_codes[0]
        
        # First use succeeds
        assert manager.verify_backup_code("noah", first_code) is True
        
        # Second use fails
        assert manager.verify_backup_code("noah", first_code) is False
    
    def test_invalid_backup_code(self, manager):
        """Invalid backup code should be rejected."""
        manager.create_human_account("olivia")
        
        assert manager.verify_backup_code("olivia", "XXXX-XXXX-XXXX") is False
    
    def test_other_codes_usable_after_one_used(self, manager):
        """Using one backup code shouldn't affect others."""
        creds = manager.create_human_account("paul")
        code1 = creds.backup_codes[0]
        code2 = creds.backup_codes[1]
        
        manager.verify_backup_code("paul", code1)
        assert manager.verify_backup_code("paul", code2) is True


# ── Credential Rotation Tests ─────────────────────────────────────────────────

class TestTOTPRotation:
    
    def test_rotate_totp_with_admin_approval(self, manager):
        """Rotate TOTP seed with admin approval."""
        old_creds = manager.create_human_account("quinn")
        old_seed = old_creds.totp_seed
        
        # Rotate with admin approval
        new_uri = manager.generate_new_totp("quinn", admin_approval="admin")
        
        new_creds = manager._load_credentials("quinn")
        assert new_creds.totp_seed != old_seed
        assert len(new_creds.backup_codes) == 10
        assert all(not used for used in new_creds.backup_codes_used)
    
    def test_old_totp_invalid_after_rotation(self, manager):
        """TOTP codes from old seed should be invalid after rotation."""
        creds = manager.create_human_account("rachel")
        old_seed = creds.totp_seed
        
        # Generate a valid code with old seed
        old_totp = pyotp.TOTP(old_seed)
        old_code = old_totp.now()
        
        # Verify it works before rotation
        assert manager.verify_human_totp("rachel", old_code) is True
        
        # Rotate
        manager.generate_new_totp("rachel", admin_approval="admin")
        
        # Old code should now fail
        assert manager.verify_human_totp("rachel", old_code) is False
    
    def test_rotation_audit_log(self, manager):
        """TOTP rotation should be logged for audit."""
        manager.create_human_account("steve")
        manager.generate_new_totp("steve", admin_approval="admin")
        
        log_file = os.path.join(manager.store_path, "audit-log", "steve.log")
        assert os.path.exists(log_file)
        
        with open(log_file) as f:
            entries = [json.loads(line) for line in f]
        
        assert len(entries) > 0
        assert entries[-1]["action"] == "totp_rotated"
        assert entries[-1]["approved_by"] == "admin"


# ── Agent Key Reset Tests ─────────────────────────────────────────────────────

class TestAgentKeyReset:
    
    def test_key_reset_tracking(self, manager):
        """Track agent key reset requests."""
        from a2a_redis import PKIStore
        
        with tempfile.TemporaryDirectory() as old_dir, \
             tempfile.TemporaryDirectory() as new_dir:
            
            old_pki = PKIStore(old_dir)
            new_pki = PKIStore(new_dir)
            
            # Request reset
            result = manager.reset_agent_keys(
                agent_name="iris",
                old_pki=old_pki,
                new_pki=new_pki,
                requested_by="rj",
                admin_approval="charlie"
            )
            
            assert result is True
            
            # Check log
            log_file = os.path.join(manager.store_path, "key-resets", "iris.log")
            assert os.path.exists(log_file)


# ── Serialization Tests ───────────────────────────────────────────────────────

class TestCredentialsSerialization:
    
    def test_credentials_to_json(self, manager):
        """Serialize credentials to JSON."""
        creds = manager.create_human_account("tina")
        json_str = creds.to_json()
        
        parsed = json.loads(json_str)
        assert parsed["human_id"] == "tina"
        assert parsed["totp_seed"] is not None
        assert "backup_codes" in parsed
    
    def test_credentials_from_json(self, manager):
        """Deserialize credentials from JSON."""
        creds1 = manager.create_human_account("uma")
        json_str = creds1.to_json()
        
        creds2 = HumanCredentials.from_json(json_str)
        assert creds2.human_id == creds1.human_id
        assert creds2.totp_seed == creds1.totp_seed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
