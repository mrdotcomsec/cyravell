#!/usr/bin/env python3
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Cyravell Standalone Release Verifier
Independent, zero-dependency/minimal-dependency pre-installation verification tool.
Validates release manifests, Ed25519 cryptographic signatures, and artifact digests
without executing any downloaded binary.
"""

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# RFC 8032 Ed25519 pure Python implementation (Zero external dependency fallback)
_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493
_I = pow(2, (_P - 1) // 4, _P)

def _inv(z):
    return pow(z, _P - 2, _P)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x

def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _P
    return (x3, y3)

def _scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q

_By = 4 * _inv(5) % _P
_Bx = _xrecover(_By)
_B = (_Bx, _By)

def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _P - x
    return (x, y)

def verify_ed25519_signature(pubkey_bytes, sig_bytes, msg_bytes):
    """
    Verifies an Ed25519 signature. Uses cryptography package if available,
    otherwise falls back to RFC 8032 pure-Python implementation.
    """
    if len(pubkey_bytes) != 32 or len(sig_bytes) != 64:
        return False

    if HAS_CRYPTOGRAPHY:
        try:
            vk = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            vk.verify(sig_bytes, msg_bytes)
            return True
        except Exception:
            return False

    # Pure Python RFC 8032 fallback
    try:
        R_bytes = sig_bytes[:32]
        S_bytes = sig_bytes[32:]
        s = int.from_bytes(S_bytes, "little")
        if s >= _Q:
            return False
        A = _decodepoint(pubkey_bytes)
        R = _decodepoint(R_bytes)
        h = hashlib.sha512(R_bytes + pubkey_bytes + msg_bytes).digest()
        k = int.from_bytes(h, "little") % _Q
        SB = _scalarmult(_B, s)
        kA = _scalarmult(A, k)
        R_plus_kA = _edwards_add(R, kA)
        return SB == R_plus_kA
    except Exception:
        return False

DEFAULT_OFFICIAL_PUBKEY_HEX = "9e9f6bf692b6f360a13419327f445a4378357219dea595f6c468916d60ef8a78"
DEFAULT_OFFICIAL_KEY_ID = "cyravell-release-official-2026"
DEFAULT_DEV_PUBKEY_HEX = "46e59f5579ecb6852665043f138d994df7688022c8e4c55aba4ad891a8d61c75"
DEFAULT_DEV_KEY_ID = "cyravell-dev-test-2026"


def compute_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def canonical_signing_bytes(manifest):
    out = []
    out.append("CYRAVELL-RELEASE-MANIFEST-V1\n")
    out.append(f"product_name:{manifest.get('product_name', '')}\n")
    out.append(f"release_version:{manifest.get('release_version', '')}\n")
    out.append(f"source_commit:{manifest.get('source_commit', '')}\n")
    out.append(f"source_tag:{manifest.get('source_tag') or ''}\n")
    out.append(f"build_timestamp:{manifest.get('build_timestamp', '')}\n")
    out.append(f"engine_version:{manifest.get('engine_version', '')}\n")
    out.append(f"extension_version:{manifest.get('extension_version', '')}\n")
    out.append(f"signing_mode:{manifest.get('signing_mode') or 'official'}\n")
    tp_str = ",".join(manifest.get("target_platforms", []))
    out.append(f"target_platforms:{tp_str}\n")
    out.append("artifacts:\n")
    artifacts = manifest.get("artifacts", {})
    # Note: BTreeMap in Rust iterates in lexicographical order by key!
    for name in sorted(artifacts.keys()):
        art = artifacts[name]
        size = art.get("size_bytes", 0)
        sha = (art.get("sha256") or "").lower()
        atype = art.get("artifact_type", "")
        tplat = art.get("target_platform") or ""
        out.append(f"{name}:{size}:{sha}:{atype}:{tplat}\n")
    out.append("required_runtime_components:\n")
    reqs = sorted(manifest.get("required_runtime_components", []))
    for req in reqs:
        out.append(f"{req}\n")
    sbom = manifest.get("sbom", {})
    s_fn = sbom.get("filename", "")
    s_sha = (sbom.get("sha256") or "").lower()
    s_fmt = sbom.get("format", "")
    out.append(f"sbom:{s_fn}:{s_sha}:{s_fmt}\n")
    return "".join(out).encode("utf-8")


def load_keystore(keys_file_path):
    candidates = []
    if keys_file_path:
        candidates.append(keys_file_path)

    # Check relative to script and working directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(script_dir, "..", "rules", "release_signing_keys.json"))
    candidates.append(os.path.join(os.getcwd(), "rules", "release_signing_keys.json"))

    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return {k["key_id"]: k for k in data.get("keys", [])}
            except Exception:
                pass

    # Embedded fallback
    return {
        DEFAULT_OFFICIAL_KEY_ID: {
            "key_id": DEFAULT_OFFICIAL_KEY_ID,
            "publisher": "Cyravell Core Release Authority (Embedded)",
            "public_key_hex": DEFAULT_OFFICIAL_PUBKEY_HEX,
            "algorithm": "ed25519",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": None,
            "is_active": True,
            "is_official": True,
        },
        DEFAULT_DEV_KEY_ID: {
            "key_id": DEFAULT_DEV_KEY_ID,
            "publisher": "Cyravell Development & Test Authority (Embedded)",
            "public_key_hex": DEFAULT_DEV_PUBKEY_HEX,
            "algorithm": "ed25519",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": None,
            "is_active": True,
            "is_official": False,
        },
    }


def parse_strict_json(path):
    def reject_duplicates(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"Duplicate key '{k}' detected in JSON")
            d[k] = v
        return d

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=reject_duplicates)


def verify_release(manifest_path, artifacts_dir, keys_file=None,
                   expected_version=None, expected_commit=None, allow_dev_keys=False):
    errors = []

    print("══════════════════════════════════════════════════════════════")
    print("      Cyravell Independent Standalone Release Verifier        ")
    print("══════════════════════════════════════════════════════════════")
    print(f"  Manifest:     {manifest_path}")
    print(f"  Artifacts:    {artifacts_dir}")
    print(f"  Require Prod: {not allow_dev_keys}")
    print("──────────────────────────────────────────────────────────────")

    if not os.path.isfile(manifest_path):
        print(f"✗ Error: Manifest '{manifest_path}' does not exist.")
        return 1

    if not os.path.isdir(artifacts_dir):
        print(f"✗ Error: Artifacts directory '{artifacts_dir}' does not exist.")
        return 1

    try:
        manifest = parse_strict_json(manifest_path)
    except Exception as e:
        print(f"✗ Error: Failed to parse manifest JSON: {e}")
        return 1

    # Basic manifest checks
    product_name = manifest.get("product_name")
    if product_name != "cyravell":
        errors.append(f"Unexpected product_name '{product_name}' (expected 'cyravell')")

    rel_version = manifest.get("release_version")
    if expected_version and rel_version != expected_version:
        errors.append(f"Release version mismatch: manifest has '{rel_version}', expected '{expected_version}'")

    source_commit = manifest.get("source_commit")
    if expected_commit and source_commit != expected_commit:
        errors.append(f"Source commit mismatch: manifest has '{source_commit}', expected '{expected_commit}'")

    signing_mode = manifest.get("signing_mode", "official")
    if not allow_dev_keys and signing_mode == "development":
        errors.append("Manifest specifies development signing mode; official verification requires official mode")

    # Keystore and signature check
    keystore = load_keystore(keys_file)
    key_id = manifest.get("signing_key_id")
    signature_hex = manifest.get("signature")

    if not key_id or not signature_hex:
        errors.append("Manifest is unsigned or missing key ID")
        key_info = None
    elif key_id not in keystore:
        errors.append(f"Release signing key '{key_id}' is not in the trusted keystore")
        key_info = None
    else:
        key_info = keystore[key_id]
        if not key_info.get("is_active", False):
            errors.append(f"Release signing key '{key_id}' has been deactivated/revoked")

        expires_at = key_info.get("expires_at")
        if expires_at:
            try:
                exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp_dt:
                    errors.append(f"Release signing key '{key_id}' expired at {expires_at}")
            except Exception as e:
                errors.append(f"Failed to parse key expiration date: {e}")

        is_official = key_info.get("is_official", False)
        if not allow_dev_keys and not is_official:
            errors.append(f"Untrusted key role: Key '{key_id}' is designated as development/test only; official production release signing key is required")

        try:
            pub_bytes = bytes.fromhex(key_info["public_key_hex"])
            sig_bytes = bytes.fromhex(signature_hex)
            c_bytes = canonical_signing_bytes(manifest)
            if verify_ed25519_signature(pub_bytes, sig_bytes, c_bytes):
                engine_type = "accelerated" if HAS_CRYPTOGRAPHY else "standard Python RFC 8032"
                print(f"  ✓ Signature verified with key '{key_id}' ({key_info.get('publisher')}) [{engine_type}]")
            else:
                errors.append(f"Cryptographic signature verification failed for key '{key_id}'")
        except Exception as e:
            errors.append(f"Cryptographic signature verification error: {e}")

    # Check artifacts
    artifacts = manifest.get("artifacts", {})
    verified_count = 0
    missing = []
    tampered = []

    for name, art in artifacts.items():
        # Directory traversal check
        if ".." in name or name.startswith("/") or "\\" in name or "\0" in name:
            errors.append(f"Security violation: artifact filename '{name}' contains directory traversal")
            continue

        art_path = os.path.join(artifacts_dir, name)
        try:
            st = os.lstat(art_path)
        except FileNotFoundError:
            missing.append(name)
            continue
        except Exception as e:
            errors.append(f"Failed to stat artifact '{name}': {e}")
            continue

        if stat.S_ISLNK(st.st_mode):
            errors.append(f"Security violation: artifact '{name}' is a symbolic link")
            tampered.append(name)
            continue

        if not stat.S_ISREG(st.st_mode):
            errors.append(f"Security violation: artifact '{name}' is not a regular file")
            tampered.append(name)
            continue

        exp_size = art.get("size_bytes", 0)
        if st.st_size != exp_size:
            errors.append(f"Artifact size mismatch for '{name}': manifest expects {exp_size}, file is {st.st_size}")
            tampered.append(name)
            continue

        exp_sha = (art.get("sha256") or "").lower()
        actual_sha = compute_sha256(art_path)
        if actual_sha != exp_sha:
            errors.append(f"SHA-256 mismatch for '{name}': manifest expects {exp_sha}, file is {actual_sha}")
            tampered.append(name)
            continue

        verified_count += 1

    # Check SBOM
    sbom = manifest.get("sbom", {})
    sbom_fn = sbom.get("filename", "")
    if sbom_fn:
        sbom_path = os.path.join(artifacts_dir, sbom_fn)
        try:
            st = os.lstat(sbom_path)
            if stat.S_ISLNK(st.st_mode):
                errors.append(f"Security violation: SBOM '{sbom_fn}' is a symbolic link")
            elif not stat.S_ISREG(st.st_mode):
                errors.append(f"Security violation: SBOM '{sbom_fn}' is not a regular file")
            else:
                exp_sbom_sha = (sbom.get("sha256") or "").lower()
                act_sbom_sha = compute_sha256(sbom_path)
                if exp_sbom_sha != act_sbom_sha:
                    errors.append(f"SBOM SHA-256 mismatch: manifest expects {exp_sbom_sha}, file is {act_sbom_sha}")
        except FileNotFoundError:
            if sbom_fn not in missing:
                missing.append(sbom_fn)
                errors.append(f"SBOM file '{sbom_fn}' is missing")
        except Exception as e:
            errors.append(f"Failed to stat SBOM '{sbom_fn}': {e}")

    # Inspect directory for unexpected files
    try:
        manifest_basename = os.path.basename(manifest_path)
        for entry in os.scandir(artifacts_dir):
            if entry.name == manifest_basename or \
               entry.name.endswith(".sig") or \
               entry.name.endswith(".sha256") or \
               entry.name == "SHA256SUMS" or \
               entry.name == "SHA256SUMS.sig":
                continue

            if entry.is_symlink():
                errors.append(f"Security violation: unlisted symbolic link '{entry.name}' in release directory")
            elif entry.name not in artifacts and entry.name != sbom_fn:
                if entry.name.endswith((".sh", ".bin", ".py", ".exe", ".so")):
                    errors.append(f"Security violation: unlisted executable file '{entry.name}' found in release directory")
                elif not allow_dev_keys:
                    errors.append(f"Security violation: unlisted file '{entry.name}' in official release directory")
    except Exception as e:
        errors.append(f"Failed to inspect release directory: {e}")

    # Check detached signature match
    detached_sig_path = f"{manifest_path}.sig"
    if os.path.isfile(detached_sig_path) and signature_hex:
        with open(detached_sig_path, "r", encoding="utf-8") as f:
            det_sig = f.read().strip()
            if det_sig != signature_hex:
                errors.append(f"Detached signature '{detached_sig_path}' does not match embedded manifest signature")

    # Check SHA256SUMS consistency
    sums_path = os.path.join(artifacts_dir, "SHA256SUMS")
    if os.path.isfile(sums_path):
        with open(sums_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    chk_sha, chk_fn = parts[0].strip().lower(), parts[1].strip().lstrip("*")
                    target = os.path.join(artifacts_dir, chk_fn)
                    if os.path.isfile(target) and not os.path.islink(target):
                        actual = compute_sha256(target)
                        if actual != chk_sha:
                            errors.append(f"SHA256SUMS entry mismatch for '{chk_fn}': expected {chk_sha}, computed {actual}")

    print("──────────────────────────────────────────────────────────────")
    if missing:
        print(f"✗ Missing artifacts ({len(missing)}): {', '.join(missing)}")
    if tampered:
        print(f"✗ Tampered artifacts ({len(tampered)}): {', '.join(tampered)}")
    if errors:
        print(f"✗ Verification FAILED with {len(errors)} error(s):")
        for err in errors:
            print(f"  • {err}")
        print("══════════════════════════════════════════════════════════════")
        print("  CRITICAL: DO NOT INSTALL OR EXECUTE ANY ARTIFACTS FROM THIS PACKAGE.")
        print("══════════════════════════════════════════════════════════════")
        return 1

    print("✓ VERIFICATION SUCCESSFUL!")
    print(f"  Product:           {product_name}")
    print(f"  Version:           {rel_version}")
    print(f"  Commit:            {source_commit}")
    print(f"  Mode:              {'OFFICIAL RELEASE' if key_info.get('is_official') else 'DEVELOPMENT / TEST'}")
    print(f"  Verified Files:    {verified_count} regular files bit-for-bit matched")
    print(f"  Signing Key:       {key_id} ({key_info.get('publisher')})")
    print("══════════════════════════════════════════════════════════════")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Cyravell Standalone Release Package Verifier (Independent Trust Path)"
    )
    parser.add_argument("--manifest", required=True, help="Path to release_manifest.json")
    parser.add_argument("--artifacts-dir", required=True, help="Path to release artifacts directory")
    parser.add_argument("--keys-file", default=None, help="Path to release_signing_keys.json")
    parser.add_argument("--expected-version", default=None, help="Expected release version")
    parser.add_argument("--expected-commit", default=None, help="Expected source git commit SHA")
    parser.add_argument(
        "--allow-dev-keys",
        action="store_true",
        help="Allow development/test signing keys (default: require official release keys)",
    )

    args = parser.parse_args()
    rc = verify_release(
        args.manifest,
        args.artifacts_dir,
        args.keys_file,
        args.expected_version,
        args.expected_commit,
        args.allow_dev_keys,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
