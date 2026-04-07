"""
Advanced FILE model evaluation with synthetic PE samples
Tests model behavior with different types of PE files
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add Scamurai module to path
SCAMURAI_ROOT = Path(__file__).resolve().parent / "Scamurai"
if str(SCAMURAI_ROOT) not in sys.path:
    sys.path.insert(0, str(SCAMURAI_ROOT))


def test_real_pe_files() -> None:
    """Test with real PE files from system."""
    from backend.services.file_service import predict_file
    from backend.config import get_threshold_config
    
    print("\n" + "=" * 80)
    print("ADVANCED TEST: Real PE Files Analysis")
    print("=" * 80)
    
    # Common system PE files to test
    pe_files = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\explorer.exe",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\svchost.exe",
    ]
    
    config = get_threshold_config("file")
    results = []
    
    for pe_path in pe_files:
        path = Path(pe_path)
        if not path.exists():
            continue
        
        try:
            with open(path, "rb") as f:
                raw = f.read()
            
            result = predict_file(path.name, raw)
            results.append({
                "filename": path.name,
                "verdict": result.get("verdict"),
                "status": result.get("status"),
                "risk_score": result.get("risk_score"),
                "confidence": result.get("confidence"),
                "risk_flag": result.get("risk_flag"),
                "whitelist_hit": "whitelist" in result.get("model_agreement", ""),
                "model_version": result.get("model_info", {}).get("model_version"),
            })
        except Exception as e:
            print(f"  ✗ {path.name}: {e}")
    
    if not results:
        print("  ⊘ No PE files found for testing")
        return
    
    print(f"\nTested {len(results)} PE files:")
    print("-" * 80)
    
    for r in results:
        whitelist_indicator = " [WHITELIST]" if r["whitelist_hit"] else ""
        print(f"\n  File: {r['filename']}{whitelist_indicator}")
        print(f"    Verdict: {r['verdict']}")
        print(f"    Status: {r['status']}")
        print(f"    Risk Score: {r['risk_score']}")
        print(f"    Confidence: {r['confidence']}%")
        if r["risk_flag"]:
            print(f"    Flag: {r['risk_flag']}")
        print(f"    Model: {r['model_version']}")
    
    # Verify all known clean files are marked BENIGN
    print("\n" + "-" * 80)
    all_benign = all(r["verdict"] == "BENIGN" for r in results)
    if all_benign:
        print("✓ All known clean files correctly marked as BENIGN")
    else:
        malicious = [r["filename"] for r in results if r["verdict"] != "BENIGN"]
        print(f"⚠ Warning: Files marked as malicious: {malicious}")


def test_threshold_behavior() -> None:
    """Test threshold classification at different risk scores."""
    from backend.config import get_threshold_config
    
    print("\n" + "=" * 80)
    print("THRESHOLD BEHAVIOR Analysis")
    print("=" * 80)
    
    detection_types = ["file", "email", "url"]
    
    for dtype in detection_types:
        config = get_threshold_config(dtype)
        
        print(f"\n  {dtype.upper()} Detection Thresholds:")
        print(f"    Threat threshold: {config.threat_threshold}")
        print(f"    Suspicious threshold: {config.suspicious_threshold}")
        
        # Test classification at various scores
        print(f"    Classification tests:")
        test_scores = [
            (0, "definitely safe"),
            (config.suspicious_threshold - 5, "just below suspicious"),
            (config.suspicious_threshold, "at suspicious"),
            ((config.threat_threshold + config.suspicious_threshold) / 2, "between suspicious and threat"),
            (config.threat_threshold - 5, "just below threat"),
            (config.threat_threshold, "at threat"),
            (100, "definitely threat"),
        ]
        
        for score, desc in test_scores:
            status = config.classify_status(score)
            print(f"      Score {score:5.1f}: {status:12s} ({desc})")


def test_model_versioning_consistency() -> None:
    """Test that model versions are consistent."""
    from backend.config import get_model_metadata
    
    print("\n" + "=" * 80)
    print("MODEL VERSIONING Consistency")
    print("=" * 80)
    
    detection_types = ["file", "email", "url"]
    
    for dtype in detection_types:
        metadata = get_model_metadata(dtype)
        
        print(f"\n  {dtype.upper()} Model Metadata:")
        print(f"    Model Version: {metadata.model_version}")
        print(f"    Threshold Version: {metadata.threshold_version}")
        print(f"    Trained At: {metadata.trained_at}")
        print(f"    Metrics Available: {bool(metadata.metrics)}")
        
        if metadata.metrics:
            print(f"    Key Metrics:")
            for key, value in sorted(metadata.metrics.items())[:3]:
                print(f"      - {key}: {value}")
    
    # Get metadata twice and verify consistency
    print(f"\n  Consistency Check:")
    m1 = get_model_metadata("file")
    m2 = get_model_metadata("file")
    if m1.model_version == m2.model_version:
        print(f"    ✓ Model version is consistent across calls: {m1.model_version}")
    else:
        print(f"    ✗ Model version inconsistent!")


def test_upload_validation_edge_cases() -> None:
    """Test edge cases in upload validation."""
    from backend.services.upload_validator import (
        validate_filename,
        validate_file_size,
        validate_file_extension,
        UploadValidationError,
        MAX_FILE_SIZE_BYTES,
        ALLOWED_EXTENSIONS,
    )
    
    print("\n" + "=" * 80)
    print("UPLOAD VALIDATION Edge Cases")
    print("=" * 80)
    
    # Edge case: Very long filename (but under limit)
    long_name = "a" * 250 + ".exe"
    try:
        validate_filename(long_name)
        print(f"  ✓ Accepted long filename: {len(long_name)} chars")
    except UploadValidationError as e:
        print(f"  ✗ Rejected long filename: {e}")
    
    # Edge case: Special characters in filename
    special_names = [
        "test-file.exe",
        "test_file.exe", 
        "test file.exe",
        "test.name.exe",
    ]
    
    print(f"\n  Testing special characters in filenames:")
    for name in special_names:
        try:
            validate_filename(name)
            print(f"    ✓ {name}")
        except UploadValidationError:
            print(f"    ✗ {name}")
    
    # Edge case: File size boundaries
    print(f"\n  Testing file size boundaries:")
    test_sizes = [
        (1, "1 byte"),
        (1024, "1 KB"),
        (1024 * 1024, "1 MB"),
        (10 * 1024 * 1024, "10 MB"),
        (99 * 1024 * 1024, "99 MB"),
        (100 * 1024 * 1024, "100 MB (limit)"),
    ]
    
    for size, desc in test_sizes:
        try:
            validate_file_size(b"x" * size)
            print(f"    ✓ Accepted: {desc}")
        except UploadValidationError as e:
            print(f"    ✗ Rejected: {desc}: {str(e)[:50]}")
    
    # Edge case: Extension boundaries
    print(f"\n  Testing extension validation:")
    for ext in ALLOWED_EXTENSIONS:
        name = f"test{ext}"
        try:
            validate_file_extension(name, ALLOWED_EXTENSIONS)
            print(f"    ✓ {name}")
        except UploadValidationError:
            print(f"    ✗ {name}")


def test_response_completeness() -> None:
    """Verify all required fields are in responses."""
    from backend.services.file_service import predict_file, THRESHOLD_CONFIG
    from pathlib import Path
    
    print("\n" + "=" * 80)
    print("RESPONSE COMPLETENESS Check")
    print("=" * 80)
    
    # Find a PE file
    pe_file = Path("C:\\Windows\\System32\\notepad.exe")
    if not pe_file.exists():
        print("  ⊘ No PE file found for testing")
        return
    
    with open(pe_file, "rb") as f:
        raw = f.read()
    
    result = predict_file("test.exe", raw)
    
    required_fields = {
        "detection_type": str,
        "filename": str,
        "status": str,  # "safe" | "suspicious" | "threat"
        "verdict": str,  # "BENIGN" | "SUSPICIOUS" | "MALICIOUS"
        "predicted_class": str,
        "decision_threshold": (int, float),
        "decision_threshold_suspicious": (int, float),
        "risk_score": int,
        "confidence": (int, float),
        "is_malicious": bool,
        "is_suspicious": bool,
        "key_features": dict,
        "model_info": dict,
        "file_hash": str,
    }
    
    print("\n  Required fields check:")
    all_present = True
    for field, expected_type in required_fields.items():
        if field in result:
            actual_val = result[field]
            if isinstance(expected_type, tuple):
                type_ok = isinstance(actual_val, expected_type)
            else:
                type_ok = isinstance(actual_val, expected_type)
            
            type_str = type(actual_val).__name__
            print(f"    ✓ {field}: {type_str}")
            
            if not type_ok:
                print(f"      ⚠ Wrong type, expected {expected_type}")
                all_present = False
        else:
            print(f"    ✗ {field}: MISSING")
            all_present = False
    
    # Check model_info sub-fields
    print(f"\n  model_info sub-fields:")
    model_info = result.get("model_info", {})
    for key in ["model_version", "threshold_version", "avg_prob"]:
        if key in model_info:
            print(f"    ✓ {key}")
        else:
            print(f"    ✗ {key}: MISSING")
            all_present = False
    
    if all_present:
        print(f"\n  ✓ All required fields present with correct types")
    else:
        print(f"\n  ⚠ Some required fields missing or wrong type")


def main() -> None:
    """Run advanced evaluation tests."""
    print("\n" + "█" * 80)
    print("ADVANCED FILE MODEL EVALUATION")
    print("█" * 80)
    
    try:
        test_real_pe_files()
        test_threshold_behavior()
        test_model_versioning_consistency()
        test_upload_validation_edge_cases()
        test_response_completeness()
        
        print("\n" + "█" * 80)
        print("✓ ADVANCED EVALUATION COMPLETED")
        print("█" * 80 + "\n")
        
    except Exception as e:
        print(f"\n✗ Error during advanced evaluation: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
