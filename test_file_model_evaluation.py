"""
Evaluation script för FILE model testing
Tests: ThresholdRegistry, ModelMetadataRegistry, UploadValidator, predict_file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Add Scamurai module to path
SCAMURAI_ROOT = Path(__file__).resolve().parent / "Scamurai"
if str(SCAMURAI_ROOT) not in sys.path:
    sys.path.insert(0, str(SCAMURAI_ROOT))


def test_threshold_registry() -> None:
    """Test ThresholdRegistry loading and status classification."""
    print("\n" + "=" * 70)
    print("TEST 1: ThresholdRegistry")
    print("=" * 70)
    
    try:
        from backend.config import get_threshold_config
        
        config = get_threshold_config("file")
        print(f"✓ Loaded threshold config for FILE")
        print(f"  - Type: {config.detection_type}")
        print(f"  - Threat threshold: {config.threat_threshold}")
        print(f"  - Suspicious threshold: {config.suspicious_threshold}")
        print(f"  - Selected threshold: {config.selected_threshold}")
        
        # Test classification
        test_scores = [30, 50, 70, 85]
        print(f"\n  Status classification tests:")
        for score in test_scores:
            status = config.classify_status(score)
            print(f"    Risk {score:2d} → {status:12s}")
        
        print("\n✓ ThresholdRegistry test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ ThresholdRegistry test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_model_metadata_registry() -> None:
    """Test ModelMetadataRegistry loading."""
    print("\n" + "=" * 70)
    print("TEST 2: ModelMetadataRegistry")
    print("=" * 70)
    
    try:
        from backend.config import get_model_metadata
        
        metadata = get_model_metadata("file")
        print(f"✓ Loaded model metadata for FILE")
        print(f"  - Model version: {metadata.model_version}")
        print(f"  - Threshold version: {metadata.threshold_version}")
        print(f"  - Trained at: {metadata.trained_at}")
        print(f"  - Metrics available: {bool(metadata.metrics)}")
        
        if metadata.metrics:
            print(f"\n  Metrics:")
            for key, value in sorted(metadata.metrics.items()):
                print(f"    - {key}: {value}")
        
        print(f"\n✓ ModelMetadataRegistry test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ ModelMetadataRegistry test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_upload_validator() -> None:
    """Test UploadValidator rules."""
    print("\n" + "=" * 70)
    print("TEST 3: UploadValidator")
    print("=" * 70)
    
    try:
        from backend.services.upload_validator import (
            validate_filename,
            validate_file_size,
            validate_file_extension,
            ALLOWED_EXTENSIONS,
            MAX_FILE_SIZE_BYTES,
            UploadValidationError,
        )
        
        print(f"✓ Loaded UploadValidator")
        print(f"  - Max file size: {MAX_FILE_SIZE_BYTES / (1024*1024):.0f} MB")
        print(f"  - Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
        
        # Test valid filename
        try:
            validate_filename("test.exe")
            print(f"\n  ✓ Valid filename: test.exe")
        except UploadValidationError as e:
            print(f"  ✗ Valid filename failed: {e}")
            return False
        
        # Test invalid filenames
        invalid_names = [
            ("", "empty"),
            ("../../../etc/passwd", "path traversal"),
            ("a" * 300, "too long"),
            ("test\x00.exe", "null byte"),
        ]
        
        print(f"\n  Testing invalid filenames:")
        for name, desc in invalid_names:
            try:
                validate_filename(name)
                print(f"    ✗ Should reject: {desc}")
                return False
            except UploadValidationError:
                print(f"    ✓ Rejected: {desc}")
        
        # Test file size validation
        print(f"\n  Testing file sizes:")
        try:
            validate_file_size(b"")
            print(f"    ✗ Should reject: empty")
            return False
        except UploadValidationError:
            print(f"    ✓ Rejected: empty file")
        
        try:
            validate_file_size(b"x" * (100 * 1024 * 1024 + 1))
            print(f"    ✗ Should reject: too large")
            return False
        except UploadValidationError:
            print(f"    ✓ Rejected: > 100 MB")
        
        try:
            validate_file_size(b"test")
            print(f"    ✓ Accepted: valid size")
        except UploadValidationError as e:
            print(f"    ✗ Valid size rejected: {e}")
            return False
        
        # Test extension validation
        print(f"\n  Testing extensions:")
        try:
            validate_file_extension("test.exe", ALLOWED_EXTENSIONS)
            print(f"    ✓ Allowed: .exe")
        except UploadValidationError as e:
            print(f"    ✗ .exe rejected: {e}")
            return False
        
        try:
            validate_file_extension("test.txt", ALLOWED_EXTENSIONS)
            print(f"    ✗ Should reject: .txt")
            return False
        except UploadValidationError:
            print(f"    ✓ Rejected: .txt")
        
        print(f"\n✓ UploadValidator test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ UploadValidator test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_service_basic() -> None:
    """Test file_service basic functionality."""
    print("\n" + "=" * 70)
    print("TEST 4: File Service Imports & Constants")
    print("=" * 70)
    
    try:
        from backend.services.file_service import (
            THRESHOLD_CONFIG,
            MODEL_METADATA,
            FEATURES,
            SENSITIVE_APIS,
            predict_file,
        )
        
        print(f"✓ File service imports successful")
        print(f"  - THRESHOLD_CONFIG loaded: {bool(THRESHOLD_CONFIG)}")
        print(f"  - MODEL_METADATA loaded: {bool(MODEL_METADATA)}")
        print(f"  - Features count: {len(FEATURES)}")
        print(f"  - Sensitive APIs count: {len(SENSITIVE_APIS)}")
        print(f"  - predict_file function available: {callable(predict_file)}")
        
        print(f"\n  Features list:")
        for feat in FEATURES:
            print(f"    - {feat}")
        
        print(f"\n✓ File Service basic test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ File Service basic test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_service_prediction_with_real_pe() -> None:
    """Test file_service prediction with real PE file if available."""
    print("\n" + "=" * 70)
    print("TEST 5: File Service Prediction (Real PE File)")
    print("=" * 70)
    
    try:
        from backend.services.file_service import predict_file
        from backend.services.file_service import FileScanError
        
        # Try to find a PE file to test
        pe_candidates = [
            Path("C:/Windows/System32/notepad.exe"),
            Path("C:/Windows/System32/calc.exe"),
            Path("C:/Windows/System32/cmd.exe"),
        ]
        
        test_file = None
        for candidate in pe_candidates:
            if candidate.exists():
                test_file = candidate
                break
        
        if test_file is None:
            print(f"  ⊘ No PE file found to test (skipping)")
            print(f"  ✓ File Service Prediction test SKIPPED (not a blocker)")
            return True
        
        print(f"  Testing with: {test_file}")
        
        with open(test_file, "rb") as f:
            raw = f.read()
        
        result = predict_file(str(test_file.name), raw)
        
        print(f"✓ Prediction successful")
        print(f"\n  Response fields:")
        for key in sorted(result.keys()):
            value = result[key]
            if isinstance(value, dict):
                print(f"    - {key}:")
                for sub_key, sub_val in value.items():
                    print(f"        {sub_key}: {sub_val}")
            elif isinstance(value, (int, float)):
                print(f"    - {key}: {value}")
            elif isinstance(value, str) and len(str(value)) < 80:
                print(f"    - {key}: {value}")
            elif isinstance(value, bool):
                print(f"    - {key}: {value}")
            else:
                print(f"    - {key}: <{type(value).__name__}>")
        
        # Validate response structure
        required_fields = [
            "detection_type",
            "status",
            "verdict",
            "risk_score",
            "confidence",
            "model_info",
            "file_hash",
        ]
        
        missing = [f for f in required_fields if f not in result]
        if missing:
            print(f"\n  ✗ Missing fields: {missing}")
            return False
        
        # Validate model_info
        model_info = result.get("model_info", {})
        model_fields = ["model_version", "threshold_version", "avg_prob"]
        missing_model = [f for f in model_fields if f not in model_info]
        if missing_model:
            print(f"\n  ✗ Missing model_info fields: {missing_model}")
            return False
        
        print(f"\n✓ File Service Prediction test PASSED")
        return True
        
    except FileScanError as e:
        print(f"  ✗ PE parsing error: {e}")
        return False
    except Exception as e:
        print(f"\n✗ File Service Prediction test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_email_service() -> None:
    """Test email_service basic functionality."""
    print("\n" + "=" * 70)
    print("TEST 6: Email Service with Registry")
    print("=" * 70)
    
    try:
        from backend.services.email_service import (
            THRESHOLD_CONFIG,
            MODEL_METADATA,
            predict_from_text,
        )
        
        print(f"✓ Email service imports successful")
        print(f"  - THRESHOLD_CONFIG loaded: {bool(THRESHOLD_CONFIG)}")
        print(f"  - Detection type: {THRESHOLD_CONFIG.detection_type}")
        print(f"  - Threat threshold: {THRESHOLD_CONFIG.threat_threshold}")
        print(f"  - MODEL_METADATA loaded: {bool(MODEL_METADATA)}")
        print(f"  - Model version: {MODEL_METADATA.model_version}")
        
        print(f"\n✓ Email Service test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ Email Service test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_url_service() -> None:
    """Test url_service basic functionality."""
    print("\n" + "=" * 70)
    print("TEST 7: URL Service with Registry")
    print("=" * 70)
    
    try:
        from backend.services.url_service import (
            THRESHOLD_CONFIG,
            MODEL_METADATA,
            predict_url,
        )
        
        print(f"✓ URL service imports successful")
        print(f"  - THRESHOLD_CONFIG loaded: {bool(THRESHOLD_CONFIG)}")
        print(f"  - Detection type: {THRESHOLD_CONFIG.detection_type}")
        print(f"  - Threat threshold: {THRESHOLD_CONFIG.threat_threshold}")
        print(f"  - MODEL_METADATA loaded: {bool(MODEL_METADATA)}")
        print(f"  - Model version: {MODEL_METADATA.model_version}")
        
        # Test with simple URL
        print(f"\n  Testing predict_url()...")
        result = predict_url("https://www.google.com")
        
        required = ["detection_type", "status", "verdict", "model_info"]
        missing = [f for f in required if f not in result]
        if missing:
            print(f"    ✗ Missing fields: {missing}")
            return False
        
        print(f"    ✓ Prediction returned: status={result['status']}, verdict={result['verdict']}")
        
        print(f"\n✓ URL Service test PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ URL Service test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main() -> int:
    """Run all evaluation tests."""
    print("\n" + "█" * 70)
    print("FILE MODEL EVALUATION - Scamurai Refactoring")
    print("█" * 70)
    print(f"Date: 2026-04-07")
    print(f"Python: {sys.version.split()[0]}")
    
    results = []
    
    # Run tests
    tests = [
        ("ThresholdRegistry", test_threshold_registry),
        ("ModelMetadataRegistry", test_model_metadata_registry),
        ("UploadValidator", test_upload_validator),
        ("File Service Basics", test_file_service_basic),
        ("File Service Prediction", test_file_service_prediction_with_real_pe),
        ("Email Service", test_email_service),
        ("URL Service", test_url_service),
    ]
    
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\n✗ {name} crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:7s} | {name}")
    
    print("=" * 70)
    print(f"Result: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        return 0
    else:
        print(f"\n⚠️  {total_count - passed_count} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
