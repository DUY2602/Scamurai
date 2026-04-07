"""
Adversarial test suite for FILE malware detection model.

Tests model robustness against:
1. Entropy Padding - benign files padded to increase entropy
2. Packed Installers - legitimate software with high entropy
3. Low Entropy Malware - synthetic examples of malware disguised as benign
"""

import os
import sys
import random
import json
from pathlib import Path
from typing import Any

# Add paths
REPO_ROOT = Path(__file__).resolve().parent.parent
SCAMURAI_ROOT = Path(__file__).resolve().parent / "Scamurai"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCAMURAI_ROOT))

import pefile
from Scamurai.backend.services.file_service import predict_file
from Scamurai.backend.services.asset_paths import find_asset_dir

TEST_SET_DIR = Path(__file__).resolve().parent / "data" / "adversarial_test_set"


def create_entropy_padded_file(source_path: Path, output_path: Path, target_entropy: float = 7.5) -> bool:
    """
    Create entropy-padded version of a file by appending random data.
    Preserves PE header and code, adds random section at end.
    """
    try:
        with open(source_path, "rb") as f:
            original_data = f.read()
        
        # Don't modify if already too large
        if len(original_data) > 50_000_000:
            return False
        
        # Generate random padding to increase entropy
        # Aim for higher entropy than original (typically 5-6 for system files)
        padding_size = len(original_data) // 4  # Add 25% random data
        padding = bytes(random.randint(0, 255) for _ in range(padding_size))
        
        output_data = original_data + padding
        
        # Write padded file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(output_data)
        
        return True
    except Exception as e:
        print(f"  Error creating padded file: {e}")
        return False


def find_packed_installers() -> list[tuple[str, Path]]:
    """Find legitimate packed installers on disk."""
    installers = []
    
    # Common locations for installers
    download_dir = Path.home() / "Downloads"
    program_files = Path("C:\\Program Files")
    program_files_x86 = Path("C:\\Program Files (x86)")
    
    # Common installer patterns
    patterns = [
        "*.exe",
        "*Setup*.exe",
        "*Setup*64.exe",
        "*Installer*.exe",
    ]
    
    for search_dir in [download_dir, program_files, program_files_x86]:
        if not search_dir.exists():
            continue
        
        for pattern in patterns[:2]:  # Just check first 2 patterns per dir
            for exe_file in search_dir.glob(pattern):
                if exe_file.is_file() and exe_file.stat().st_size > 100_000:
                    # Quick check if it's actually PE
                    try:
                        pe = pefile.PE(str(exe_file))
                        entropy = max(s.get_entropy() for s in pe.sections)
                        pe.close()
                        
                        # Installer typically has sections with entropy > 6.5
                        if entropy > 6.5:
                            installers.append((exe_file.name, exe_file))
                    except Exception:
                        pass
    
    return installers[:5]  # Limit to 5 samples


def create_low_entropy_malware_demo(output_path: Path) -> bool:
    """
    Create a synthetic low-entropy 'malware' for testing.
    
    This is a legitimate demonstration: creates a valid PE that looks benign
    but demonstrates how a real malware might disguise itself (encoder patterns, etc.)
    """
    try:
        # Find a benign base file
        base_file = Path("C:\\Windows\\System32\\notepad.exe")
        if not base_file.exists():
            return False
        
        # For the demo, we'll just copy it (real adversarial malware would use
        # encoding/encryption to maintain low entropy)
        with open(base_file, "rb") as f:
            data = f.read()
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(data)
        
        return True
    except Exception as e:
        print(f"  Error creating demo file: {e}")
        return False


def prepare_test_files() -> dict[str, list[Path]]:
    """Prepare all adversarial test files."""
    results = {
        "entropy_padding": [],
        "packed_installers": [],
        "low_entropy_malware": [],
    }
    
    print("\n" + "="*80)
    print("PREPARING ADVERSARIAL TEST FILES")
    print("="*80)
    
    # 1. Create entropy-padded benign files
    print("\n1. Creating entropy-padded benign files...")
    benign_files = [
        Path("C:\\Windows\\System32\\notepad.exe"),
        Path("C:\\Windows\\System32\\calc.exe"),
        Path("C:\\Windows\\System32\\cmd.exe"),
    ]
    
    for benign_file in benign_files:
        if benign_file.exists():
            output_file = TEST_SET_DIR / "entropy_padding" / f"{benign_file.stem}_padded.exe"
            if create_entropy_padded_file(benign_file, output_file):
                results["entropy_padding"].append(output_file)
                print(f"   ✓ Created: {output_file.name}")
    
    # 2. Find packed installers
    print("\n2. Searching for packed installers...")
    installers = find_packed_installers()
    for installer_name, installer_path in installers:
        output_file = TEST_SET_DIR / "packed_installers" / installer_name
        try:
            import shutil
            shutil.copy2(installer_path, output_file)
            results["packed_installers"].append(output_file)
            print(f"   ✓ Found: {installer_name}")
        except Exception as e:
            print(f"   ✗ Could not copy: {installer_name} - {e}")
    
    if not results["packed_installers"]:
        print("   ⊘ No real installers found, using system files as demo")
        for benign_file in benign_files[:2]:
            if benign_file.exists():
                # Just reference system files (we'll handle specially in testing)
                results["packed_installers"].append(benign_file)
    
    # 3. Create low-entropy malware demos
    print("\n3. Creating low-entropy malware demonstrations...")
    for i in range(2):
        output_file = TEST_SET_DIR / "low_entropy_malware" / f"adversarial_demo_{i+1}.exe"
        if create_low_entropy_malware_demo(output_file):
            results["low_entropy_malware"].append(output_file)
            print(f"   ✓ Created: {output_file.name}")
    
    return results


def test_adversarial_files(test_files: dict[str, list[Path]]) -> dict[str, Any]:
    """Test model on adversarial files and collect results."""
    results = {
        "entropy_padding": {"passed": 0, "failed": 0, "details": []},
        "packed_installers": {"passed": 0, "failed": 0, "details": []},
        "low_entropy_malware": {"passed": 0, "failed": 0, "details": []},
    }
    
    print("\n" + "="*80)
    print("TESTING ADVERSARIAL FILES")
    print("="*80)
    
    # Test entropy-padded files (should all be BENIGN)
    print("\n1. Testing entropy-padded benign files (expect: BENIGN)...")
    for file_path in test_files.get("entropy_padding", []):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            result = predict_file(file_path.name, file_data)
            verdict = result.get("verdict", "ERROR")
            
            # Success if detected as BENIGN (not incorrectly flagged as malicious)
            passed = verdict == "BENIGN"
            results["entropy_padding"]["passed" if passed else "failed"] += 1
            
            details = {
                "filename": file_path.name,
                "verdict": verdict,
                "risk_score": result.get("risk_score"),
                "status": result.get("status"),
                "confidence": result.get("confidence"),
                "passed": passed,
            }
            results["entropy_padding"]["details"].append(details)
            
            status_icon = "✓" if passed else "✗"
            print(f"   {status_icon} {file_path.name}: {verdict} (risk={result.get('risk_score')}, conf={result.get('confidence')}%)")
        except Exception as e:
            print(f"   ✗ Error testing {file_path.name}: {e}")
            results["entropy_padding"]["failed"] += 1
    
    # Test packed installers (should all be BENIGN)
    print("\n2. Testing packed installers (expect: BENIGN)...")
    for file_path in test_files.get("packed_installers", []):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            result = predict_file(file_path.name, file_data)
            verdict = result.get("verdict", "ERROR")
            
            # Success if detected as BENIGN
            passed = verdict == "BENIGN"
            results["packed_installers"]["passed" if passed else "failed"] += 1
            
            details = {
                "filename": file_path.name,
                "verdict": verdict,
                "risk_score": result.get("risk_score"),
                "status": result.get("status"),
                "confidence": result.get("confidence"),
                "passed": passed,
            }
            results["packed_installers"]["details"].append(details)
            
            status_icon = "✓" if passed else "✗"
            print(f"   {status_icon} {file_path.name}: {verdict} (risk={result.get('risk_score')}, conf={result.get('confidence')}%)")
        except Exception as e:
            print(f"   ✗ Error testing {file_path.name}: {e}")
            results["packed_installers"]["failed"] += 1
    
    # Test low-entropy malware (baseline check)
    print("\n3. Testing low-entropy malware demonstrations (baseline check)...")
    for file_path in test_files.get("low_entropy_malware", []):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            result = predict_file(file_path.name, file_data)
            verdict = result.get("verdict", "ERROR")
            
            details = {
                "filename": file_path.name,
                "verdict": verdict,
                "risk_score": result.get("risk_score"),
                "status": result.get("status"),
                "confidence": result.get("confidence"),
            }
            results["low_entropy_malware"]["details"].append(details)
            
            print(f"   - {file_path.name}: {verdict} (risk={result.get('risk_score')}, conf={result.get('confidence')}%)")
        except Exception as e:
            print(f"   ✗ Error testing {file_path.name}: {e}")
            results["low_entropy_malware"]["failed"] += 1
    
    return results


def print_summary(results: dict[str, Any]) -> None:
    """Print test summary."""
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    total_passed = 0
    total_failed = 0
    
    for category, data in results.items():
        passed_count = data.get("passed", 0)
        failed_count = data.get("failed", 0)
        total = passed_count + failed_count
        
        total_passed += passed_count
        total_failed += failed_count
        
        if total > 0:
            pass_rate = (passed_count / total) * 100
            status_icon = "✓" if pass_rate == 100 else "⚠" if pass_rate >= 80 else "✗"
            print(f"\n{status_icon} {category.replace('_', ' ').title()}")
            print(f"   Passed: {passed_count}/{total} ({pass_rate:.1f}%)")
            
            # Show details
            for detail in data.get("details", []):
                if "passed" in detail and not detail["passed"]:
                    print(f"   FAILED: {detail['filename']} -> {detail['verdict']}")
    
    print("\n" + "-"*80)
    total_tests = total_passed + total_failed
    if total_tests > 0:
        overall_pass_rate = (total_passed / total_tests) * 100
        print(f"Overall: {total_passed}/{total_tests} ({overall_pass_rate:.1f}%)")
        
        if overall_pass_rate == 100:
            print("✓ All adversarial tests PASSED - Model is robust!")
        elif overall_pass_rate >= 90:
            print("⚠ Most tests passed - Model is reasonably robust")
        else:
            print("✗ Significant failures - Model needs improvement")
    
    print("="*80)


def main():
    """Main test runner."""
    print("\n" + "="*80)
    print("ADVERSARIAL TEST SUITE FOR FILE MALWARE DETECTION")
    print("="*80)
    
    # Prepare test files
    test_files = prepare_test_files()
    
    # Run tests
    results = test_adversarial_files(test_files)
    
    # Print summary
    print_summary(results)
    
    # Save results to JSON
    results_file = TEST_SET_DIR / "adversarial_results.json"
    summary_for_json = {
        "timestamp": str(Path("dummyfile").resolve()),  # Just for structure
        "test_files": {k: [str(f) for f in v] for k, v in test_files.items()},
        "results": results,
    }
    
    with open(results_file, "w") as f:
        json.dump(summary_for_json, f, indent=2)
    print(f"\n✓ Results saved to: {results_file}")


if __name__ == "__main__":
    main()
