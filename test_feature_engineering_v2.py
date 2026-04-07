"""Test suite for enhanced PE feature extraction."""

from pathlib import Path
import sys

# Add Scamurai to path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from FILE.training.feature_engineering_v2 import (
    detect_packing,
    categorize_imports,
    has_tls_section,
    get_api_categories,
    get_export_count,
    get_resource_entropy,
    extract_enhanced_features,
)
import pefile

def test_system_files():
    """Test feature extraction on known system files."""
    test_files = [
        Path("C:\\Windows\\System32\\notepad.exe"),
        Path("C:\\Windows\\System32\\calc.exe"),
        Path("C:\\Windows\\System32\\cmd.exe"),
    ]
    
    print("\n" + "="*80)
    print("TEST 1: System Files Feature Extraction")
    print("="*80)
    
    for file_path in test_files:
        if not file_path.exists():
            print(f"⊘ Skipped: {file_path.name} (not found)")
            continue
        
        try:
            features = extract_enhanced_features(file_path)
            print(f"\n✓ {file_path.name}")
            print(f"  - is_packed: {features['is_packed']}")
            print(f"  - import_category_score: {features['import_category_score']}")
            print(f"  - has_tls: {features['has_tls']}")
            print(f"  - export_table_size: {features['export_table_size']}")
            print(f"  - resource_entropy: {features['resource_entropy']}")
            api_dist = features['api_category_dist']
            print(f"  - API categories: {api_dist}")
        except Exception as e:
            print(f"✗ Error processing {file_path.name}: {e}")


def test_raw_pe_bytes():
    """Test feature extraction on raw PE bytes."""
    print("\n" + "="*80)
    print("TEST 2: Raw PE Bytes Extraction")
    print("="*80)
    
    test_file = Path("C:\\Windows\\System32\\notepad.exe")
    if not test_file.exists():
        print("⊘ Skipped: notepad.exe not found")
        return
    
    try:
        with open(test_file, "rb") as f:
            raw_bytes = f.read()
        
        features = extract_enhanced_features(raw_bytes)
        print(f"\n✓ Extracted from raw bytes ({len(raw_bytes)} bytes)")
        print(f"  - is_packed: {features['is_packed']}")
        print(f"  - import_category_score: {features['import_category_score']}")
        print(f"  - export_table_size: {features['export_table_size']}")
    except Exception as e:
        print(f"✗ Error: {e}")


def test_feature_consistency():
    """Verify features are consistent across calls."""
    print("\n" + "="*80)
    print("TEST 3: Feature Consistency")
    print("="*80)
    
    test_file = Path("C:\\Windows\\System32\\notepad.exe")
    if not test_file.exists():
        print("⊘ Skipped: notepad.exe not found")
        return
    
    try:
        features1 = extract_enhanced_features(test_file)
        features2 = extract_enhanced_features(test_file)
        
        # Compare (api_category_dist is dict, so compare separately)
        api_dist_1 = features1.pop('api_category_dist')
        api_dist_2 = features2.pop('api_category_dist')
        
        if features1 == features2:
            print("✓ Features are consistent across multiple extractions")
        else:
            print("✗ Feature inconsistency detected!")
            print(f"  First:  {features1}")
            print(f"  Second: {features2}")
        
        if api_dist_1 == api_dist_2:
            print("✓ API categories are consistent")
        else:
            print("✗ API category inconsistency detected!")
    except Exception as e:
        print(f"✗ Error: {e}")


def test_packing_detection():
    """Test packing detection logic."""
    print("\n" + "="*80)
    print("TEST 4: Packing Detection Logic")
    print("="*80)
    
    test_file = Path("C:\\Windows\\System32\\notepad.exe")
    if not test_file.exists():
        print("⊘ Skipped: notepad.exe not found")
        return
    
    try:
        pe = pefile.PE(str(test_file))
        is_packed = detect_packing(pe)
        
        # System files should not be packed
        if is_packed == 0:
            print("✓ System file correctly identified as NOT packed")
        else:
            print("✗ System file incorrectly flagged as packed")
        
        # Show entropy breakdown
        print("\n  Section entropy breakdown:")
        for section in pe.sections:
            entropy = section.get_entropy()
            section_name = section.Name.rstrip(b'\x00').decode('latin-1')
            status = "HIGH" if entropy > 7.5 else "NORMAL"
            print(f"    {section_name}: {entropy:.4f} ({status})")
        
        pe.close()
    except Exception as e:
        print(f"✗ Error: {e}")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("ENHANCED PE FEATURE EXTRACTION TEST SUITE")
    print("="*80)
    
    test_system_files()
    test_raw_pe_bytes()
    test_feature_consistency()
    test_packing_detection()
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETE")
    print("="*80 + "\n")
