"""
Feature extraction pipeline v2 - combining baseline and enhanced features.

This module provides both v1 (baseline) and v2 (enhanced) feature sets for
training FILE malware detection models.

Version 1 (10 features): Baseline
  - Sections, AvgEntropy, MaxEntropy, SuspiciousSections, DLLs, Imports,
    HasSensitiveAPI, ImageBase, SizeOfImage, HasVersionInfo

Version 2 (16 features): Enhanced
  - All v1 features +
  - is_packed, import_category_score, has_tls, export_table_size, 
    resource_entropy, api_category_score
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import pefile

from FILE.training.feature_engineering_v2 import (
    detect_packing,
    categorize_imports,
    has_tls_section,
    get_api_categories,
    get_export_count,
    get_resource_entropy,
)

SENSITIVE_APIS = {
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"VirtualAllocEx",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"GetProcAddress",
    b"CreateProcessA",
    b"CreateProcessW",
    b"WinExec",
    b"ShellExecuteA",
    b"ShellExecuteW",
    b"InternetOpen",
    b"HttpSendRequest",
    b"URLDownloadToFileA",
    b"URLDownloadToFileW",
    b"WSAStartup",
    b"connect",
    b"send",
    b"recv",
    b"RegOpenKeyExA",
    b"RegSetValueExA",
    b"RegCreateKeyExA",
    b"SetWindowsHookEx",
    b"CreateToolhelp32Snapshot",
    b"Process32First",
    b"Process32Next",
    b"IsDebuggerPresent",
}

FEATURE_COLUMNS_V1 = [
    "Sections",
    "AvgEntropy",
    "MaxEntropy",
    "SuspiciousSections",
    "DLLs",
    "Imports",
    "HasSensitiveAPI",
    "ImageBase",
    "SizeOfImage",
    "HasVersionInfo",
]

FEATURE_COLUMNS_V2 = FEATURE_COLUMNS_V1 + [
    "IsPacked",
    "ImportCategoryScore",
    "HasTLS",
    "ExportTableSize",
    "ResourceEntropy",
    "APICategoryScore",
]


def extract_baseline_features(pe: pefile.PE) -> dict[str, Any]:
    """Extract v1 baseline features from PE file."""
    try:
        sections = len(pe.sections)
        entropies = [section.get_entropy() for section in pe.sections]
        avg_entropy = sum(entropies) / sections if sections else 0.0
        max_entropy = max(entropies) if entropies else 0.0

        suspicious_sections = 0
        for section in pe.sections:
            if (section.Characteristics & 0x80000000) and (section.Characteristics & 0x20000000):
                suspicious_sections += 1

        import_count = 0
        dll_count = 0
        has_sensitive_api = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if not entry.imports:
                    continue
                import_count += len(entry.imports)
                for imported in entry.imports:
                    if imported.name in SENSITIVE_APIS:
                        has_sensitive_api = 1

        has_version_info = 1 if hasattr(pe, "VS_FIXEDFILEINFO") else 0
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

        return {
            "Sections": sections,
            "AvgEntropy": round(avg_entropy, 4),
            "MaxEntropy": round(max_entropy, 4),
            "SuspiciousSections": suspicious_sections,
            "DLLs": dll_count,
            "Imports": import_count,
            "HasSensitiveAPI": has_sensitive_api,
            "ImageBase": image_base,
            "SizeOfImage": size_of_image,
            "HasVersionInfo": has_version_info,
        }
    except Exception:
        raise


def extract_enhanced_features_v2(pe: pefile.PE) -> dict[str, Any]:
    """Extract v2 enhanced features from PE file."""
    try:
        features = extract_baseline_features(pe)
        
        # Add v2 features
        features["IsPacked"] = detect_packing(pe)
        features["ImportCategoryScore"] = categorize_imports(pe)
        features["HasTLS"] = has_tls_section(pe)
        features["ExportTableSize"] = get_export_count(pe)
        features["ResourceEntropy"] = get_resource_entropy(pe)
        
        # API category score: max of all categories normalized
        api_cats = get_api_categories(pe)
        max_category_count = max(api_cats.values()) if api_cats else 0
        features["APICategoryScore"] = round(min(1.0, max_category_count / 20.0), 4)
        
        return features
    except Exception:
        raise


def extract_training_features_from_pe_v1(file_path: Path) -> dict[str, Any]:
    """Extract v1 features from PE file for training."""
    pe = pefile.PE(str(file_path))
    try:
        return extract_baseline_features(pe)
    finally:
        pe.close()


def extract_training_features_from_pe_v2(file_path: Path) -> dict[str, Any]:
    """Extract v2 features from PE file for training."""
    pe = pefile.PE(str(file_path))
    try:
        return extract_enhanced_features_v2(pe)
    finally:
        pe.close()


def extract_training_features_from_raw_v1(raw: bytes, filename: str = "") -> dict[str, Any]:
    """Extract v1 features from raw PE bytes."""
    pe = pefile.PE(data=raw)
    try:
        return extract_baseline_features(pe)
    except pefile.PEFormatError as e:
        raise ValueError(f"'{filename}' is not a valid PE executable") from e
    finally:
        pe.close()


def extract_training_features_from_raw_v2(raw: bytes, filename: str = "") -> dict[str, Any]:
    """Extract v2 features from raw PE bytes."""
    pe = pefile.PE(data=raw)
    try:
        return extract_enhanced_features_v2(pe)
    except pefile.PEFormatError as e:
        raise ValueError(f"'{filename}' is not a valid PE executable") from e
    finally:
        pe.close()


# Convenience function to get the appropriate extractor based on version
def get_extractor(version: int = 1):
    """Get feature extraction function for given version."""
    if version == 1:
        return extract_training_features_from_pe_v1
    elif version == 2:
        return extract_training_features_from_pe_v2
    else:
        raise ValueError(f"Unknown feature version: {version}")


def get_extractor_raw(version: int = 1):
    """Get raw byte feature extraction function for given version."""
    if version == 1:
        return extract_training_features_from_raw_v1
    elif version == 2:
        return extract_training_features_from_raw_v2
    else:
        raise ValueError(f"Unknown feature version: {version}")


def get_feature_columns(version: int = 1) -> list[str]:
    """Get feature column names for given version."""
    if version == 1:
        return FEATURE_COLUMNS_V1
    elif version == 2:
        return FEATURE_COLUMNS_V2
    else:
        raise ValueError(f"Unknown feature version: {version}")
