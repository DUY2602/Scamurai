"""
Enhanced feature extraction for PE file malware detection.

Adds new discriminative features beyond the baseline 10:
- is_packed: Entropy-based packing detection
- import_category_score: Suspicious vs benign API categorization
- has_tls: TLS/encryption section presence
- api_category_dist: Categorical API grouping
- export_table_size: Number of exports (0 for most files)
- resource_entropy: Entropy of resource section
"""

from pathlib import Path
from typing import Any

import pefile

# API categories
NETWORKING_APIS = {
    b"InternetOpen",
    b"InternetConnect",
    b"HttpOpenRequest",
    b"HttpSendRequest",
    b"HttpSendRequestEx",
    b"URLDownloadToFileA",
    b"URLDownloadToFileW",
    b"URLDownloadToFileEx",
    b"WSAStartup",
    b"socket",
    b"connect",
    b"send",
    b"recv",
    b"WSAConnect",
    b"bind",
    b"listen",
    b"accept",
}

PROCESS_APIS = {
    b"CreateProcessA",
    b"CreateProcessW",
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"ReadProcessMemory",
    b"VirtualAllocEx",
    b"GetProcessHandle",
    b"OpenProcess",
    b"TerminateProcess",
    b"CreateToolhelp32Snapshot",
    b"Process32First",
    b"Process32Next",
    b"Module32First",
    b"Module32Next",
    b"WinExec",
    b"ShellExecuteA",
    b"ShellExecuteW",
}

REGISTRY_APIS = {
    b"RegOpenKeyExA",
    b"RegOpenKeyExW",
    b"RegSetValueExA",
    b"RegSetValueExW",
    b"RegCreateKeyExA",
    b"RegCreateKeyExW",
    b"RegQueryValueExA",
    b"RegQueryValueExW",
    b"RegDeleteValueA",
    b"RegDeleteValueW",
    b"RegDeleteKeyA",
    b"RegDeleteKeyW",
}

FILEIO_APIS = {
    b"CreateFileA",
    b"CreateFileW",
    b"ReadFile",
    b"WriteFile",
    b"DeleteFileA",
    b"DeleteFileW",
    b"SetFileAttributes",
    b"CopyFileA",
    b"CopyFileW",
    b"MoveFileA",
    b"MoveFileW",
}

INJECTION_APIS = {
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"SetWindowsHookEx",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"GetProcAddress",
    b"GetModuleHandleA",
    b"GetModuleHandleW",
}

ANTIDEBUGGING_APIS = {
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"SetUnhandledExceptionFilter",
    b"AddVectoredExceptionHandler",
    b"GetTickCount",
    b"QueryPerformanceCounter",
}

CREDENTIAL_APIS = {
    b"GetKeyboardState",
    b"GetAsyncKeyState",
    b"SetWindowsHookEx",
    b"CallNextHookEx",
    b"CreateToolhelp32Snapshot",
}

# Map sections that indicate encryption or obfuscation
SUSPICIOUS_SECTIONS = {
    b".packed",
    b".encrypted",
    b".exe",
    b".bin",
    b".upx",
    b".aspack",
    b".kkrunchy",
}

# TLS-related sections
TLS_SECTIONS = {
    b".tls",
    b".reloc",
}


def detect_packing(pe: pefile.PE) -> int:
    """
    Detect if binary is likely packed/obfuscated.
    Returns 1 if packed, 0 otherwise.
    
    Indicators:
    - Section with very high entropy (>7.5)
    - Suspicious section names (.packed, .upx, etc.)
    - Very few or no imports
    - Low ratio of code sections to data sections
    """
    try:
        # Check for suspicious section names
        for section in pe.sections:
            section_name = section.Name.rstrip(b'\x00')
            if section_name in SUSPICIOUS_SECTIONS:
                return 1
            # Check for high entropy (compressed/encrypted)
            entropy = section.get_entropy()
            if entropy > 7.5:
                # Verify it's not a resource section
                if section_name != b".rsrc":
                    return 1
        
        # Code-to-data ratio: packed files have few imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            # If no DLLs imported but binary is large, likely packed
            if dll_count == 0 and pe.OPTIONAL_HEADER.SizeOfImage > 100000:
                return 1
        else:
            # No import table at all is suspicious
            if pe.OPTIONAL_HEADER.SizeOfImage > 100000:
                return 1
        
        return 0
    except Exception:
        return 0


def categorize_imports(pe: pefile.PE) -> float:
    """
    Return a score 0-1 indicating ratio of suspicious APIs imported.
    
    Score calculation:
    - Suspicious API category weight = 0.8 (networking, process injection, etc.)
    - Benign system API weight = 0.1 (display, messaging, etc.)
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return 0.0
    
    all_categories = (
        NETWORKING_APIS | PROCESS_APIS | REGISTRY_APIS | FILEIO_APIS | 
        INJECTION_APIS | ANTIDEBUGGING_APIS | CREDENTIAL_APIS
    )
    
    suspicious_apis = 0
    total_apis = 0
    
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imported in entry.imports:
                if imported.name is None:
                    continue
                total_apis += 1
                api_name = imported.name
                if api_name in all_categories:
                    # Weight by how suspicious each category is
                    if api_name in INJECTION_APIS or api_name in ANTIDEBUGGING_APIS:
                        suspicious_apis += 1.5  # Higher weight
                    elif api_name in NETWORKING_APIS or api_name in PROCESS_APIS:
                        suspicious_apis += 1.0
                    else:
                        suspicious_apis += 0.5
        
        if total_apis == 0:
            return 0.0
        
        # Normalize to 0-1 range
        score = min(1.0, suspicious_apis / (total_apis * 1.5))
        return round(score, 4)
    except Exception:
        return 0.0


def has_tls_section(pe: pefile.PE) -> int:
    """
    Check for TLS (Thread Local Storage) or encryption sections.
    Returns 1 if TLS-like sections present, 0 otherwise.
    """
    try:
        for section in pe.sections:
            section_name = section.Name.rstrip(b'\x00')
            if section_name in TLS_SECTIONS:
                return 1
            if b"tls" in section_name.lower():
                return 1
        return 0
    except Exception:
        return 0


def get_api_categories(pe: pefile.PE) -> dict[str, int]:
    """
    Count APIs in each category.
    Returns dict with counts for backward compatibility and analysis.
    """
    categories = {
        "networking": 0,
        "process": 0,
        "registry": 0,
        "fileio": 0,
        "injection": 0,
        "antidebug": 0,
        "credential": 0,
    }
    
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imported in entry.imports:
                    if imported.name is None:
                        continue
                    api_name = imported.name
                    if api_name in NETWORKING_APIS:
                        categories["networking"] += 1
                    if api_name in PROCESS_APIS:
                        categories["process"] += 1
                    if api_name in REGISTRY_APIS:
                        categories["registry"] += 1
                    if api_name in FILEIO_APIS:
                        categories["fileio"] += 1
                    if api_name in INJECTION_APIS:
                        categories["injection"] += 1
                    if api_name in ANTIDEBUGGING_APIS:
                        categories["antidebug"] += 1
                    if api_name in CREDENTIAL_APIS:
                        categories["credential"] += 1
    except Exception:
        pass
    
    return categories


def get_export_count(pe: pefile.PE) -> int:
    """
    Count number of exported functions.
    Most benign files export 0, many malware export functions for DLL injection.
    """
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        return 0
    except Exception:
        return 0


def get_resource_entropy(pe: pefile.PE) -> float:
    """
    Calculate entropy of .rsrc (resource) section.
    High entropy suggests compressed/encrypted resources (suspicious).
    """
    try:
        for section in pe.sections:
            if section.Name.rstrip(b'\x00') == b".rsrc":
                return round(section.get_entropy(), 4)
        return 0.0
    except Exception:
        return 0.0


def extract_enhanced_features(pe_path_or_bytes) -> dict[str, Any]:
    """
    Extract all enhanced features from a PE file.
    
    Args:
        pe_path_or_bytes: Either a file path (str/Path) or raw PE bytes
        
    Returns:
        dict with all v2 features
    """
    if isinstance(pe_path_or_bytes, (str, Path)):
        pe = pefile.PE(str(pe_path_or_bytes))
    else:
        pe = pefile.PE(data=pe_path_or_bytes)
    
    try:
        features = {
            "is_packed": detect_packing(pe),
            "import_category_score": categorize_imports(pe),
            "has_tls": has_tls_section(pe),
            "api_category_dist": get_api_categories(pe),
            "export_table_size": get_export_count(pe),
            "resource_entropy": get_resource_entropy(pe),
        }
        return features
    finally:
        pe.close()
