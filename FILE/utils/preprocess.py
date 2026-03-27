import pefile
import os
import csv
import hashlib

# List of senesitive APIs to detect
# b: byte string
SENSITIVE_APIS = [
    b"CreateRemoteThread", b"WriteProcessMemory", b"VirtualAllocEx", 
    b"InternetOpen", b"HttpSendRequest", b"GetKeyboardState", 
    b"SetWindowsHookEx", b"ShellExecuteA", b"IsDebuggerPresent"
]

# Hashing files with MD5 to create Static Signature for identification 
# Allowing immediate known malware detection without deep analysis
def get_md5(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

# Extracting file features and return them as a list
def extract_features(file_path, label):
    try:
        # Use pefile to read file attributes (without having to execute them)
        pe = pefile.PE(file_path)
        
        # Sections & Entropy: 2 most important features to distinct Malware from Benign
        n_sections = len(pe.sections)
        entropies = [s.get_entropy() for s in pe.sections]
        avg_entropy = sum(entropies) / n_sections if n_sections > 0 else 0
        max_entropy = max(entropies) if entropies else 0
        
        # Check for W+X (Write + Execute) permissions in sections.
        # A classic indicator of self-modifying code or unpacked malware 
        # being injected into memory at runtime.        
        suspicious_sections = 0
        for section in pe.sections:
            # Characteristics: 0x80000000 (Write) | 0x20000000 (Execute)
            if (section.Characteristics & 0x80000000) and (section.Characteristics & 0x20000000):
                suspicious_sections += 1
        
        # Analyze Imports (DLLs & API)
        n_imports = 0
        n_dlls = 0
        has_sensitive_api = 0
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            n_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.imports:
                    n_imports += len(entry.imports)
                    for imp in entry.imports:
                        if imp.name in SENSITIVE_APIS:
                            has_sensitive_api = 1
        
        # Header Features
        image_base = pe.OPTIONAL_HEADER.ImageBase
        size_image = pe.OPTIONAL_HEADER.SizeOfImage
        
        # Version Info (Malware usually miss this info)
        has_version = 1 if hasattr(pe, 'VS_FIXEDFILEINFO') else 0
        
        # Reset after each file
        pe.close()

        return [
            get_md5(file_path),   # MD5 hash of the file path
            n_sections,           # Number of sections in the file
            round(avg_entropy, 4),# Average entropy of the file
            round(max_entropy, 4),# Maximum entropy of the file (check packing)
            suspicious_sections,  # Number of sections that are both written and run (risky)
            n_dlls,               # Number of linked libraries
            n_imports,            # Total number of function calls
            has_sensitive_api,    # Whether the file uses a "sensitive" function (0/1)
            image_base,           # Image base loaded into RAM
            size_image,           # Size when running in RAM
            has_version,          # Any information on version (0/1)
            label                 # 1 (Malware) | 0 (Benign)
        ]
    except Exception:
        return None

def build_dataset(malware_folder, benign_folder, output_csv):
    header = [
        'MD5', 'Sections', 'AvgEntropy', 'MaxEntropy', 'SuspiciousSections',
        'DLLs', 'Imports', 'HasSensitiveAPI', 'ImageBase', 'SizeOfImage', 
        'HasVersionInfo', 'Label'
    ]
    
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        
        # Extract Malware
        print(">>> Extracting features from Malware...")
        count_mal = 0
        for filename in os.listdir(malware_folder):
            res = extract_features(os.path.join(malware_folder, filename), 1)
            if res:
                writer.writerow(res)
                count_mal += 1
            
        # Extract Benign
        print(">>> Extracting features from Benign...")
        count_ben = 0
        for filename in os.listdir(benign_folder):
            res = extract_features(os.path.join(benign_folder, filename), 0)
            if res:
                writer.writerow(res)
                count_ben += 1
                
    print(f"\n--- Complete ---")
    print(f"Data saved to: {output_csv}")

# Data Path Configuration
MAL_DIR = "data/MALWARE_DATASET"
BEN_DIR = "data/BENIGN_DATASET"
OUTPUT_FILE = "malware_data_final.csv"

if __name__ == "__main__":
    if os.path.exists(MAL_DIR) and os.path.exists(BEN_DIR):
        build_dataset(MAL_DIR, BEN_DIR, OUTPUT_FILE)
    else:
        print("Error: Directory not found!")