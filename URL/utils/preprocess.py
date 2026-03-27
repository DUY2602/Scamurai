import re
import math
import pandas as pd
from tqdm import tqdm
from urllib.parse import urlparse

# 1. Calculate Entropy
def get_entropy(text):
    if not text: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

# 2. Extract Features for "86% ACCURACY" (14 features)
def extract_features(url):
    # Clean URL
    u = str(url).strip().lower().replace('[', '').replace(']', '')
    address = u if '://' in u else 'http://' + u
    try:
        p = urlparse(address)
    except:
        p = urlparse('http://error-url.com')
        
    hostname = p.netloc.replace('www.', '')
    path = p.path + p.query
    full_url = hostname + path
    
    # List of signals (Optimized)
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin', 'confirm', 'bank']
    trash_tld = ('.tk', '.xyz', '.cc', '.top', '.pw', '.online', '.site', '.biz')
    popular_tld = ('.com', '.net', '.org', '.co', '.edu', '.gov', '.info', '.edu.vn')

    # Extract the exact 14 columns to help the Model achieve 86.48%
    return {
        'url_len': len(full_url),
        'hostname_len': len(hostname),
        'dot_count': full_url.count('.'),
        'dash_count': hostname.count('-'),
        'digit_ratio': len(re.findall(r'\d', full_url)) / (len(full_url) + 1),
        'entropy': get_entropy(full_url),
        'is_trash_tld': int(hostname.endswith(trash_tld)),
        'is_popular_tld': int(any(hostname.endswith(t) for t in popular_tld)),
        'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname))),
        'is_exec': int(bool(re.search(r'\.(exe|apk|msi|bin|js|vbs|scr|zip)$', path))),
        'keyword_count': sum(1 for k in keywords if k in full_url),
        'subdomain_count': len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0,
        'special_ratio': sum(full_url.count(c) for c in ['-', '.', '_', '@', '?', '&', '=']) / (len(full_url) + 1),
        'has_number_in_host': int(any(char.isdigit() for char in hostname))
    }

# 3. Process CSV to Prepare Training/Prediction Data
def process_and_save_csv(input_path, output_path):
    print(f"📂 Loading data from: {input_path}")
    try:
        df = pd.read_csv(input_path)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return

    # Automatically find the label column
    label_col = next((c for c in df.columns if c.lower() in ['type', 'label', 'target']), None)
    
    if 'url' not in df.columns or not label_col:
        print("❌ Error: Need 'url' and label column!")
        return

    print(f"🧬 Extracting 14 features for {len(df)} rows...")
    
    all_features = []
    # Use tqdm to show the progress bar for professional
    for _, row in tqdm(df.iterrows(), total=len(df)):
        # 1. Extract the 14 technical features
        feat = extract_features(row['url'])
        
        # 2. Map original type to Binary Label: Benign vs Harm
        # This groups phishing, malware, defacement into 'harm'
        original_label = str(row[label_col]).lower()
        feat['target'] = 'benign' if original_label == 'benign' else 'harm'
        
        feat['url'] = row['url']
        all_features.append(feat)

    new_df = pd.DataFrame(all_features)
    # Move url and target to the beginning
    cols = ['url', 'target'] + [c for c in new_df.columns if c not in ['url', 'target']]
    new_df = new_df[cols]
    
    new_df.to_csv(output_path, index=False, encoding='utf-8')
    print(f"✅ Saved processed file at: {output_path}")

if __name__ == "__main__":
    # Run a trial if you want to preprocess the CSV file
    process_and_save_csv('URL/data/malicious_url.csv', 'URL/data/processed_malicious_url.csv')
