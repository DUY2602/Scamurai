import os
import sys
import joblib
import warnings
import pandas as pd
warnings.filterwarnings('ignore')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.preprocess import extract_features

def main():
    print("="*60)
    print("URL MALWARE DETECTION - TEST ALL MODELS")
    print("="*60)
    
    # Input URL to test
    url = input("\nInput URL to test: ").strip()
    
    if not url:
        print("Error occurred: URL is empty")
        return
    
    # Find all model in the folder
    models_folder = "URL/models"
    if not os.path.exists(models_folder):
        print("Folder 'URL/models' not found")
        return
    
    model_files = [f for f in os.listdir(models_folder) if f.endswith('_model.pkl')]
    
    if not model_files:
        print("Cannot find any model files in 'URL/models' folder")
        return
    
    print(f"\nFound {len(model_files)} models:")
    for m in model_files:
        print(f"  - {m}")
    
    try:
        # Extract features from URL
        print("\nExtracting features...")
        features_dict = extract_features(url)
        
        # Load feature names
        feature_names_path = os.path.join(models_folder, 'feature_names.pkl')
        if os.path.exists(feature_names_path):
            with open(feature_names_path, 'rb') as f:
                feature_names = joblib.load(f)
        else:
            # Nếu không có file feature_names, dùng tất cả keys
            feature_names = list(features_dict.keys())
        
        # Create DataFrame with extracted features
        X = pd.DataFrame([features_dict])[feature_names]
        
        # Load scaler
        scaler_path = os.path.join(models_folder, 'scaler.pkl')
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)  # Sửa thành joblib.load
            X_scaled = scaler.transform(X)
        else:
            X_scaled = X
        
        # Load label encoder
        encoder_path = os.path.join(models_folder, 'label_encoder.pkl')
        label_encoder = None
        if os.path.exists(encoder_path):
            label_encoder = joblib.load(encoder_path)
        
        # Show URL features
        print("\n" + "="*60)
        print(f"URL: {url}")
        print("-"*60)
        for key, value in features_dict.items():
            if isinstance(value, float):
                print(f"{key}: {value:.3f}")
            else:
                print(f"{key}: {value}")
        print("="*60)
        
        # Test every model
        print("\nKẾT QUẢ DỰ ĐOÁN:")
        print("-"*70)
        print(f"{'Model':<15} {'Kết quả':<15} {'Confidence':<15}")
        print("-"*70)
        
        for model_file in model_files:
            model_path = os.path.join(models_folder, model_file)
            model_name = model_file.replace('_model.pkl', '')
            
            # Load model
            model = joblib.load(model_path)
            
            # Predict
            pred = model.predict(X_scaled)[0]
            
            # Decode prediction if label encoder
            if label_encoder:
                result = label_encoder.inverse_transform([pred])[0]
            else:
                result = "MALICIOUS" if pred == 1 else "BENIGN"
            
            # Probability
            conf = ""
            if hasattr(model, 'predict_proba'):
                prob = model.predict_proba(X_scaled)[0]
                conf = f"{max(prob)*100:.2f}%"
            
            print(f"{model_name:<15} {result:<15} {conf:<15}")
        
        print("-"*70)
        
    except Exception as e:
        print(f"Lỗi: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()