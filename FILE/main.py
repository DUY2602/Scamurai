import os
import sys
import joblib
import warnings
warnings.filterwarnings('ignore')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.preprocess import extract_features

def main():
    print("="*60)
    print("MALWARE DETECTION - TEST ALL MODELS")
    print("="*60)
    
    # Input file to test
    file_path = input("\nPath to test file: ").strip()
    file_path = file_path.strip('"').strip("'")
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    # Find all model in the folder
    models_folder = "FILE/models"
    if not os.path.exists(models_folder):
        print("Folder 'models' not found")
        return
    
    model_files = [f for f in os.listdir(models_folder) if f.endswith('_model.pkl')]
    
    if not model_files:
        print("Cannot find any model files in 'FILE/models' folder")
        return
    
    print(f"\nFound {len(model_files)} models:")
    for m in model_files:
        print(f"  - {m}")
    
    try:
        # Extract features
        print("\nExtracting features...")
        features = extract_features(file_path, label=None)
        
        if not features:
            print("Cannot extract features (ensure the file type is executable)")
            return
        
        # Prepare data for prediction (drop MD5 & label)
        X = [features[1:-1]]
        
        # Show features of the file
        print("\n" + "="*60)
        print(f"FILE: {os.path.basename(file_path)}")
        print("-"*60)
        print(f"Sections: {features[1]}")
        print(f"Avg Entropy: {features[2]}")
        print(f"Max Entropy: {features[3]}")
        print(f"Suspicious Sections: {features[4]}")
        print(f"DLLs: {features[5]}")
        print(f"Imports: {features[6]}")
        print(f"Sensitive API: {'Yes' if features[7] == 1 else 'None'}")
        print(f"Image Base: {features[8]}")
        print(f"Size Image: {features[9]}")
        print(f"Has Version Info: {'Yes' if features[10] == 1 else 'None'}")
        print("="*60)
        
        # Test every model
        print("\nTEST RESULT:")
        print("-"*60)
        print(f"{'Model':<15} {'Prediction':<10} {'Confidence':<15}")
        print("-"*60)
        
        for model_file in model_files:
            model_path = os.path.join(models_folder, model_file)
            model_name = model_file.replace('_model.pkl', '')
            
            # Load model
            model = joblib.load(model_path)
            
            # Predict
            pred = model.predict(X)[0]
            result = "MALWARE" if pred == 1 else "BENIGN"
            
            # Probability
            conf = ""
            if hasattr(model, 'predict_proba'):
                prob = model.predict_proba(X)[0]
                conf = f"{max(prob)*100:.2f}%"
            
            print(f"{model_name:<15} {result:<10} {conf:<15}")
        
        print("-"*60)
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()