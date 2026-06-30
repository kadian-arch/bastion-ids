import joblib
import numpy as np
import pandas as pd

class BastionPreprocessor:
    def __init__(self, transformer_path, encoder_path):
        self.transformer = joblib.load(transformer_path)
        self.le = joblib.load(encoder_path)
        
        # Get the exact column names the transformer expects
        try:
            self.feature_names = list(self.transformer.feature_names_in_)
        except:
            self.feature_names = None

    def clean_and_scale(self, raw_df):
        X = raw_df.copy()
        
        # 1. Drop absolute metadata
        drop_list = ['id', 'label', 'attack_cat', 'srcip', 'dstip', 'Stime', 'Ltime']
        X = X.drop(columns=[c for c in drop_list if c in X.columns], errors='ignore')

        # 2. IDENTIFY CATEGORIES VS NUMBERS
        # These MUST be strings for the OneHotEncoder to not crash
        cat_cols = ['proto', 'state', 'service']
        
        for col in X.columns:
            if col in cat_cols:
                X[col] = X[col].astype(str).replace('0.0', '-') # Force to string
            else:
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0.0)

        # 3. Align Columns to Training
        if self.feature_names:
            for col in self.feature_names:
                if col not in X.columns:
                    # If missing, use '-' for categories, 0.0 for numbers
                    X[col] = '-' if col in cat_cols else 0.0
            X = X[self.feature_names]

        # 4. Transform - THIS IS THE MOMENT OF TRUTH
        # We pass the DataFrame so the ColumnTransformer knows which is which
        scaled_array = self.transformer.transform(X)
        
        # 5. Format for Specialists
        # Named DF for ML
        scaled_ml_df = pd.DataFrame(scaled_array, columns=[f"f{i}" for i in range(scaled_array.shape[1])])
        
        # 3D for DL
        scaled_dl = scaled_array.reshape(scaled_array.shape[0], scaled_array.shape[1], 1)
        
        # Context (the 10 features)
        context_data = scaled_array[:, [6, 7, 8, 9, 10, 11, 12, 13, 29, 32]]
        
        return scaled_ml_df, scaled_dl, context_data

    def decode_label(self, pred_idx):
        return self.le.inverse_transform([int(np.ravel(pred_idx)[0])])[0]