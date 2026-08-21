import os

# Base Directory
BASE_DIR = "C:/Bastion_IDS"

# Data Paths
RAW_DATA_PATH = "C:/Users/ESHOP/Hybrid ids/training/data/raw/UNSW-NB15_1.csv"

# Model Paths
MODEL_DIR = os.path.join(BASE_DIR, "models")
ARTIFACT_DIR = os.path.join(BASE_DIR, "utils")

MODELS = {
    "catboost": os.path.join(MODEL_DIR, "catboost.pkl"),
    "xgboost": os.path.join(MODEL_DIR, "xgboost.pkl"),
    "rf": os.path.join(MODEL_DIR, "randomforest_initial.pkl"),
    "dl": os.path.join(MODEL_DIR, "final_hybrid_specialist.keras"),
    "meta_judge": os.path.join(MODEL_DIR, "context_meta_judge.pkl")
}

ENCODERS = {
    "preprocessor": os.path.join(ARTIFACT_DIR, "preprocessor.pkl"),
    "label_encoder": os.path.join(ARTIFACT_DIR, "label_encoder.pkl")
}

# System Thresholds
THRESHOLD_DETECTION = 0.85
BATCH_SIZE = 1