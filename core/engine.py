"""
BASTION IDS — MASTER DETECTION ENGINE (v2.0)
============================================
4-Layer detection pipeline:
  Layer 1: Signature Engine     (ET-Open 48k+ rules + IP reputation + heuristics)
  Layer 2: ML Ensemble          (Random Forest + XGBoost + CatBoost consensus)
  Layer 3: Deep Learning        (Residual DNN specialist)
  Layer 4: Anomaly Sentinel     (Autoencoder + Isolation Forest → zero-day)

Returns: (verdict, confidence, source_engine)
"""

import os
import sys
import io
import json
import warnings
import logging
import joblib
import numpy as np
import pandas as pd

# Suppress ALL TF/Keras console noise before importing tensorflow
os.environ["TF_CPP_MIN_LOG_LEVEL"]   = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"]  = "0"
os.environ["KERAS_BACKEND"]          = "tensorflow"

warnings.filterwarnings("ignore")          # suppress Python-level warnings (GPU, etc.)

# TensorFlow is REQUIRED only for Layer 3 (DNN) and the Layer 4 autoencoder.
# On machines whose CPU lacks AVX, or with an outdated VC++ runtime, TF's native
# DLL fails to load. That must NOT take down the whole engine — Layers 1, 2 and
# the Isolation-Forest half of Layer 4 are pure sklearn/xgboost/catboost and work
# fine without it. So we import TF defensively and degrade gracefully.
try:
    import tensorflow as tf
    logging.getLogger("tensorflow").setLevel(logging.ERROR)
    logging.getLogger("keras").setLevel(logging.ERROR)
    tf.get_logger().setLevel("ERROR")
    TF_AVAILABLE = True
    TF_LOAD_ERROR = None
except Exception as _tf_ex:               # ImportError, DLL init failure, etc.
    tf = None
    TF_AVAILABLE = False
    TF_LOAD_ERROR = str(_tf_ex).split("\n")[0][:160]

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
UTILS_DIR = os.path.join(BASE_DIR, "utils")

# Feature contract the preprocessor was trained on
UNSW_FEATURES = [
    "dur","proto","service","state","spkts","dpkts","sbytes","dbytes",
    "rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt",
    "sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat",
    "smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl",
    "ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
    "is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst",
    "is_sm_ips_ports"
]
CAT_FEATURES = ["proto","service","state"]
NUM_FEATURES  = [f for f in UNSW_FEATURES if f not in CAT_FEATURES]


class BastionEngine:

    def __init__(self):
        self._startup_messages = []
        self._log("SYSTEM: Initializing Bastion IDS Detection Engine v2.0...")

        # ── Layer 1: Signature Engine ────────────────────────────
        from core.signatures import BastionSignatureEngine
        self.sig_engine = BastionSignatureEngine()
        # Propagate signature startup log
        self._startup_messages.extend(self.sig_engine.get_startup_log())

        # ── Preprocessor & Label Encoder ────────────────────────
        self._log("SYSTEM: Loading preprocessor and label encoder...")
        self.preprocessor = joblib.load(os.path.join(UTILS_DIR, "preprocessor.pkl"))
        self.label_encoder = joblib.load(os.path.join(UTILS_DIR, "label_encoder.pkl"))
        classes = [str(c) for c in self.label_encoder.classes_]
        self._log(f"SYSTEM: Label classes: {classes}")

        # ── ML Models (Layer 2) ──────────────────────────────────
        self._log("SYSTEM: Loading ML ensemble (RF + XGB + CatBoost)...")
        self.rf  = self._try_load_model("randomforest.pkl",  "randomforest_initial.pkl")
        self.xgb = self._try_load_model("xgboost.pkl")
        self.cat = self._try_load_model("catboost.pkl")

        # ── DL Model (Layer 3) ───────────────────────────────────
        self._log("SYSTEM: Loading Deep Learning specialist...")
        self.dl = self._try_load_keras("dnn_specialist.keras", "final_hybrid_specialist.keras")

        # ── Anomaly Sentinel (Layer 4) ───────────────────────────
        self._log("SYSTEM: Loading Anomaly Sentinel (Autoencoder + Isolation Forest)...")
        self.autoencoder     = self._try_load_keras("autoencoder.keras")
        self.ae_encoder      = self._try_load_keras("autoencoder_encoder.keras")
        self.isolation_forest= self._try_load_model("isolation_forest.pkl")
        self.anomaly_config  = self._load_anomaly_config()
        if self.anomaly_config:
            self._log(f"SYSTEM: Anomaly threshold: {self.anomaly_config['autoencoder']['operational_threshold']:.5f}")

        ok  = lambda v: "[OK]" if v else "[--]"
        layers_up = self.get_model_status()["layers_active"]
        if layers_up == 4:
            self._log("SYSTEM: [OK] ALL 4 DETECTION LAYERS ONLINE")
        else:
            self._log(f"SYSTEM: [WARN] {layers_up}/4 DETECTION LAYERS ONLINE "
                      f"(deep-learning layer disabled — TensorFlow unavailable on "
                      f"this machine; signature, ML and anomaly detection active)")
        self._log(
            f"SYSTEM: Signatures: {self.sig_engine.rules_count:,} | "
            f"ML: {ok(self.rf)} RF {ok(self.xgb)} XGB {ok(self.cat)} CAT | "
            f"DL: {ok(self.dl)} | Anomaly: {ok(self.autoencoder or self.isolation_forest)}"
        )

    # ── Loaders ────────────────────────────────────────────────────
    def _try_load_model(self, *names):
        for name in names:
            path = os.path.join(MODEL_DIR, name)
            if os.path.exists(path):
                try:
                    m = joblib.load(path)
                    self._log(f"  Loaded: {name}")
                    return m
                except Exception as ex:
                    short = str(ex).split("\n")[0][:120]
                    self._log(f"  [WARN] Could not load {name}: {short}")
        return None

    @staticmethod
    def _strip_renorm(obj):
        """Recursively remove legacy renorm* keys from a deserialized config dict."""
        if isinstance(obj, dict):
            for k in ("renorm", "renorm_clipping", "renorm_momentum"):
                obj.pop(k, None)
            for v in obj.values():
                BastionEngine._strip_renorm(v)
        elif isinstance(obj, list):
            for item in obj:
                BastionEngine._strip_renorm(item)

    @staticmethod
    def _load_keras_compat(path: str):
        """
        Load a .keras model file, patching legacy BatchNormalization renorm args.

        The .keras format is a ZIP containing config.json + model.weights.h5.
        Keras resolves classes by their full module path, so custom_objects won't
        intercept BatchNormalization — instead we patch the config.json inside
        the zip directly to remove the unsupported renorm* fields.
        """
        import zipfile, tempfile, shutil

        # Pass 1: normal load (works if model was saved with current Keras)
        try:
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = io.StringIO()
            try:
                return tf.keras.models.load_model(path, compile=False)
            finally:
                sys.stdout, sys.stderr = old_out, old_err
        except Exception:
            pass

        # Pass 2: patch config.json inside the .keras zip, then reload
        tmpdir = tempfile.mkdtemp(prefix="bastion_keras_")
        try:
            patched = os.path.join(tmpdir, os.path.basename(path))

            # Read original zip contents
            with zipfile.ZipFile(path, "r") as zin:
                members = {n: zin.read(n) for n in zin.namelist()}

            # Patch the architecture config — strip renorm* from every layer dict
            cfg_key = next((k for k in members if k.endswith("config.json")), None)
            if cfg_key:
                cfg = json.loads(members[cfg_key].decode("utf-8"))
                BastionEngine._strip_renorm(cfg)
                members[cfg_key] = json.dumps(cfg).encode("utf-8")

            # Write patched zip
            with zipfile.ZipFile(patched, "w", zipfile.ZIP_DEFLATED) as zout:
                for name, data in members.items():
                    zout.writestr(name, data)

            # Load the patched model (silence any remaining chatter)
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = io.StringIO()
            try:
                return tf.keras.models.load_model(patched, compile=False)
            finally:
                sys.stdout, sys.stderr = old_out, old_err

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _try_load_keras(self, *names):
        if not TF_AVAILABLE:
            self._log(f"  [WARN] Skipping {names[0]} — TensorFlow unavailable "
                      f"({TF_LOAD_ERROR}). Deep-learning layer disabled; other "
                      f"layers unaffected.")
            return None
        for name in names:
            path = os.path.join(MODEL_DIR, name)
            if not os.path.exists(path):
                continue
            try:
                m = self._load_keras_compat(path)
                if m is not None:
                    self._log(f"  Loaded: {name}")
                    return m
            except Exception as ex:
                short = str(ex).split("\n")[0][:120]
                self._log(f"  [WARN] Could not load {name}: {short}")
        return None

    def _load_anomaly_config(self):
        path = os.path.join(UTILS_DIR, "anomaly_threshold.json")
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    def _log(self, msg):
        # Encode safely for Windows console (cp1252 can't handle emoji)
        safe = msg.encode("ascii", errors="replace").decode("ascii")
        print(safe, flush=True)
        self._startup_messages.append(msg)  # keep original in memory

    # ── Universal Flow Preprocessing ────────────────────────────────
    def _prepare_flow(self, raw_flow_df: pd.DataFrame) -> pd.DataFrame:
        """
        Convert any input DataFrame to the exact 42-feature UNSW contract.
        Handles column name aliases from live capture, CICIDS, and other formats.
        """
        from utils.feature_bridge import bridge, detect_dataset_format
        fmt = detect_dataset_format(raw_flow_df)
        features, _ = bridge(raw_flow_df)
        return features

    def _transform(self, flow_df: pd.DataFrame):
        """Apply the fitted ColumnTransformer and return (X_ml, X_dl)."""
        try:
            X = self.preprocessor.transform(flow_df)
            # DL expects 3D (batch, timesteps, features) — wrap as (1, 1, n)
            X_dl = X.reshape(1, 1, -1) if X.ndim == 2 and X.shape[0] == 1 else X
            return X, X_dl
        except Exception as ex:
            # Fallback: zero vector
            n = len(UNSW_FEATURES)
            X = np.zeros((1, n))
            return X, X.reshape(1, 1, n)

    def _decode(self, idx: int) -> str:
        try:
            return str(self.label_encoder.inverse_transform([idx])[0])
        except Exception:
            return "Unknown"

    # ── Core Analysis ───────────────────────────────────────────────
    def analyze_flow(self, raw_flow_df: pd.DataFrame,
                     raw_payload: bytes = None):
        """
        Run the full 4-layer detection pipeline on one or more flows.

        Args:
            raw_flow_df: One-or-more-row DataFrame (any format, any column names).
                         When multiple rows are supplied the most severe verdict
                         across all rows is returned (any attack row flags the batch).
            raw_payload: Optional raw packet bytes for signature content matching

        Returns:
            (verdict: str, confidence: float, source_engine: str)
        """
        # ── MULTI-ROW: vectorised path — returns most severe verdict ───
        if len(raw_flow_df) > 1:
            n = len(raw_flow_df)
            _safe = {"NORMAL", "BASTION_CLEAN", "PREPROCESSING_ERROR", ""}
            best_verdict, best_conf, best_eng = "NORMAL", 0.0, "BASTION_CLEAN"

            # Layer 1: signature check per row (must be per-row; fast)
            sig_hit_idx  = None
            for idx in range(n):
                row_df = raw_flow_df.iloc[idx : idx + 1]
                try:
                    matched, sig_msg, sig_conf, *_ = self.sig_engine.match(row_df, raw_payload)
                    if matched and sig_conf > best_conf:
                        best_verdict, best_conf, best_eng = str(sig_msg), sig_conf, "SIGNATURE_DB"
                except Exception:
                    pass

            # Layers 2-4: batch-vectorised ML / DL / anomaly
            try:
                flow_df = self._prepare_flow(raw_flow_df)
                X_batch = self.preprocessor.transform(flow_df)   # shape (n, n_feat)
            except Exception:
                return best_verdict, best_conf, best_eng

            # ML ensemble — single predict_proba call per model across all rows
            experts_batch = []   # list of (name, proba_matrix)
            for name, model in [("RF", self.rf), ("XGB", self.xgb), ("CAT", self.cat)]:
                if model is None:
                    continue
                try:
                    proba = model.predict_proba(X_batch)          # (n, n_classes)
                    experts_batch.append((name, proba))
                except Exception:
                    continue

            for row_i in range(n):
                experts = []
                for name, proba in experts_batch:
                    idx  = int(np.argmax(proba[row_i]))
                    conf = float(proba[row_i][idx])
                    lbl  = self._decode(idx)
                    experts.append({"name": name, "label": lbl, "conf": conf})
                malicious = [e for e in experts
                             if e["label"].upper() != "NORMAL" and e["conf"] >= 0.70]
                if len(malicious) < 2:
                    soft = [e for e in experts if e["label"].upper() != "NORMAL" and e["conf"] >= 0.60]
                    if len(soft) >= 2:
                        lbls = [e["label"].upper() for e in soft]
                        if lbls.count(lbls[0]) >= 2:
                            malicious = [e for e in soft if e["label"].upper() == lbls[0]]
                if len(malicious) >= 2 or any(e["conf"] >= 0.92 for e in malicious):
                    top = max(malicious, key=lambda x: x["conf"])
                    if top["conf"] > best_conf:
                        best_verdict, best_conf, best_eng = top["label"].upper(), top["conf"], "ML_ENSEMBLE"

            # DL — single batch predict call
            if self.dl is not None:
                try:
                    dl_proba = np.array(self.dl.predict(X_batch, verbose=0))   # (n, n_classes)
                    for row_i in range(n):
                        dl_idx  = int(np.argmax(dl_proba[row_i]))
                        dl_conf = float(dl_proba[row_i][dl_idx])
                        dl_lbl  = self._decode(dl_idx)
                        if dl_lbl.upper() != "NORMAL" and dl_conf >= 0.82 and dl_conf > best_conf:
                            best_verdict, best_conf, best_eng = dl_lbl.upper(), dl_conf, "DL-SENSEI"
                except Exception:
                    pass

            # Anomaly — batch reconstruction error per row
            if self.autoencoder is not None:
                try:
                    ae_cfg    = self.anomaly_config["autoencoder"]
                    ae_thresh = ae_cfg["operational_threshold"]
                    X_recon   = self.autoencoder.predict(X_batch, verbose=0)
                    ae_errs   = np.mean((X_batch - X_recon) ** 2, axis=1)   # (n,)
                    anomalous = np.where(ae_errs > ae_thresh)[0]
                    if len(anomalous):
                        row_i   = anomalous[int(np.argmax(ae_errs[anomalous]))]
                        ae_score = min(1.0, float(ae_errs[row_i]) / (ae_thresh * 2))
                        if ae_score > best_conf:
                            best_verdict, best_conf, best_eng = "ANOMALY_DETECTED", ae_score, "ANOMALY"
                except Exception:
                    pass

            return best_verdict, best_conf, best_eng

        # ── LAYER 1: SIGNATURE ENGINE ──────────────────────────────
        matched, sig_msg, sig_conf, sig_sev, sig_sid, sig_classtype = \
            self.sig_engine.match(raw_flow_df, raw_payload)
        if matched:
            return str(sig_msg), sig_conf, "SIGNATURE_DB"

        # ── PREPROCESSING (universal, any format) ─────────────────
        try:
            flow_df = self._prepare_flow(raw_flow_df)
            X_ml, X_dl = self._transform(flow_df)
        except Exception:
            return "NORMAL", 0.0, "PREPROCESSING_ERROR"

        # ── LAYER 2: ML ENSEMBLE ───────────────────────────────────
        experts = []
        for name, model in [("RF", self.rf), ("XGB", self.xgb), ("CAT", self.cat)]:
            if model is None:
                continue
            try:
                prob = model.predict_proba(X_ml)[0]
                idx  = int(np.argmax(prob))
                conf = float(np.max(prob))
                label= self._decode(idx)
                experts.append({"name":name,"label":label,"conf":conf,"prob":prob})
            except Exception:
                continue

        malicious_ml = [e for e in experts
                        if e["label"].upper() != "NORMAL" and e["conf"] >= 0.70]
        # Soft consensus: two models agree on the same class at >=0.60.
        # Applied when hard consensus (2+ at 0.70) is not yet met.
        # Normal traffic scores >0.90 Normal, so 0.60 attack confidence
        # from two independent models is statistically meaningful signal.
        if len(malicious_ml) < 2:
            soft_ml = [e for e in experts
                       if e["label"].upper() != "NORMAL" and e["conf"] >= 0.60]
            if len(soft_ml) >= 2:
                labels = [e["label"].upper() for e in soft_ml]
                if labels.count(labels[0]) >= 2:
                    malicious_ml = [e for e in soft_ml if e["label"].upper() == labels[0]]

        # Consensus: 2+ models agree
        if len(malicious_ml) >= 2:
            top = max(malicious_ml, key=lambda x: x["conf"])
            return top["label"].upper(), top["conf"], "ML_ENSEMBLE"

        # Single model extremely confident
        if any(e["conf"] >= 0.92 for e in malicious_ml):
            top = max(malicious_ml, key=lambda x: x["conf"])
            return top["label"].upper(), top["conf"], "ML_ENSEMBLE"

        # ── LAYER 3: DEEP LEARNING ─────────────────────────────────
        if self.dl is not None:
            try:
                # DL model may be flat (1, n_feat) or seq (1, 1, n_feat)
                try:
                    dl_prob = self.dl.predict(X_ml, verbose=0)[0]
                except Exception:
                    dl_prob = self.dl.predict(X_dl, verbose=0)[0]

                dl_idx  = int(np.argmax(dl_prob))
                dl_conf = float(np.max(dl_prob))
                dl_label= self._decode(dl_idx)
                if dl_label.upper() != "NORMAL" and dl_conf >= 0.82:
                    return dl_label.upper(), dl_conf, "DL-SENSEI"
            except Exception:
                pass

        # ── LAYER 4: ANOMALY SENTINEL (Zero-Day) ──────────────────
        anomaly_result = self._anomaly_check(X_ml)
        if anomaly_result is not None:
            score, verdict = anomaly_result
            return verdict, score, "ANOMALY"

        # ALL 4 LAYERS: No threat detected
        return "NORMAL", 0.0, "BASTION_CLEAN"

    def _anomaly_check(self, X_ml: np.ndarray):
        """
        Layer 4: Autoencoder + Isolation Forest anomaly scoring.
        Returns (combined_score, verdict) if anomalous, else None.
        """
        if self.anomaly_config is None:
            return None

        ae_score  = 0.0
        if_score  = 0.0
        ae_thresh = self.anomaly_config["autoencoder"]["operational_threshold"]
        if_thresh = self.anomaly_config["isolation_forest"]["threshold"]
        ae_w      = self.anomaly_config["combined_weights"]["autoencoder_weight"]
        if_w      = self.anomaly_config["combined_weights"]["isolation_forest_weight"]

        # Autoencoder reconstruction error
        if self.autoencoder is not None:
            try:
                X_recon = self.autoencoder.predict(X_ml, verbose=0)
                ae_err  = float(np.mean((X_ml - X_recon) ** 2))
                # Normalize to [0, 1] based on threshold
                ae_score = min(1.0, ae_err / (ae_thresh * 2))
                ae_anomalous = ae_err > ae_thresh
            except Exception:
                ae_anomalous = False
        else:
            ae_anomalous = False

        # Isolation Forest
        if_anomalous = False
        if self.isolation_forest is not None and self.ae_encoder is not None:
            try:
                encoded = self.ae_encoder.predict(X_ml, verbose=0)
                if_dec  = float(self.isolation_forest.decision_function(encoded)[0])
                if_score = max(0.0, min(1.0, (if_thresh - if_dec) / (abs(if_thresh) + 1e-9)))
                if_anomalous = if_dec < if_thresh
            except Exception:
                pass
        elif self.isolation_forest is not None:
            try:
                if_dec  = float(self.isolation_forest.decision_function(X_ml)[0])
                if_score = max(0.0, min(1.0, (if_thresh - if_dec) / (abs(if_thresh) + 1e-9)))
                if_anomalous = if_dec < if_thresh
            except Exception:
                pass

        # Combined decision — require CONSENSUS from both detectors to reduce
        # false positives. Single-detector anomalies are too noisy for production.
        combined = ae_w * ae_score + if_w * if_score
        combined = round(min(1.0, combined), 4)

        # Both detectors must agree, AND combined score must exceed threshold
        both_agree = ae_anomalous and if_anomalous
        strong_single = (ae_anomalous and ae_score >= 0.90) or \
                        (if_anomalous and if_score >= 0.90)

        if (both_agree or strong_single) and combined >= 0.75:
            if combined >= 0.90:
                verdict = "ZERO-DAY THREAT: Novel Attack Pattern Detected"
            elif combined >= 0.80:
                verdict = "SUSPICIOUS: Possible Zero-Day or Novel Attack"
            else:
                verdict = "ANOMALY: Traffic Deviates from Baseline Profile"
            return combined, verdict

        return None

    def get_startup_log(self):
        """Return startup log lines for dashboard display."""
        return self._startup_messages

    def get_model_status(self) -> dict:
        """Return status dict for health endpoint."""
        return {
            "signature_engine": self.sig_engine.rules_count > 0,
            "signatures_active": self.sig_engine.rules_count,
            "ml_rf":    self.rf is not None,
            "ml_xgb":   self.xgb is not None,
            "ml_cat":   self.cat is not None,
            "dl":       self.dl is not None,
            # Layer 4 is "up" if EITHER detector is available. The Isolation
            # Forest is pure sklearn and works even when TF (autoencoder) can't load.
            "anomaly":  (self.autoencoder is not None) or (self.isolation_forest is not None),
            "isolation_forest": self.isolation_forest is not None,
            "tf_available": TF_AVAILABLE,
            "layers_active": sum([
                self.sig_engine.rules_count > 0,
                any([self.rf, self.xgb, self.cat]),
                self.dl is not None,
                (self.autoencoder is not None) or (self.isolation_forest is not None),
            ])
        }
