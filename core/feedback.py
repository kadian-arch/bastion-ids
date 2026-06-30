"""
Analyst Feedback Mechanism for Bastion IDS
==========================================

Purpose
-------
Lets a security analyst confirm or correct the verdict the system gives for an
alert. Each judgement ("Correct" or "False Alarm", optionally with the true
attack label) is stored to disk. The stored feedback is later used to retrain
and continuously improve the detection models, closing the loop between live
detection and model learning.

Why this matters for an IDS
---------------------------
No detector is perfect. By capturing the analyst's judgement on real alerts,
the system gathers labelled, real-world examples of both correct detections and
mistakes. Feeding these back into training lets the models adapt to the specific
network they protect and steadily reduce false alarms over time.

Storage
-------
Feedback is appended to data/analyst_feedback.json as a list of records:
    {
      "alert_id":      <int|str>,      # id of the alert being judged
      "verdict":       "FUZZERS",      # what the system originally said
      "source_engine": "ML_ENSEMBLE",  # which layer produced it
      "judgement":     "CORRECT" | "FALSE_ALARM",
      "true_label":    "Normal",       # optional analyst-supplied true class
      "srcip": ..., "dstip": ..., "proto": ..., "dsport": ...,  # context
      "confidence":    0.81,
      "timestamp":     "2026-05-30T...",   # when feedback was given
      "note":          "free text"          # optional analyst note
    }

This module has no heavy dependencies so it can be imported anywhere in the
backend without side effects.
"""

import os
import json
import threading
from datetime import datetime

# Store the feedback file next to the other data files.
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
FEEDBACK_FILE = os.path.join(_DATA_DIR, "analyst_feedback.json")

_lock = threading.Lock()

VALID_JUDGEMENTS = {"CORRECT", "FALSE_ALARM"}


def _ensure_store():
    """Make sure the data directory and feedback file exist."""
    os.makedirs(_DATA_DIR, exist_ok=True)
    if not os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def load_feedback():
    """Return all stored feedback records as a list."""
    _ensure_store()
    try:
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def add_feedback(alert: dict, judgement: str, true_label: str = None, note: str = None):
    """
    Record one analyst judgement on an alert.

    alert       : the alert dict the analyst is judging (as shown in the UI).
    judgement   : "CORRECT" or "FALSE_ALARM".
    true_label  : optional real attack class the analyst believes is correct.
    note        : optional free-text note.

    Returns the stored record. Raises ValueError on a bad judgement.
    """
    judgement = (judgement or "").upper().strip()
    if judgement not in VALID_JUDGEMENTS:
        raise ValueError("judgement must be CORRECT or FALSE_ALARM")

    record = {
        "alert_id":      alert.get("id"),
        "verdict":       alert.get("verdict"),
        "source_engine": alert.get("source_engine"),
        "judgement":     judgement,
        "true_label":    true_label,
        "srcip":         alert.get("srcip"),
        "dstip":         alert.get("dstip"),
        "proto":         alert.get("proto"),
        "dsport":        alert.get("dsport"),
        "confidence":    alert.get("confidence"),
        "session":       alert.get("session"),
        "timestamp":     datetime.now().isoformat(),
        "note":          note,
    }

    with _lock:
        data = load_feedback()
        data.append(record)
        with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return record


def feedback_stats():
    """
    Summarise the feedback gathered so far. Useful for the dashboard and for
    judging how much retraining data has been collected.
    """
    data = load_feedback()
    total = len(data)
    correct = sum(1 for r in data if r.get("judgement") == "CORRECT")
    false_alarms = sum(1 for r in data if r.get("judgement") == "FALSE_ALARM")
    by_engine = {}
    for r in data:
        eng = r.get("source_engine") or "UNKNOWN"
        by_engine.setdefault(eng, {"correct": 0, "false_alarm": 0})
        if r.get("judgement") == "CORRECT":
            by_engine[eng]["correct"] += 1
        elif r.get("judgement") == "FALSE_ALARM":
            by_engine[eng]["false_alarm"] += 1

    precision_signal = (correct / total) if total else 0.0
    return {
        "total_feedback": total,
        "confirmed_correct": correct,
        "false_alarms": false_alarms,
        "analyst_precision_signal": round(precision_signal, 4),
        "by_engine": by_engine,
    }


def export_retraining_set():
    """
    Build a simple list of (context, true_label) examples from feedback that the
    analyst supplied a true label for. These are the records most useful for
    retraining, since they carry a confirmed ground-truth class.
    """
    examples = []
    for r in load_feedback():
        label = r.get("true_label")
        if not label and r.get("judgement") == "CORRECT":
            label = r.get("verdict")  # confirmed-correct => verdict is the label
        if label:
            examples.append({
                "srcip": r.get("srcip"), "dstip": r.get("dstip"),
                "proto": r.get("proto"), "dsport": r.get("dsport"),
                "confidence": r.get("confidence"),
                "label": label,
            })
    return examples
