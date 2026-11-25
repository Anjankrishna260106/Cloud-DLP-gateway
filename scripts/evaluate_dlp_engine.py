"""
Comprehensive DLP Engine Benchmark & Metric Evaluation.
Evaluates the 25-file synthetic test dataset against the DLPGateway.
Calculates Precision, Recall, False Positive Rate (FPR), and F1 Score
both overall (Sensitive vs Safe) and per-data-type.
Outputs clean formatted Markdown tables for the seminar report.
"""

import os
import sys
import json
from collections import defaultdict

# Ensure project root & dlp-engine on sys.path
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("dlp-engine"))

from gateway import DLPGateway

EVAL_DIR = os.path.abspath("test-files/eval_dataset")
MANIFEST_PATH = os.path.join(EVAL_DIR, "manifest.json")


def run_evaluation():
    if not os.path.exists(MANIFEST_PATH):
        raise FileNotFoundError(f"Manifest not found at {MANIFEST_PATH}. Run scripts/generate_eval_dataset.py first.")

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    gateway = DLPGateway(redos_vulnerable_mode=False)

    # Global Binary Classification Counters (Sensitive vs Safe)
    global_tp = 0  # Ground truth sensitive & detected sensitive
    global_fp = 0  # Ground truth safe & detected sensitive (False Alarm)
    global_tn = 0  # Ground truth safe & detected safe
    global_fn = 0  # Ground truth sensitive & detected safe (Leakage Miss)

    # Policy Action Accuracy Counters
    policy_matches = 0

    # Per-Entity Counters: {entity_type: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}}
    target_entity_types = ["EMAIL", "PHONE", "PAN", "AADHAAR", "CREDIT_CARD", "API_KEY", "AWS_KEY", "PASSWORD"]
    entity_stats = {etype: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for etype in target_entity_types}

    evaluation_rows = []

    for item in manifest:
        filename = item["filename"]
        filepath = os.path.join(EVAL_DIR, filename)
        with open(filepath, "rb") as f:
            file_bytes = f.read()

        scan_result, _ = gateway.process(file_bytes, filename)

        predicted_sensitive = scan_result.findings_count > 0
        actual_sensitive = item["is_sensitive"]

        # Global Binary Metrics
        if actual_sensitive and predicted_sensitive:
            global_tp += 1
        elif not actual_sensitive and predicted_sensitive:
            global_fp += 1
        elif not actual_sensitive and not predicted_sensitive:
            global_tn += 1
        elif actual_sensitive and not predicted_sensitive:
            global_fn += 1

        # Policy Action Match
        if scan_result.policy_action.value == item["expected_action"]:
            policy_matches += 1

        # Detected entities set
        predicted_entities = set(scan_result.summary_by_type.keys())
        expected_entities = set(item["expected_entities"])

        # Update per-entity metrics
        for etype in target_entity_types:
            exp = etype in expected_entities
            pred = etype in predicted_entities
            if exp and pred:
                entity_stats[etype]["tp"] += 1
            elif not exp and pred:
                entity_stats[etype]["fp"] += 1
            elif not exp and not pred:
                entity_stats[etype]["tn"] += 1
            elif exp and not pred:
                entity_stats[etype]["fn"] += 1

        evaluation_rows.append({
            "filename": filename,
            "format": item["format"],
            "expected_entities": list(expected_entities),
            "detected_entities": list(predicted_entities),
            "expected_action": item["expected_action"],
            "predicted_action": scan_result.policy_action.value,
            "action_match": scan_result.policy_action.value == item["expected_action"],
            "latency_ms": scan_result.processing_time_ms
        })

    # Calculations
    precision = global_tp / (global_tp + global_fp) if (global_tp + global_fp) > 0 else 1.0
    recall = global_tp / (global_tp + global_fn) if (global_tp + global_fn) > 0 else 1.0
    fpr = global_fp / (global_fp + global_tn) if (global_fp + global_tn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (global_tp + global_tn) / len(manifest)
    policy_accuracy = policy_matches / len(manifest)

    # Format Markdown Results Table
    markdown_report = []
    markdown_report.append("# CloudGuard Pre-Storage DLP Engine: Quantitative Evaluation\n")
    markdown_report.append(f"**Test Dataset Size**: {len(manifest)} synthetic files across 5 file formats (`.txt`, `.csv`, `.pdf`, `.docx`, `.xlsx`)")
    markdown_report.append(f"**Overall Classification Accuracy**: {accuracy * 100:.2f}% | **Policy Routing Accuracy**: {policy_accuracy * 100:.2f}%\n")

    markdown_report.append("### 1. Overall Binary DLP Performance (Sensitive vs Safe Payload)")
    markdown_report.append("| Metric | Formula | Value | Percentage | Description |")
    markdown_report.append("| :--- | :--- | :---: | :---: | :--- |")
    markdown_report.append(f"| **True Positives (TP)** | Correctly identified sensitive files | {global_tp} | — | Sensitive files intercepted before storage |")
    markdown_report.append(f"| **True Negatives (TN)** | Correctly identified safe files | {global_tn} | — | Safe business files routed directly to Safe S3 |")
    markdown_report.append(f"| **False Positives (FP)** | Safe files flagged as sensitive | {global_fp} | — | False alarms blocking legitimate productivity |")
    markdown_report.append(f"| **False Negatives (FN)** | Sensitive files missed by DLP | {global_fn} | — | Catastrophic data leaks into storage |")
    markdown_report.append(f"| **Precision** | $\\frac{{TP}}{{TP + FP}}$ | **{precision:.4f}** | **{precision * 100:.1f}%** | Ratio of true detections over all alarms |")
    markdown_report.append(f"| **Recall (Sensitivity)** | $\\frac{{TP}}{{TP + FN}}$ | **{recall:.4f}** | **{recall * 100:.1f}%** | Coverage: 100% means zero missed leaks |")
    markdown_report.append(f"| **False Positive Rate (FPR)** | $\\frac{{FP}}{{FP + TN}}$ | **{fpr:.4f}** | **{fpr * 100:.1f}%** | Rate of benign files incorrectly flagged |")
    markdown_report.append(f"| **F1-Score** | $2 \\cdot \\frac{{P \\cdot R}}{{P + R}}$ | **{f1:.4f}** | **{f1 * 100:.1f}%** | Harmonic balance between precision and recall |")

    markdown_report.append("\n### 2. Granular Per-Data-Type Detection Breakdown")
    markdown_report.append("| Sensitive Entity Type | Validation Technique | Ground Truth Count | TP | FP | FN | Precision | Recall | FPR |")
    markdown_report.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    for etype in target_entity_types:
        s = entity_stats[etype]
        p_val = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 1.0
        r_val = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 1.0
        fpr_val = s["fp"] / (s["fp"] + s["tn"]) if (s["fp"] + s["tn"]) > 0 else 0.0
        gt_count = s["tp"] + s["fn"]
        val_tech = {
            "EMAIL": "RFC Linear Regex",
            "PHONE": "E.164 + Indian Mobile Regex",
            "PAN": "Entity Code Regex (4th char)",
            "AADHAAR": "Verhoeff Checksum Matrix",
            "CREDIT_CARD": "Luhn Mod-10 Checksum",
            "API_KEY": "High Entropy / Prefix Match",
            "AWS_KEY": "AKIA/ASIA Prefix + Secret Regex",
            "PASSWORD": "Config & Key-Value Patterns"
        }.get(etype, "Regex")
        markdown_report.append(f"| `{etype}` | {val_tech} | {gt_count} | {s['tp']} | {s['fp']} | {s['fn']} | {p_val * 100:.1f}% | {r_val * 100:.1f}% | {fpr_val * 100:.1f}% |")

    markdown_report.append("\n### 3. File-by-File Evaluation Audit Log")
    markdown_report.append("| File | Format | Expected | Detected | Expected Action | Executed Action | Match | Latency |")
    markdown_report.append("| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :---: |")
    for row in evaluation_rows:
        exp_str = ", ".join(row["expected_entities"]) or "None (Safe)"
        det_str = ", ".join(row["detected_entities"]) or "None (Safe)"
        match_icon = "PASS" if row["action_match"] else "FAIL"
        markdown_report.append(f"| `{row['filename']}` | {row['format']} | {exp_str} | {det_str} | {row['expected_action']} | {row['predicted_action']} | {match_icon} | {row['latency_ms']} ms |")

    report_text = "\n".join(markdown_report)

    output_path = os.path.join(EVAL_DIR, "EVALUATION_REPORT.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print("\n" + report_text)
    print(f"\nEvaluation Report successfully saved to: {output_path}")
    return report_text


if __name__ == "__main__":
    run_evaluation()
