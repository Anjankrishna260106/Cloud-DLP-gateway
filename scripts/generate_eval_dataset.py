"""
Generates a 25-file diverse synthetic dataset for DLP engine evaluation.
Mixes plain text, CSV, PDF, DOCX, and XLSX formats with ground-truth labels.
"""

import os
import io
import json

EVAL_DIR = os.path.abspath("test-files/eval_dataset")
os.makedirs(EVAL_DIR, exist_ok=True)


def create_eval_dataset():
    files_manifest = []

    # --- 1. SAFE SAMPLES (Negative Ground Truth for sensitive leakage) ---
    safe_samples = [
        ("eval_01_safe_memo.txt", "text", "Quarterly engineering review meeting minutes. Team completed sprint 42 on schedule. System uptime was 99.98% with all cloud microservices functioning normally.", []),
        ("eval_02_safe_readme.md", "text", "# Open Source Documentation\nThis module exports utility functions for matrix transformations and string manipulations with zero external dependencies.", []),
        ("eval_03_safe_config.json", "text", json.dumps({"app": "gateway", "version": "1.0", "cache_ttl": 300, "debug": False, "regions": ["us-east-1", "eu-west-1"]}, indent=2), []),
        ("eval_04_safe_catalog.csv", "csv", "item_id,item_name,price_usd,stock_count\nSKU-1001,Wireless Keyboard,45.00,120\nSKU-1002,Ergonomic Mouse,25.50,340\nSKU-1003,USB-C Monitor Cable,12.00,800", []),
        ("eval_05_safe_press_release.txt", "text", "Global Tech Corp announces open-source contributions to Linux container standards. Media contacts: please reach out via the official website press portal.", []),
        ("eval_06_safe_license.txt", "text", "Apache License Version 2.0, January 2004. Licensed under the Apache License, Version 2.0; you may not use this file except in compliance with the License.", []),
        ("eval_07_safe_changelog.txt", "text", "Changelog 2.4.0:\n- Fixed edge case in date parsing\n- Added support for gzip compressed streams\n- Refactored internal buffer pools", []),
    ]

    # --- 2. PII / CONTACT SAMPLES (Emails & Phone Numbers -> MASK) ---
    pii_samples = [
        ("eval_08_email_directory.txt", "text", "Staff Directory:\nAlice Smith: alice.smith.work@example.com\nBob Jones: b.jones@enterprise.org\nCarol Lee: carol.lee99@domain.co.in", ["EMAIL"]),
        ("eval_09_phone_roster.txt", "text", "On-Call Phone Escalation Schedule:\nPrimary Lead: +91-98765-43210\nSecondary Lead: 09811223344\nEscalation Manager: +1-555-432-8765", ["PHONE"]),
        ("eval_10_mixed_pii_contacts.csv", "csv", "name,email,phone\nRahul Sharma,rahul.sharma@testcorp.com,+91-99887-76655\nDeepa Nair,deepa.nair@sample.net,9823012345", ["EMAIL", "PHONE"]),
        ("eval_11_support_inquiry.txt", "text", "Help desk ticket: Customer John reported order missing. Customer callback phone number is (555) 234-5678 and email is j.doe@customermail.com.", ["EMAIL", "PHONE"]),
        ("eval_12_newsletter_subscribers.txt", "text", "Subscribers awaiting confirmation:\nsubscriber.one@news.org\nsubscriber.two@bulletin.io\nmarketing.lead@startuphub.ai", ["EMAIL"]),
    ]

    # --- 3. FINANCIAL / HIGH-IMPACT IDENTITY (PAN, Cards, Aadhaar -> QUARANTINE) ---
    financial_samples = [
        ("eval_13_pan_records.csv", "csv", "employee_id,employee_name,pan_card\nEMP-01,Vikram Rao,ABCPA1234F\nEMP-02,Ananya Sen,PQRCA5678K\nEMP-03,Suresh Kumar,LMNPA9012M", ["PAN"]),
        ("eval_14_credit_cards.csv", "csv", "account_id,card_number,exp,limit\nACC-991,4111111111111111,12/28,5000\nACC-992,5500000000000004,06/27,10000\nACC-993,4242424242424242,10/29,7500", ["CREDIT_CARD"]),
        ("eval_15_aadhaar_registry.txt", "text", "Government Identity Verification Records:\nApplicant 1 UID: 2123 4567 8904\nApplicant 2 UID: 3456 7890 1238", ["AADHAAR"]),
        ("eval_16_pan_and_cards.csv", "csv", "user_ref,pan,credit_card,phone\nUSR-1,ABCPA1234F,4111111111111111,+91-98200-11223\nUSR-2,PQRCA5678K,5500000000000004,9876501234", ["PAN", "CREDIT_CARD", "PHONE"]),
        ("eval_17_tax_filing_summary.txt", "text", "ITR Filing Confirmation:\nAssessee: Rajesh Gupta\nPAN: BCDPG4321H\nAadhaar: 2345 6789 0127\nBank card verification: 4111-1111-1111-1111", ["PAN", "AADHAAR", "CREDIT_CARD"]),
    ]

    # --- 4. CLOUD SECRETS & CREDENTIALS (AWS Keys, API Keys, Passwords -> BLOCK) ---
    secret_samples = [
        ("eval_18_aws_credentials.env", "text", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=ap-south-1", ["AWS_KEY"]),
        ("eval_19_stripe_secrets.txt", "text", "Stripe Live Secret Keys:\nProduction: sk_DEMO_FAKE_51AbcDefGhiJklMnoPqrStuVwxYz123456\nRestricted: rk_DEMO_FAKE_51AbcDefGhiJklMnoPqrStuVwxYz123456", ["API_KEY"]),
        ("eval_20_github_tokens.txt", "text", "Deployment PAT Token:\nexport GITHUB_TOKEN=ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyzAB\nexport SLACK_TOKEN=xoxb-FAKE-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", ["API_KEY"]),
        ("eval_21_database_passwords.env", "text", "DATABASE_URL=postgres://app_user:AdminSuperSecret2026!@db.internal:5432/production\nREDIS_AUTH=redis_pass = 'SecretCachePassword99!'", ["PASSWORD"]),
        ("eval_22_mixed_cloud_keys.txt", "text", "Production config dump:\naws_access_key = 'AKIA1122334455667788'\napi_key = 'AIzaSyA12345678901234567890123456789012'\nadmin_password = 'ProductionPassword@2026'", ["AWS_KEY", "API_KEY", "PASSWORD"]),
    ]

    # --- 5. MULTI-FORMAT SAMPLES (DOCX, XLSX, PDF) ---
    multi_format_samples = [
        ("eval_23_employee_onboarding.docx", "docx", "Employee Onboarding Record:\nName: Meera Patel\nPersonal Email: meera.patel@samplemail.com\nEmergency Contact: +91-98112-99887\nAssigned Department: Cloud Infrastructure", ["EMAIL", "PHONE"]),
        ("eval_24_financial_audit.xlsx", "xlsx", [["Transaction ID", "Customer PAN", "Amount INR"], ["TXN-501", "ABCPA1234F", "150000"], ["TXN-502", "PQRCA5678K", "82000"]], ["PAN"]),
        ("eval_25_executive_memo.pdf", "pdf", "Executive Security Advisory:\nCloud accounts must rotate credentials immediately.\nLeak notice detected for AWS Key AKIA2233445566778899 and associated administrator password.", ["AWS_KEY", "PASSWORD"]),
    ]

    # Write text and CSV files
    for filename, ftype, content, expected_entities in safe_samples + pii_samples + financial_samples + secret_samples:
        filepath = os.path.join(EVAL_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        files_manifest.append({
            "filename": filename,
            "format": ftype,
            "expected_entities": expected_entities,
            "is_sensitive": len(expected_entities) > 0,
            "expected_action": (
                "BLOCK" if any(e in ["AWS_KEY", "API_KEY", "PASSWORD"] for e in expected_entities) else
                "QUARANTINE" if any(e in ["PAN", "CREDIT_CARD", "AADHAAR"] for e in expected_entities) else
                "MASK" if len(expected_entities) > 0 else
                "ALLOW"
            )
        })

    # Write multi-format files
    import docx
    import openpyxl
    import fitz

    # DOCX
    docx_file, _, docx_text, docx_expected = multi_format_samples[0]
    docx_path = os.path.join(EVAL_DIR, docx_file)
    doc = docx.Document()
    doc.add_paragraph(docx_text)
    doc.save(docx_path)
    files_manifest.append({
        "filename": docx_file, "format": "docx", "expected_entities": docx_expected,
        "is_sensitive": True, "expected_action": "MASK"
    })

    # XLSX
    xlsx_file, _, xlsx_rows, xlsx_expected = multi_format_samples[1]
    xlsx_path = os.path.join(EVAL_DIR, xlsx_file)
    wb = openpyxl.Workbook()
    ws = wb.active
    for r in xlsx_rows:
        ws.append(r)
    wb.save(xlsx_path)
    files_manifest.append({
        "filename": xlsx_file, "format": "xlsx", "expected_entities": xlsx_expected,
        "is_sensitive": True, "expected_action": "QUARANTINE"
    })

    # PDF
    pdf_file, _, pdf_text, pdf_expected = multi_format_samples[2]
    pdf_path = os.path.join(EVAL_DIR, pdf_file)
    pdoc = fitz.open()
    page = pdoc.new_page()
    page.insert_text((72, 72), pdf_text)
    pdoc.save(pdf_path)
    pdoc.close()
    files_manifest.append({
        "filename": pdf_file, "format": "pdf", "expected_entities": pdf_expected,
        "is_sensitive": True, "expected_action": "BLOCK"
    })

    manifest_path = os.path.join(EVAL_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(files_manifest, f, indent=2)

    print(f"Generated {len(files_manifest)} evaluation files in {EVAL_DIR}")


if __name__ == "__main__":
    create_eval_dataset()
