"""
Multi-format text extraction engine for pre-storage DLP gateway.
Supports: .txt, .csv, .pdf, .docx, .xlsx
"""

import io
import os
from typing import Tuple, Dict, Any


def extract_text_from_file(file_bytes: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
    """
    Extract readable text and document metadata from file bytes.
    Returns: (extracted_text, metadata_dict)
    """
    ext = os.path.splitext(filename)[1].lower().strip(".")
    metadata = {
        "filename": filename,
        "extension": ext,
        "file_size": len(file_bytes),
        "extractor_used": "unknown",
        "page_or_record_count": 1
    }

    if not file_bytes:
        return "", metadata

    if ext in ["txt", "log", "env", "json", "yml", "yaml", "xml", "md", "sql"]:
        text = _extract_txt(file_bytes)
        metadata["extractor_used"] = "builtin_text"
        return text, metadata

    elif ext == "csv":
        text, rows = _extract_csv(file_bytes)
        metadata["extractor_used"] = "csv_pandas"
        metadata["page_or_record_count"] = rows
        return text, metadata

    elif ext == "pdf":
        text, pages = _extract_pdf(file_bytes)
        metadata["extractor_used"] = "pymupdf_fitz"
        metadata["page_or_record_count"] = pages
        return text, metadata

    elif ext in ["docx", "doc"]:
        text, paragraphs = _extract_docx(file_bytes)
        metadata["extractor_used"] = "python_docx"
        metadata["page_or_record_count"] = paragraphs
        return text, metadata

    elif ext in ["xlsx", "xls"]:
        text, sheets_and_rows = _extract_xlsx(file_bytes)
        metadata["extractor_used"] = "openpyxl_pandas"
        metadata["page_or_record_count"] = sheets_and_rows
        return text, metadata

    else:
        # Fallback binary/string extraction attempt
        try:
            text = file_bytes.decode("utf-8", errors="ignore")
            metadata["extractor_used"] = "fallback_utf8"
            return text, metadata
        except Exception:
            return "", metadata


def _extract_txt(file_bytes: bytes) -> str:
    """Extract plain text with multiple encoding fallbacks."""
    for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
        try:
            return file_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="ignore")


def _extract_csv(file_bytes: bytes) -> Tuple[str, int]:
    """Extract text from CSV data."""
    raw_str = _extract_txt(file_bytes)
    lines = [l for l in raw_str.splitlines() if l.strip()]
    return raw_str, len(lines)


def _extract_pdf(file_bytes: bytes) -> Tuple[str, int]:
    """Extract text from PDF pages using PyMuPDF (fitz)."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        extracted_pages = []
        page_count = len(doc)
        for i in range(page_count):
            page = doc.load_page(i)
            page_text = page.get_text("text")
            if page_text:
                extracted_pages.append(f"--- Page {i+1} ---\n{page_text}")
        doc.close()
        return "\n\n".join(extracted_pages), page_count
    except Exception as e:
        # Fallback in case of encrypted or malformed PDF
        return f"[PDF Extraction Warning: {str(e)}]", 0


def _extract_docx(file_bytes: bytes) -> Tuple[str, int]:
    """Extract text from DOCX documents using python-docx."""
    try:
        import docx
        doc = docx.Document(io.BytesIO(file_bytes))
        chunks = []
        # Paragraphs
        for p in doc.paragraphs:
            if p.text and p.text.strip():
                chunks.append(p.text)
        # Tables
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_text:
                    chunks.append(row_text)
        return "\n".join(chunks), len(chunks)
    except Exception as e:
        return f"[DOCX Extraction Warning: {str(e)}]", 0


def _extract_xlsx(file_bytes: bytes) -> Tuple[str, int]:
    """Extract text from XLSX sheets using openpyxl / pandas."""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
        chunks = []
        total_rows = 0
        for sheet_name in wb.sheetnames:
            sheet = wb[sheet_name]
            chunks.append(f"--- Sheet: {sheet_name} ---")
            for row in sheet.iter_rows(values_only=True):
                non_empty = [str(val).strip() for val in row if val is not None and str(val).strip() != ""]
                if non_empty:
                    chunks.append(" , ".join(non_empty))
                    total_rows += 1
        return "\n".join(chunks), total_rows
    except Exception as e:
        # Fallback to pandas
        try:
            import pandas as pd
            excel_file = pd.ExcelFile(io.BytesIO(file_bytes))
            chunks = []
            total_rows = 0
            for sheet_name in excel_file.sheet_names:
                df = pd.read_excel(excel_file, sheet_name=sheet_name)
                chunks.append(f"--- Sheet: {sheet_name} ---")
                csv_text = df.to_csv(index=False)
                chunks.append(csv_text)
                total_rows += len(df)
            return "\n".join(chunks), total_rows
        except Exception as e2:
            return f"[XLSX Extraction Warning: {str(e2)}]", 0
