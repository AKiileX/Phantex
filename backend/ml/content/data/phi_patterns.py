# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — PHI Patterns (JB4).

Regex-based detection of Protected Health Information:
- Medical record numbers (MRN)
- ICD-10 diagnosis codes
- Drug / prescription names (common controlled & branded drugs)
- Patient identifier patterns
- Lab result values near clinical context

All regex patterns are pre-compiled.  Matched values are returned
**redacted** — the raw PHI is never stored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class PHIMatch:
    """A PHI detection with the value pre-redacted."""

    data_type: str  # "MRN", "ICD10", "DRUG", "LAB_RESULT", "PATIENT_ID"
    redacted_value: str
    offset: int
    length: int
    confidence: float
    context: str = ""

# ── Medical Record Number ────────────────────────────────────────────────────

_MRN_RE = re.compile(
    r"(?:MRN|medical\s+record\s*(?:number|#|no)?)[\s:=#]*(\d{6,12})",
    re.I,
)

# ── ICD-10 Codes ─────────────────────────────────────────────────────────────

# ICD-10 format: letter + 2 digits + optional .0-9 suffix
_ICD10_RE = re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b")

# Context needed to distinguish from random alphanumeric codes
_ICD10_CONTEXT = re.compile(
    r"(?:ICD[-\s]*10|diagnosis|diagnos[ei]s|diagnostic\s+code|condition\s+code|"
    r"primary\s+diagnosis|secondary\s+diagnosis|billing\s+code|procedure\s+code)",
    re.I,
)

# ── Drug / Medication Names ──────────────────────────────────────────────────

# Top prescribed medications (generic + brand names, non-exhaustive)
_DRUG_NAMES = [
    # Controlled substances
    "oxycodone",
    "hydrocodone",
    "fentanyl",
    "morphine",
    "codeine",
    "methadone",
    "tramadol",
    "oxycontin",
    "vicodin",
    "percocet",
    "adderall",
    "ritalin",
    "concerta",
    "methylphenidate",
    "alprazolam",
    "xanax",
    "diazepam",
    "valium",
    "clonazepam",
    "lorazepam",
    "ativan",
    "zolpidem",
    "ambien",
    # Common medications
    "lisinopril",
    "atorvastatin",
    "lipitor",
    "metformin",
    "amlodipine",
    "omeprazole",
    "losartan",
    "simvastatin",
    "metoprolol",
    "levothyroxine",
    "synthroid",
    "amoxicillin",
    "azithromycin",
    "ciprofloxacin",
    "prednisone",
    "gabapentin",
    "sertraline",
    "zoloft",
    "fluoxetine",
    "prozac",
    "escitalopram",
    "lexapro",
    "duloxetine",
    "cymbalta",
    "bupropion",
    "wellbutrin",
    "insulin",
    "warfarin",
    "coumadin",
    "heparin",
    "enoxaparin",
]

_DRUG_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(d) for d in _DRUG_NAMES) + r")\b",
    re.I,
)

_DRUG_CONTEXT = re.compile(
    r"(?:prescri(?:bed?|ption)|medication|dosage|dose|mg|tablet|capsule|"
    r"twice\s+daily|once\s+daily|as\s+needed|PRN|administered|patient\s+(?:takes?|on)|"
    r"drug|treatment|therapy|refill)",
    re.I,
)

# ── Lab Results ──────────────────────────────────────────────────────────────

_LAB_RESULT_RE = re.compile(
    r"(?:A1[Cc]|[Hh]b[Aa]1[Cc]|glucose|cholesterol|triglycerides|creatinine|"
    r"GFR|ALT|AST|WBC|RBC|platelets?|hemoglobin|hematocrit|TSH|PSA|BUN|"
    r"bilirubin|albumin|sodium|potassium|chloride|calcium|magnesium)"
    r"[\s:=]*(\d+\.?\d*)\s*(?:mg/[dD][lL]|mmol/L|U/L|g/dL|%|mEq/L|ng/mL|pg/mL)?",
    re.I,
)

# ── Patient Identifiers ─────────────────────────────────────────────────────

_PATIENT_ID_RE = re.compile(
    r"(?:patient\s*(?:ID|#|number|name)|pt\s*#|pt\s+name)[\s:=#]*"
    r"([A-Za-z0-9][A-Za-z0-9 .'-]{1,40})",
    re.I,
)

# ── Public API ───────────────────────────────────────────────────────────────

def scan_for_phi(text: str) -> list[PHIMatch]:
    """Scan *text* for PHI and return redacted matches.

    Returns a list sorted by offset.
    """
    hits: list[PHIMatch] = []

    # MRN
    for m in _MRN_RE.finditer(text):
        mrn_val = m.group(1)
        hits.append(
            PHIMatch(
                data_type="MRN",
                redacted_value=f"MRN:***{mrn_val[-3:]}",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.90,
                context="medical record number pattern",
            )
        )

    # ICD-10 (only with context)
    has_icd_context = bool(_ICD10_CONTEXT.search(text))
    if has_icd_context:
        for m in _ICD10_RE.finditer(text):
            code = m.group(0)
            # Validate: real ICD-10 categories are A00-Z99
            category_letter = code[0]
            if category_letter.isalpha() and category_letter.upper() in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                window = text[start:end]
                if _ICD10_CONTEXT.search(window):
                    hits.append(
                        PHIMatch(
                            data_type="ICD10",
                            redacted_value=f"ICD10:{code}",  # ICD-10 codes are classification codes, not PII themselves
                            offset=m.start(),
                            length=len(code),
                            confidence=0.85,
                            context="ICD-10 code near diagnosis keyword",
                        )
                    )

    # Drug names (only with medication context)
    has_drug_context = bool(_DRUG_CONTEXT.search(text))
    if has_drug_context:
        for m in _DRUG_RE.finditer(text):
            drug = m.group(0)
            start = max(0, m.start() - 80)
            end = min(len(text), m.end() + 80)
            window = text[start:end]
            if _DRUG_CONTEXT.search(window):
                hits.append(
                    PHIMatch(
                        data_type="DRUG",
                        redacted_value=f"[medication:{drug.lower()[:3]}***]",
                        offset=m.start(),
                        length=len(drug),
                        confidence=0.80,
                        context="medication name near prescription context",
                    )
                )

    # Lab results
    for m in _LAB_RESULT_RE.finditer(text):
        test_name = (
            m.group(0).split(":")[0].split("=")[0].strip()
            if ":" in m.group(0) or "=" in m.group(0)
            else m.group(0).split()[0]
        )
        hits.append(
            PHIMatch(
                data_type="LAB_RESULT",
                redacted_value=f"{test_name}: ***",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.75,
                context="lab result value detected",
            )
        )

    # Patient identifiers
    for m in _PATIENT_ID_RE.finditer(text):
        hits.append(
            PHIMatch(
                data_type="PATIENT_ID",
                redacted_value="patient: ***",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.85,
                context="patient identifier near keyword",
            )
        )

    hits.sort(key=lambda h: h.offset)
    return hits
