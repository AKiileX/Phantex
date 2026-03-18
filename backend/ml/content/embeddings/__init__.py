# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8a — Embedding-based Content Analysis.

Sentence-transformer embeddings + cosine-similarity search against
a corpus of known attack vectors.  Catches novel phrasings,
multilingual variants, and obfuscated injections that regex misses.
"""
