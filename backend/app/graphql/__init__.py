# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Phantex GraphQL API — Block AE

Provides the full GraphQL layer on top of existing REST services:
- ``schema``  — root Strawberry schema (Query + Mutation + Subscription)
- ``get_graphql_context`` — per-request auth + DB context factory
"""

from app.graphql.context import get_graphql_context
from app.graphql.schema import schema

__all__ = ["schema", "get_graphql_context"]
