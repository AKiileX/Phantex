#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Seed core rules into PostgreSQL."""
import asyncio
from rules.loader import seed_core_rules

async def main():
    result = await seed_core_rules()
    print(f"Inserted: {result['inserted']}")
    print(f"Updated:  {result['updated']}")
    if result['errors']:
        print(f"Errors:   {result['errors']}")
    print("Done.")

asyncio.run(main())
