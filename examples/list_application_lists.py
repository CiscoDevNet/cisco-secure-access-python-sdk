# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Application Lists Management Example for Cisco Secure Access API.

This module provides an example of listing and exporting Application Lists
using the Cisco Secure Access Python SDK. It demonstrates read operations:
- List all application lists (summaries)
- Enrich each summary with full details (applicationIds, applicationCategoryIds)
- Optionally resolve those IDs to human-readable names
- Export the result as JSON or CSV

Usage:
    # Export all application lists with raw IDs to JSON
    python list_application_lists.py

    # Export to CSV
    python list_application_lists.py --format csv

    # Export with applicationIds / applicationCategoryIds resolved to names
    python list_application_lists.py --human-readable

    # Choose output filename (extension is appended automatically)
    python list_application_lists.py --file my_app_lists --format csv
"""

import argparse
import csv
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

# Load CLIENT_ID / CLIENT_SECRET from a local .env if present. The shared
# access_token helper only reads `os.environ`, so without this the example
# fails for users who keep credentials in .env instead of exporting them.
load_dotenv()

from access_token import get_valid_access_token
from secure_access.api.application_lists_api import ApplicationListsApi
from secure_access.api.application_categories_api import ApplicationCategoriesApi
from secure_access.api_client import ApiClient
from secure_access.configuration import Configuration
from secure_access.exceptions import ApiException

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ApplicationListManager:
    def __init__(self) -> None:
        self.access_token = get_valid_access_token()
        self.configuration = Configuration(access_token=self.access_token)
        self.api_client = ApiClient(configuration=self.configuration)
        # The applications-by-name lookup uses /reports/v2/applications, which
        # is not covered by the generated SDK. Fall back to a direct REST call
        # built off the same Configuration so host/auth stay in one place.
        self._reports_url = f"{self.configuration.host}/reports/v2"
        self._reports_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def fetch_application_lists(self) -> List[Dict[str, Any]]:
        """Fetch all application list summaries via ApplicationListsApi."""
        logger.info("Fetching application list summaries...")
        api = ApplicationListsApi(api_client=self.api_client)
        try:
            # Use the without_preload_content variant to get raw JSON; the
            # SDK's pydantic model may reject newer/optional fields and we
            # want to round-trip every field the API returns into the export.
            response = api.get_application_lists_without_preload_content()
            payload = json.loads(response.data)
            return payload.get("results", []) if isinstance(payload, dict) else []
        except (ApiException, ValueError) as e:
            logger.error(f"Error fetching application lists: {e}")
            return []

    def fetch_application_name_maps(self) -> Tuple[Dict[int, str], Dict[int, str]]:
        """Fetch {id: name} maps for applications and application categories.

        - Applications come from /reports/v2/applications (ApplicationsWithCategories).
          This endpoint is not currently exposed by the generated SDK, so we
          call it directly with `requests` using the same access token.
        - Application *category* IDs used inside applicationLists belong to the
          policy taxonomy and must come from /policies/v2/applicationCategories,
          NOT from the `categories` field of /reports/v2/applications (that one
          is the reporting taxonomy and uses different IDs).
        """
        logger.info("Fetching application + category name maps...")
        app_map: Dict[int, str] = {}
        cat_map: Dict[int, str] = {}

        # Applications — /reports/v2/applications (no SDK coverage today)
        try:
            r = requests.get(
                f"{self._reports_url}/applications",
                headers=self._reports_headers,
                timeout=60,
            )
            r.raise_for_status()
            data = r.json().get("data", {}) or {}
            app_map = {a["id"]: a.get("label") or a.get("name") for a in data.get("applications", [])}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching applications: {e}")

        # Application categories — /policies/v2/applicationCategories via SDK.
        # The endpoint returns a JSON object keyed by category id, e.g.
        # {"48": {"id": 48, "name": "Games", ...}, ...}. (Not a list, not
        # {"results": [...]}.) Pagination params are accepted but the full set
        # fits in one response in practice — we still walk pages defensively
        # in case that changes.
        api = ApplicationCategoriesApi(api_client=self.api_client)
        try:
            page = 1
            while True:
                response = api.get_application_categoriespoliciesapplicationcategories_without_preload_content(
                    page=page, limit=100,
                )
                payload = json.loads(response.data)
                if isinstance(payload, dict) and "results" in payload:
                    cats: List[Dict[str, Any]] = payload.get("results") or []
                elif isinstance(payload, dict):
                    cats = list(payload.values())
                elif isinstance(payload, list):
                    cats = payload
                else:
                    cats = []
                if not cats:
                    break
                for c in cats:
                    if isinstance(c, dict) and "id" in c:
                        cat_map[c["id"]] = c.get("name") or c.get("label")
                if len(cats) < 100:
                    break
                page += 1
        except (ApiException, ValueError) as e:
            logger.error(f"Error fetching application categories: {e}")

        logger.info(f"Loaded {len(app_map)} applications, {len(cat_map)} categories.")
        return app_map, cat_map

    def humanize(
        self,
        enriched_data: List[Dict[str, Any]],
        app_map: Dict[int, str],
        cat_map: Dict[int, str],
    ) -> List[Dict[str, Any]]:
        """Replace applicationIds/applicationCategoryIds with name lists.

        Logs an INFO line for every ID that cannot be resolved, including the
        owning application-list name so the operator can chase it down.
        """
        out: List[Dict[str, Any]] = []
        unresolved_apps = unresolved_cats = 0
        for entry in enriched_data:
            list_name = entry.get("applicationListName", f"<id {entry.get('applicationListId')}>")
            new_entry = {k: v for k, v in entry.items()
                         if k not in ("applicationIds", "applicationCategoryIds")}

            app_names: List[str] = []
            for aid in entry.get("applicationIds", []):
                name = app_map.get(aid)
                if name is None:
                    unresolved_apps += 1
                    logger.info(
                        "Unresolved application ID %s in list '%s' — not found in /reports/v2/applications",
                        aid, list_name,
                    )
                    app_names.append(f"Unknown ID: {aid}")
                else:
                    app_names.append(name)
            new_entry["applicationNames"] = app_names

            cat_names: List[str] = []
            for cid in entry.get("applicationCategoryIds", []):
                name = cat_map.get(cid)
                if name is None:
                    unresolved_cats += 1
                    logger.info(
                        "Unresolved application-category ID %s in list '%s' — not found in /policies/v2/applicationCategories",
                        cid, list_name,
                    )
                    cat_names.append(f"Unknown ID: {cid}")
                else:
                    cat_names.append(name)
            new_entry["applicationCategoryNames"] = cat_names

            out.append(new_entry)

        if unresolved_apps or unresolved_cats:
            logger.info(
                "Unresolved totals: %d application ID(s), %d category ID(s)",
                unresolved_apps, unresolved_cats,
            )
        return out

    def fetch_list_details(self, list_id: int) -> Dict[str, Any]:
        """Fetch detailed items (applicationIds/categories) for a specific list."""
        api = ApplicationListsApi(api_client=self.api_client)
        try:
            response = api.get_application_list_without_preload_content(application_list_id=list_id)
            payload = json.loads(response.data)
            return payload if isinstance(payload, dict) else {}
        except (ApiException, ValueError) as e:
            logger.error(f"Error fetching details for list {list_id}: {e}")
            return {}

    def save_as_json(self, data: List[Dict[str, Any]], filename: str) -> None:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Successfully saved to JSON: {filename}")

    def save_as_csv(self, data: List[Dict[str, Any]], filename: str) -> None:
        """Saves enriched data to CSV. Note: list fields are joined as strings."""
        if not data:
            return

        # Flatten the data for CSV — handle both ID and human-readable schemas
        flat_data: List[Dict[str, Any]] = []
        for item in data:
            flat_item = item.copy()
            for key in ('applicationIds', 'applicationCategoryIds',
                        'applicationNames', 'applicationCategoryNames'):
                if key in flat_item:
                    flat_item[key] = ",".join(map(str, flat_item.get(key) or []))
            flat_data.append(flat_item)

        keys = flat_data[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(flat_data)
        logger.info(f"Successfully saved to CSV: {filename}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Utility to list and export Cisco Secure Access Application Lists with details",
    )
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help="Output format")
    parser.add_argument('--file', default='app_lists_full_backup', help="Output filename (without extension)")
    parser.add_argument('--human-readable', action='store_true',
                        help="Replace applicationIds / applicationCategoryIds with their resolved names")

    args = parser.parse_args()

    manager = ApplicationListManager()

    # 1. Get all summaries
    summaries = manager.fetch_application_lists()
    if not summaries:
        logger.warning("No application lists found.")
        return

    # 2. Enrich with details
    enriched_data: List[Dict[str, Any]] = []
    logger.info(f"Enriching {len(summaries)} lists with details...")
    for summary in summaries:
        list_id = summary.get("applicationListId")
        details = manager.fetch_list_details(list_id)
        # Merge summary and detail
        enriched_data.append({**summary, **details})

    # 3. Optionally resolve IDs → names
    if args.human_readable:
        app_map, cat_map = manager.fetch_application_name_maps()
        if not app_map and not cat_map:
            logger.error("Could not fetch name maps; aborting human-readable conversion.")
            return
        enriched_data = manager.humanize(enriched_data, app_map, cat_map)

    # 4. Export
    filename = f"{args.file}.{args.format}"
    if args.format == 'json':
        manager.save_as_json(enriched_data, filename)
    else:
        manager.save_as_csv(enriched_data, filename)


if __name__ == "__main__":
    main()
