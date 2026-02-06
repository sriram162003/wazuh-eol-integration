#!/usr/bin/env python3
"""
Wazuh EOL Checker Integration
STRICT MODE: JSON output ONLY
"""

import json
import requests
from datetime import datetime
from typing import Dict, Optional
import time
import sys
import csv


class EOLChecker:
    BASE_URL = "https://endoflife.date/api"

    def __init__(self):
        self.cache = {}

    def get_product_info(self, product: str) -> Optional[Dict]:
        if product in self.cache:
            return self.cache[product]

        try:
            url = f"{self.BASE_URL}/{product}.json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cache[product] = data
                return data
        except requests.exceptions.RequestException:
            pass

        return None

    def find_best_match(self, product: str, version: str) -> Optional[Dict]:
        cycles = self.get_product_info(product)
        if not isinstance(cycles, list):
            return None

        for cycle in cycles:
            if str(cycle.get("cycle")) == version:
                return cycle

        for cycle in cycles:
            c = str(cycle.get("cycle", ""))
            if version.startswith(c + ".") or c.startswith(version + "."):
                return cycle

        return None

    def get_eol_status(self, product: str, version: str) -> Dict:
        info = self.find_best_match(product, version)

        if not info:
            return {
                "eol_date": "Unknown",
                "is_eol": False,
                "support_status": "Unknown",
                "days_until_eol": None,
                "lts": False,
                "latest_version": "Unknown",
            }

        today = datetime.utcnow()
        eol_raw = info.get("eol")
        support_raw = info.get("support")

        is_eol = False
        days_until_eol = None
        eol_date = "Unknown"

        if isinstance(eol_raw, str):
            try:
                eol_dt = datetime.strptime(eol_raw, "%Y-%m-%d")
                eol_date = eol_raw
                if eol_dt < today:
                    is_eol = True
                    days_until_eol = 0
                else:
                    days_until_eol = (eol_dt - today).days
            except ValueError:
                pass
        elif eol_raw is True:
            is_eol = True
            days_until_eol = 0

        if support_raw is False:
            is_eol = True
            support_status = "End of Support"
            days_until_eol = 0
        elif is_eol:
            support_status = "End of Life"
        elif days_until_eol is not None and days_until_eol < 90:
            support_status = "EOL Soon (<90 days)"
        else:
            support_status = "Actively Supported"

        return {
            "eol_date": eol_date,
            "is_eol": is_eol,
            "support_status": support_status,
            "days_until_eol": days_until_eol,
            "lts": bool(info.get("lts", False)),
            "latest_version": info.get("latest", "Unknown"),
        }


def get_inventory():
    try:
        with open("/var/ossec/etc/software_inventory.csv") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []
def emit(event: Dict):
    print(json.dumps({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "eol_check": event
    }))
    sys.stdout.flush()


def main():
    checker = EOLChecker()
    inventory = get_inventory()

    if not inventory:
        emit({
            "status": "error",
            "message": "No software inventory found"
        })
        return

    eol_count = 0

    for item in inventory:
        product = item.get("product", "").lower().strip()
        version = item.get("version", "").strip()

        status = checker.get_eol_status(product, version)
        if status["is_eol"]:
            eol_count += 1

        emit({
            "product": product,
            "version": version,
            "system": item.get("system", ""),
            "criticality": item.get("criticality", ""),
            **status,
            "check_timestamp": datetime.utcnow().isoformat() + "Z"
        })

        time.sleep(0.5)

    emit({
        "status": "completed",
        "total_checked": len(inventory),
        "eol_count": eol_count,
        "check_timestamp": datetime.utcnow().isoformat() + "Z"
    })


if __name__ == "__main__":
    main()
