#!/usr/bin/env python
from subprocess import run

downloads = {
    "sigma_all_rules.zip": "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip",
    "enterprise-attack.json": "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
}

for fname, url in downloads.items():
    run(["curl", "-L", "-o", fname, url], check=True)
