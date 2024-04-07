#!/usr/bin/env python
from subprocess import run

downloads = {
    "data/sigma_all_rules.zip": "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip",
}

# Download external deps
for fname, url in downloads.items():
    run(["curl", "-L", "-o", fname, url], check=True)

run(["pip", "install", "-r", "requirements.txt"])
run(["npm", "ci"])
run(["npm", "run", "build"])
