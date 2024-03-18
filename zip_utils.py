#!/usr/bin/env python
from pathlib import Path
import zipfile

# Zip up internal utils
utils = Path("utils").glob("*.py")
with zipfile.ZipFile('utils.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zip_file:
    for path in utils:
        zip_file.write(path)