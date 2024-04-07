import sys, io
import pandas as pd

df = pd.read_json("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
# Some basic parsing to make simpler to work with
df = pd.json_normalize(df["objects"])
df["url"] = df["external_references"].dropna().apply(lambda row: row[0].get("url"))
df["external_id"] = df["external_references"].dropna().apply(lambda row: row[0].get("external_id"))
output = io.BytesIO()
df.to_parquet(output)
output.seek(0)
sys.stdout.buffer.write(output.read())

