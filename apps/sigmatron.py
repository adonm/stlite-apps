import streamlit as st
import pandas as pd
import yaml, time
from pyodide.http import pyfetch
from pathlib import Path
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

st.set_page_config(
    page_title="Sigmatron",
    layout="wide"
)

st.title("Sigmatron")
st.markdown("[stlite-apps main index](../)")
st.markdown("## Utility to find and view sigma rules with conversions")

manual_entry = st.toggle('Enter yaml manually')
sigma_yaml = False

@st.cache_data
def load_rules(path = Path("sigma")):
    sigma_rules = []
    logsource_keys = ["product", "category", "service"]
    
    for rule in Path("sigma").rglob("*.yml"):
        yml = yaml.safe_load(rule.read_text())
        
        try:
            src = yml["logsource"]
        except KeyError:
            continue
        
        rule_meta = {
            "path": rule,
            "title": yml["title"],
            "tags": yml.get("tags", [])
        }
        
        for key in logsource_keys: # all filter keys must be lists
            if src.get(key):
                rule_meta[key] = [src[key]]
            else:
                rule_meta[key] = []
        
        sigma_rules.append(rule_meta)
    
    return sigma_rules

if not manual_entry:
    all_rules = load_rules()
    filters = {}
    with st.sidebar:
        st.markdown("## Filters")
        defaults = {
            "product": "windows",
            "category": "process_creation"
        }
        for name in ["tags", "product", "category", "service"]:
            options = sorted(set().union(*(r[name] for r in all_rules)))
            filters[name] = st.multiselect(f"{name.title()} ({len(options)} total)", options, default = defaults.get(name, []))

    def filter_rules(seq):
        for rule in seq:
            for name, option in filters.items():
                # if a multiselect set, and any of its items in the yaml rule, return
                if option and not set(option).intersection(set(rule[name])):
                    break
            else:
                yield rule
    
    rules = sorted(filter_rules(all_rules), key=lambda r: r["title"])
    
    rule = st.selectbox(f"Sigma Rule ({len(rules)} total) to display", rules, format_func=lambda r: r["title"])
    sigma_yaml = rule["path"].read_text()
else:
    sigma_yaml = st.text_area("YAML to convert")

with st.sidebar:
    # Create backend, which automatically adds the pipeline
    backends = [(Microsoft365DefenderBackend(), "kusto")]
    st.markdown("## Convert and display")
    backend, lang = st.selectbox(f"Sigma Backend ({len(backends)} total)", backends, format_func=lambda b: f"{b[0].name} ({b[1]})")

# Convert the rule
if sigma_yaml:
    sigma_rule = SigmaRule.from_yaml(sigma_yaml)
    try:
        converted = backend.convert_rule(sigma_rule)[0]
    except Exception as e:
        converted = str(e)
else:
    sigma_yaml = converted = "Nothing to convert..."

# Display the conversion
st.markdown(f"""
## {backend.name.replace("backend", "").strip()} Query ({lang})

```{lang}
{converted}
```

## Sigma YAML

```yaml
{sigma_yaml}
```
""")