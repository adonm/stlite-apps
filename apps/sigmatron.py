import streamlit as st
from pyodide.http import pyfetch
from pathlib import Path
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

st.title("Sigmatron")
st.markdown("## Utility to browse and display sigma rules")
col1, col2 = st.columns(2)

# Create backend, which automatically adds the pipeline
backends = [Microsoft365DefenderBackend()]

# display short paths
def obj_name(obj):
    return obj.name

# Basic file browser
products = list(Path("sigma").glob("*/*"))
product = col1.selectbox("Product", products, index = products.index(Path("sigma/rules/windows")), format_func=lambda p: p.relative_to("sigma"))
categories = list(product.glob("*"))
category = col2.selectbox("Category", categories, index = categories.index(product / "process_creation"), format_func=obj_name)

if category.is_dir():
    rules = category.rglob("*.yml")
else:
    rules = [category]

rule = st.selectbox("Sigma Rule", rules, format_func=obj_name)

sigma_yaml = rule.read_text()

# Define an example rule as a YAML str
sigma_rule = SigmaRule.from_yaml(sigma_yaml)

backend = col1.selectbox("Sigma Backend", backends, format_func=obj_name)

# Convert the rule
try:
    defender_kql = backend.convert_rule(sigma_rule)[0]
except Exception as e:
    defender_kql = str(e)

# Display the conversion
st.markdown(f"""
## KQL Query

```kusto
{defender_kql}
```

## Original sigma rule

```yaml
{sigma_yaml}
```
""")