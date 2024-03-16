import streamlit as st
from pyodide.http import pyfetch
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

st.title("Sigmatron")
st.markdown("## Utility to browse and display sigma rules")

base_url = st.text_input('Base url', 'https://raw.githubusercontent.com/SigmaHQ/sigma/master')
sigma_path = st.text_input('Sigma YAML path', '/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml')

async def load_yaml(url):
    res = await pyfetch(url)
    data = await res.text()
    return data

sigma_yaml = await load_yaml(base_url + sigma_path)

# Define an example rule as a YAML str
sigma_rule = SigmaRule.from_yaml(sigma_yaml)
# Create backend, which automatically adds the pipeline
m365def_backend = Microsoft365DefenderBackend()

# Convert the rule
st.markdown(f"""
## KQL Query

```kusto
{m365def_backend.convert_rule(sigma_rule)[0]}
```

## Original sigma rule

```yaml
{sigma_yaml}
```
""")