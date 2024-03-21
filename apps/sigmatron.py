import streamlit as st
import pandas as pd
import yaml, micropip
from pathlib import Path

from sigma.rule import SigmaRule

from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

from sigma.backends.opensearch import OpensearchLuceneBackend

from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.sysmon import sysmon_pipeline

from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

from sigma.backends.loki import LogQLBackend

from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.pipelines.carbonblack import CarbonBlack_pipeline
from sigma.backends.cortexxdr import CortexXDRBackend

from utils.iocextract import IoCExtract
from utils.statemgmt import load_session, save_session

# App configuration
st.set_page_config(page_title="Sigmatron", layout="wide")
st.title("Sigmatron :lab_coat: (◑‿◐) :female-detective:")
# Link to the main index of stlite-apps
st.markdown("**[stlite-apps main index](../)**, **[Main Sigma Rule Repository](https://github.com/SigmaHQ/sigma)**, **[Sigma Backends](https://sigmahq.io/docs/digging-deeper/backends.html)**")
session = st.session_state

view_tab, build_tab, extract_tab, about_tab = st.tabs(["Viewer", "Builder", "Extractor", "About"])

with about_tab:
    st.markdown("Source on github: [adonm/stlite-apps](https://github.com/adonm/stlite-apps)")

with view_tab:
    # Load sigma rules from the "sigma" directory
    @st.cache_resource
    def rule_cache():
        rules = {}        
        for rule_file in Path("sigma").rglob("*.yml"):
            rule = yaml.safe_load(rule_file.read_text())
            try:
                source = rule["logsource"]
            except KeyError:
                # Skip rules without a "logsource" key
                continue
    
            rule_meta = {
                "path": rule_file,
                "title": rule["title"],
                "tags": rule.get("tags", []),
                "description": rule["description"],
                "product": [source.get("product")] if "product" in source else [],
                "category": [source.get("category")] if "category" in source else [],
                "service": [source.get("service")] if "service" in source else [],
            }
            title = f"{rule['date']} - {rule['title']}"
            if "modified" in rule:
                title = f"{rule['modified']} - {rule['title']} (created {rule['date']})"
    
            rules[title] = rule_meta

        session.update({ # set default inputs
            "product": ["windows"],
            "category": ["process_creation"],
            "ioc_text": "1.1.1.1\n8.8.8.8\nhttps://sneaky.malicious.domain"
        })
        load_session() # load the session once when loading rules
        return rules

    @st.cache_resource
    def backend_cache():
        # Convenient sigma backends, sourced from popular items at https://github.com/search?q=pysigma-backend&type=repositories&s=stars&o=desc
        return {
            "M365 Defender (KQL)": (Microsoft365DefenderBackend(), "kusto"),
            "Opensearch winlogbeat (Lucene)": (OpensearchLuceneBackend(ecs_windows()), "lucene"),
            "Elastic winlogbeat (Lucene)": (LuceneBackend(ecs_windows()), "lucene"),
            "Elastic sysmon (Lucene)": (LuceneBackend(sysmon_pipeline()), "lucene"),
            "Splunk": (SplunkBackend(splunk_windows_pipeline()), "splunk"),
            "Grafana Loki (LogQL)": (LogQLBackend(), "logql"),
            "Carbon Black (Lucene)": (CarbonBlackBackend(CarbonBlack_pipeline()), "lucene"),
            "Cortex XDR (XQL)": (CortexXDRBackend(), "xql")
        }

    # Load rules and backends
    rules, backends = rule_cache(), backend_cache()

    # Option to enter YAML manually
    st.toggle("Enter yaml manually", key="manual")

    # Sidebar for filters
    with st.sidebar:
        st.markdown("## Filters")
        filters = ["tags", "product", "category", "service"]
        for attr in filters:
            options = sorted(set().union(*(el[attr] for el in rules.values())))
            st.multiselect(f"{attr.title()} ({len(options)} total)", options, key=attr)

        # Reset filters button
        if st.button("Save session to url"):
            save_session()
        
    # Filter rules based on selected filters
    active_filters = {attr: session[attr] for attr in filters if session[attr]}
    filtered_rules = sorted([rule for rule, el in rules.items() if all(set(opt).intersection(set(el[attr])) for attr, opt in active_filters.items())], reverse=True)

    # Display filtered rules
    if not session.get("manual"):
        if filtered_rules:
            index = 0
            if session.get("rule") in filtered_rules:
                index = filtered_rules.index(session.rule)
            session.rule = st.selectbox(f"Sigma Rule ({len(filtered_rules)}/{len(rules)} total) to display", filtered_rules, index=index)
            # Load text of selected rule if not manually entered
            selected_rule = rules.get(session.rule)
            if selected_rule:
                session.sigmayml = session.selected_rule_text = selected_rule["path"].read_text()
        else:
            st.write("No rules for the selected filters:")
            st.write(fltrs)

    if session.manual:
        session.sigmayml = st.text_area("YAML to convert", value=session.get("selected_rule_text"))


    # Sidebar for selecting backend and displaying conversion
    with st.sidebar:
        st.markdown("## Convert and display")
        backend_name = st.selectbox(f"Sigma Backend ({len(backends)} total)", backends.keys(), key="backend")
    
    # Convert and display the selected rule
    if session.get("sigmayml"):
        try:
            backend, lang = backends[backend_name]
            converted = backend.convert_rule(SigmaRule.from_yaml(session.sigmayml))[0]
        except Exception as e:
            converted = str(e)
    
        st.markdown(f"## {backend_name} Query\n\n```{lang}\n{converted}\n```")
        if not session.get("manual"):
            st.markdown(f"## Sigma YAML\n\n```yaml\n{session.sigmayml}\n```")

with build_tab:
    st.write("todo")

with extract_tab:
    st.markdown("## Indicator Of Compromise (IOC) extraction utility")
    st.markdown("This is based on the [msticpy.transform.IoCExtract](https://msticpy.readthedocs.io/en/latest/data_analysis/IoCExtract.html) utility.")
    
    ioc_text = st.text_area("Text to extract IOCs from", key="ioc_text")
    ioc_extractor = IoCExtract()

    # any IoCs in the string?
    iocs_found = ioc_extractor.extract(ioc_text)
    
    if iocs_found:
        # Convert to a list of dictionaries
        rows = []
        for ioc, values in iocs_found.items():
            for value in values:
                rows.append({'ioc': ioc, 'value': value})
        
        # Display a DataFrame from the list of dictionaries
        st.dataframe(pd.DataFrame(rows))