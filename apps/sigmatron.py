import streamlit as st
import pandas as pd
import yaml, micropip
from pathlib import Path

from sigma.rule import SigmaRule

from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

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
st.markdown("**[stlite-apps main index](../)**")

view_tab, build_tab, extract_tab = st.tabs(["Viewer", "Builder", "Extractor"])

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

        st.session_state.update({ # set default inputs
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
    if st.toggle("Enter yaml manually", key="manual"):
        sigma_yaml = st.text_area("YAML to convert", key="sigma_yaml")
    else:
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
        active_filters = {attr: st.session_state[attr] for attr in filters if st.session_state[attr]}
        filtered_rules = [rule for rule, el in rules.items() if all(set(opt).intersection(set(el[attr])) for attr, opt in active_filters.items())]
    
        # Display filtered rules
        if filtered_rules:
            rule_title = st.selectbox(f"Sigma Rule ({len(filtered_rules)}/{len(rules)} total) to display", sorted(filtered_rules, reverse=True), key="rule")
            selected_rule = rules[rule_title]
            sigma_yaml = selected_rule["path"].read_text()
        else:
            st.write("No rules for the selected filters:")
            st.write(fltrs)
    
    # Sidebar for selecting backend and displaying conversion
    with st.sidebar:
        st.markdown("## Convert and display")
        backend_name = st.selectbox(f"Sigma Backend ({len(backends)} total)", backends.keys(), key="backend")
    
    # Convert and display the selected rule
    if "sigma_yaml" in locals() and sigma_yaml is not None:
        try:
            backend, lang = backends[backend_name]
            converted = backend.convert_rule(SigmaRule.from_yaml(sigma_yaml))[0]
        except Exception as e:
            converted = str(e)
    
        st.markdown(f"## {backend_name} Query\n\n```{lang}\n{converted}\n```")
        st.markdown(f"## Sigma YAML\n\n```yaml\n{sigma_yaml}\n```")

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