import streamlit as st
import streamlit_permalink as stp
from streamlit_javascript import st_javascript
import yaml, micropip
from pathlib import Path
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

# App configuration
st.set_page_config(page_title="Sigmatron", layout="wide")
st.title("Sigmatron :lab_coat: (◑‿◐) :female-detective:")
# Link to the main index of stlite-apps
st.markdown("**[stlite-apps main index](../)**")

view_tab, build_tab, extract_tab = st.tabs(["Viewer", "Builder", "Extractor"])

with view_tab:
    # Load sigma rules from the "sigma" directory
    @st.cache_data
    def load_rules():
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
    
        return rules
    
    
    # Option to enter YAML manually
    if stp.toggle("Enter yaml manually", url_key="manual"):
        sigma_yaml = st.text_area("YAML to convert", url_key="sigma_yaml")
    else:
        # Load rules and apply filters
        rules = load_rules()
        fltrs, defaults = {}, {"product": ["windows"], "category": ["process_creation"]}
    
        # Sidebar for filters
        with st.sidebar:
            st.markdown("## Filters")
            for attr in ["tags", "product", "category", "service"]:
                options = sorted(set().union(*(el[attr] for el in rules.values())))
                fltrs[attr] = stp.multiselect(f"{attr.title()} ({len(options)} total)", options, default=defaults.get(attr, []), url_key=attr)

            # Reset filters button
            if st.button("Reset filters"):
                st.query_params.clear()
    
        # Filter rules based on selected filters
        filtered_rules = [rule for rule, el in rules.items() if all(set(opt).intersection(set(el[attr])) for attr, opt in fltrs.items() if opt)]
    
        # Display filtered rules
        if filtered_rules:
            rule_title = stp.selectbox(f"Sigma Rule ({len(filtered_rules)}/{len(rules)} total) to display", sorted(filtered_rules, reverse=True), url_key="rule")
            selected_rule = rules[rule_title]
            sigma_yaml = selected_rule["path"].read_text()
        else:
            st.write("No rules for the selected filters:")
            st.write(fltrs)
    
    # Sidebar for selecting backend and displaying conversion
    with st.sidebar:
        backends = {"M365 Defender (KQL)": (Microsoft365DefenderBackend(), "kusto")}
        st.markdown("## Convert and display")
        backend_name = stp.selectbox(f"Sigma Backend ({len(backends)} total)", backends.keys(), url_key="backend")
        backend, lang = backends[backend_name]
    
    # Convert and display the selected rule
    if "sigma_yaml" in locals() and sigma_yaml is not None:
        try:
            converted = backend.convert_rule(SigmaRule.from_yaml(sigma_yaml))[0]
        except Exception as e:
            converted = str(e)
    
        st.markdown(f"## {backend_name} Query\n\n```{lang}\n{converted}\n```")
        st.markdown(f"## Sigma YAML\n\n```yaml\n{sigma_yaml}\n```")

with build_tab:
    st.write("todo")

with extract_tab:
    from utils.iocextract import IoCExtract
    ioc_text = stp.text_area("Text to extract IOCs from", url_key="ioc_text")
    ioc_extractor = IoCExtract()

    # any IoCs in the string?
    iocs_found = ioc_extractor.extract(ioc_text)
    
    if iocs_found:
        st.write(iocs_found)