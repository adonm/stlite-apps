# stlite-apps

[Streamlit Lite](https://github.com/whitphx/stlite) apps mainly focused on mitre/sigma and detection rules.

## Design guideline

Make existing detections / stix info / osint easier to use with fast client side web interfaces. Caching all source content in app repo with actions and using github cdn avoids CORS issues etc.

- Download relevant data sources nightly and commit back to repo if changed with [update.py](update.py).
- Define interfaces in apps subdir
- Include sensible defaults and deep linking (to share interesting views directly).

First app was an stlite based sigma browser that includes defender conversions, [sigmatron](https://adonm.github.io/stlite-apps/apps/sigmatron.html), next will likely be a Mitre stix browser.

