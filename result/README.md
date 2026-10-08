# Curated result bundle

This directory is the GitHub-facing record of earlier CoSA demo runs. It is
assembled from the local `runs/` workspace by:

```sh
python3 scripts/collect_results.py
```

`runs/<label>/` contains selected machine-readable evidence: prompts, fixture
metadata, hook events, inspection summaries, and artifacts where present.
Terminal UI logs and transient `.claude` state are intentionally excluded.
`index.json` also records a compact summary for every local run that existed at
collection time, including incomplete and timed-out runs.

The event evidence is untrusted experiment data. Read the event ordering and
the independent oracle fields before making a causal claim. A model's textual
claim that validation passed is not evidence of a committed task state.
