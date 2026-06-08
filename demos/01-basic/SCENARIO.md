# Demo 01 - Basic engagement report

A realistic external web-app pentest engagement for a fictional client,
`Acme Retail Ltd`. The findings file (`engagement.yaml`) covers a typical
mix of severities you'd see in a CREST-style report: an SQL injection
(critical), missing MFA (high), verbose error pages (medium), and a
missing security header (low).

## Run it

```sh
# Validate the YAML and see severity stats as a table
python -m pwnreview generate demos/01-basic/engagement.yaml

# Machine-readable report payload
python -m pwnreview generate demos/01-basic/engagement.yaml --format json

# Render a self-contained HTML report to disk
python -m pwnreview generate demos/01-basic/engagement.yaml --render html -o report.html

# Render Markdown to stdout
python -m pwnreview generate demos/01-basic/engagement.yaml --render markdown

# Validate only (CI gate; non-zero exit on malformed input)
python -m pwnreview validate demos/01-basic/engagement.yaml --format json
```

## What to expect

- Findings are sorted highest-risk first (critical -> info), ties broken by
  CVSS weight then id.
- The executive summary reports an aggregate risk score and overall posture
  (the highest severity present).
- Invalid severities, missing titles, duplicate ids, or out-of-range CVSS
  values cause a non-zero exit with a clear error.
