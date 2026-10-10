# Relay feed

`latest.json` and `archive/*.json` are written by `.github/workflows/ct-relay.yml`, which runs
`scripts/ct_snapshot.py` (the project's own Certificate Transparency tailer) on a schedule.
They contain **observations of public CT data**: hostnames from publicly logged certificates that
matched a protected brand keyword, with heuristic scores. They are not accusations. Entries older
than 14 days are pruned. See `DISCLAIMER.md` at the repository root.
