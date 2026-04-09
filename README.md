# WebShame

Static Hall of Shame interface for XeroDay findings. The site is plain HTML, CSS, and JavaScript so it can be published directly with GitHub Pages from the repository root.

## GitHub Pages

- No build step is required.
- All asset paths are relative, so it works under `https://<user>.github.io/<repo>/`.
- The page loads `data/hall-of-shame.json`.
- Because `x3r0day.github.io` is already your user site, this repo should be published as a project page, for example `https://x3r0day.github.io/WebShame/`.
- The scheduled workflow in `.github/workflows/refresh-hall-of-shame.yml` deploys this repo's Pages site and does not overwrite your existing root user page.
- In repository settings, set Pages to use `GitHub Actions` as the source.

## Important

Do not publish raw `leaked_keys.json` to GitHub Pages. That file contains the actual secrets. The web interface only masks values at render time, which is not enough if the raw JSON is public.

## Integration With XeroDay-APISniffer

Use the export script to generate a public-safe dataset:

```bash
python3 scripts/export_hall_of_shame.py \
  --input XeroDay-APISniffer/leaked_keys.json \
  --output data/hall-of-shame.json
```

That script:

- keeps repo, provider, file, and count metadata
- masks secret values into previews
- classifies severity for the UI
- trims the number of findings per repo for a cleaner public board
- writes `data/scan-history.json`, which is safe to commit and is used to deduplicate later scans
- automatically chunks scan history into `data/scan-history.part*.json` files when it would exceed 100MB

After that, commit the updated `data/hall-of-shame.json` and publish the repo with GitHub Pages.

## Files

- `index.html`: single-page interface
- `assets/styles.css`: layout and visual design
- `assets/app.js`: data loading, filtering, and rendering
- `data/hall-of-shame.json`: sample sanitized dataset
- `data/scan-history.json`: safe repo history manifest used by the scheduled scanner workflow and leaderboard
- `data/scan-history.part*.json`: optional chunk files created automatically when history grows large
- `scripts/export_hall_of_shame.py`: converter from raw APISniffer output
- `scripts/materialize_scan_state.py`: rebuilds APISniffer history files from safe state

## Scheduled Scanning

`.github/workflows/refresh-hall-of-shame.yml` does the following on a schedule and on manual dispatch:

- clones `https://github.com/X3r0Day/XeroDay-APISniffer.git` into the runner
- restores prior safe scan history into the cloned APISniffer workspace
- runs only Stage 1 and Stage 2: discovery and scanning
- updates `data/hall-of-shame.json` and `data/scan-history.json`
- commits those safe files back to this repo
- deploys the refreshed static site to GitHub Pages

The default schedule is every 30 minutes. Change the cron expression in `.github/workflows/refresh-hall-of-shame.yml` if you want a different interval.

Optional secret:

- `APISNIFFER_PROXIES`: newline-separated proxies written into `live_proxies.txt` during the workflow
