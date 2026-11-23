# Sherlock Web — real Sherlock username OSINT in a browser

A **working web interface for the official [Sherlock Project](https://github.com/sherlock-project/sherlock)**. This is not a mock search UI or an independently maintained copy of Sherlock's website detection rules. It executes the authentic `sherlock-project` command line tool on the server and renders its CSV results.

## Features

- Search one or up to **eight** usernames in one run, including Sherlock's `{?}` variation syntax.
- Uses the **original Sherlock detection engine**, which supports 400+ platforms (exact count depends on the installed version and exclusions).
- Search all supported sites or select particular sites by their **exact Sherlock names** from the installed catalog.
- Options mapped to Sherlock: `--timeout`, `--site`, `--nsfw`, `--local`, `--ignore-exclusions`.
- Live Sherlock output, scan status, elapsed timer, stop scan.
- Full results after completion: found / not found / unknown, profile links, response time, filter, sorting.
- Export JSON, CSV, text with found links, or XLSX (from Sherlock itself).
- Recent server-session history. Mobile-friendly UI.
- Limits simultaneous scans and usernames. No third-party API key required.

## Start on Windows

1. Install **Python 3.10 or newer** from [python.org](https://python.org/) (select **Add Python to PATH**). Connect to the internet for package installation and account checks.
2. Unzip the project.
3. Double-click `start-windows.bat`.
4. Open **http://127.0.0.1:8000** in a browser. The script installs the official Sherlock library on the first run.

## Start on Linux / macOS

```bash
cd sherlock-web
./start-mac-linux.sh
```

Open **http://127.0.0.1:8000**.

## Docker (alternative)

```bash
docker compose up --build
```

Open **http://127.0.0.1:8000**.

## Deploying a public website

This app must run on a **Python-capable server** (VPS, Docker hosting, or a Python web host). **GitHub Pages and static-only hosting cannot execute Sherlock**, so uploading only the HTML, CSS and JavaScript is not enough.

For public/LAN deployments, set a strong `SHERLOCK_WEB_TOKEN` in the server environment and run through HTTPS behind a reverse proxy. The UI prompts for this token, stored only in the current browser tab. **Do not put the access token in public client-side source files.** The Docker Compose example listens on `127.0.0.1` by default; change that intentionally if exposing the service. Additional user accounts, quotas, rate limiting, logging, and persistent storage are recommended for multiuser or high-traffic deployment.

The app keeps a limited history in memory until restart; raw CSV/XLSX/TXT files are saved under `data/scans/<job-id>/` (a named persistent volume when using Docker). Treat those reports as potentially sensitive. Set `SHERLOCK_DATA_DIR` to change storage location. Purge it periodically if appropriate.

## Engine fidelity

The backend invokes:

```bash
python -m sherlock_project --no-color --print-all --csv --xlsx --txt --folderoutput <scan-folder> --timeout 30 <username>
```

It adds selected optional switches. The actual site list and detection behavior **are determined by upstream Sherlock**, not reimplemented here. There is no paid API, no fake preloaded user profiles, and no invented match percentages.

The upstream Sherlock Project is open-source under the MIT license. Sherlock output **is not proof two profiles belong to the same individual**. Some sites block automated checks or change their response behavior.

For Sherlock installed via `pipx` in a separate environment, you may instead set `SHERLOCK_EXECUTABLE` to an executable pathname for that installed CLI.

## Verification and limitations

Tests in `tests/` cover the website API, scan lifecycle, parsed Sherlock-format results, cancellation, and exports using an **offline stand-in executable**. This sandbox cannot install packages from PyPI or make real network requests, so a live upstream Sherlock scan could not be performed here. Once dependencies are installed with internet access, the site uses genuine Sherlock searches.

## Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/api/meta` | Engine status |
| GET | `/api/sites` | Current upstream catalog |
| POST | `/api/scans` | Start scan |
| GET | `/api/scans` | Current server-session history |
| GET | `/api/scans/{id}` | Progress, logs and results |
| DELETE | `/api/scans/{id}` | Stop scan |
| GET | `/api/scans/{id}/export/{format}` | Download `csv`, `json`, `txt`, or `xlsx` |
| GET | `/health` | Server health |

## Credits

Official upstream: [Sherlock Project](https://github.com/sherlock-project/sherlock). This browser interface is a separate project and is not an official Sherlock Project release. Sherlock Project is distributed under the MIT license; install the package to receive its license and notices.
