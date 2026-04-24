# Trivy Docker Image Scanner

A modern web app to **pull Docker images from any registry, save them as `.tar`, and
scan them with [Trivy](https://github.com/aquasecurity/trivy)** — replacing
batch scripts that loop `docker pull` + `docker save`. Includes an in-app Trivy
version manager.

## Features

- **Pull from registry**: add one or more image URLs (one per row, click **+ Add image** for more), optional `docker login`, get `.tar` files saved on disk
- **Quick Scan**: scan a Docker image directly without writing a `.tar` file
- **One-click scan** of every just-pulled `.tar` (no re-upload needed)
- Drag-and-drop upload for an existing `.tar` file
- Native folder picker (**Browse…** button) for choosing the output directory
- Show/hide password toggle on the registry-login form
- Pick & install any Trivy version straight from GitHub releases
- Severity dashboard (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN) with searchable, filterable CVE table
- Modern dark glassmorphism UI: gradients, aurora background

## Create VENV Window
```
python -m venv venv
```

In bash on Windows: ```source venv/Scripts/activate```
In PowerShell: ```venv\Scripts\Activate.ps1```
In cmd: ```venv\Scripts\activate.bat```

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Open http://localhost:8000

The host needs:

- **Docker** on PATH (for the *Pull from Registry* feature)
- The app downloads Trivy itself into `./bin/trivy` when you click *Install*

## How to use

### 1) Install Trivy

Pick a version from the right-hand panel and click **Install** — the matching
binary is downloaded from `github.com/aquasecurity/trivy/releases/download/v<version>/...`
into `./bin/trivy`.

### 2) Pull images (replaces your batch script)

In the *Pull from Docker Registry* card:

1. (Optional) Fill **Registry login** with your registry hostname, username, and
   password / access token, then click **docker login**.
2. Add image URLs by clicking **+ Add image** for each one, for example:

   ```
   nginx:latest
   alpine:3.19
   registry.example.com/team/my-service:1.2.3
   ```

3. Optionally set an **Output directory** (e.g.
   `D:\scans\2026-04-24` on Windows, or `/var/scans/today` on Linux/macOS),
   or click **Browse…** to pick a folder. Leave blank to save into `./tars`
   next to `main.py`.
4. Click **Pull all**. The server runs:

   ```
   docker pull <image>
   docker save -o <output_dir>/<short-name>.tar <image>
   ```

   for each line. Each result row shows the saved path, file size, and a
   **Scan now** button.

### 3) Scan

Click **Scan now** next to any pulled tar — or drop an existing `.tar` into the
*Scan an Existing Tar* card and click **Run scan**.

## Endpoints

| Endpoint | What it does |
| --- | --- |
| `GET  /api/trivy/version`  | Reports installed Trivy version |
| `GET  /api/trivy/releases` | Lists recent Trivy releases from GitHub |
| `POST /api/trivy/install`  | Downloads & extracts the binary for the current OS/arch |
| `GET  /api/docker/check`   | Reports whether `docker` is reachable |
| `POST /api/docker/login`   | Runs `docker login -u <user> --password-stdin <registry>` |
| `POST /api/docker/logout`  | Runs `docker logout <registry>` |
| `POST /api/docker/pull`    | JSON `{images:[...], output_dir:"..."}` → pulls and saves tars |
| `GET  /api/docker/tars`    | Lists `.tar` files in the output directory |
| `POST /api/browse_folder`  | Opens a native OS folder picker on the host and returns the chosen path |
| `POST /api/scan`           | Scans an uploaded `.tar` with Trivy |
| `POST /api/scan_path`      | Scans a `.tar` already on disk (used by the *Scan now* buttons) |
| `POST /api/scan_image`     | **Quick Scan** — scans a Docker image by name with no `.tar` written |

## Run with Docker

A `Dockerfile` and `docker-compose.yml` are included. They bake in both Trivy
and the Docker CLI so the container is fully self-contained.

```bash
# Build + run with docker compose (preferred)
docker compose up -d
docker compose logs -f
# stop:
docker compose down
```

Or with plain docker:

```bash
docker build -t trivy-image-scanner:latest .

docker run --rm -p 8000:8000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(pwd)/tars:/app/tars" \
    trivy-image-scanner:latest
```

Open http://localhost:8000.

> **Note:** the container talks to your **host's** Docker engine via the mounted
> `/var/run/docker.sock`. This is required so the app can run `docker pull` /
> `docker save` against your normal Docker setup. It also means the container
> has root-equivalent access to your Docker engine — only use with images you
> trust, and don't run it on production servers exposed to the internet.

## Build & push to Docker Hub

The `Dockerfile`, `.dockerignore`, and `.gitignore` are written so your local
virtualenv, `bin/`, `tars/`, `.env` files, IDE metadata, and any `.txt` notes
never end up in the image you push.

```bash
# 1. log in to Docker Hub once
docker login

# 2. build, tagging the image with your Docker Hub username and a version
#    Replace <YOUR_USERNAME> with your real Docker Hub username.
docker build -t <YOUR_USERNAME>/trivy-image-scanner:1.0.0 \
             -t <YOUR_USERNAME>/trivy-image-scanner:latest .

# 3. push both tags
docker push <YOUR_USERNAME>/trivy-image-scanner:1.0.0
docker push <YOUR_USERNAME>/trivy-image-scanner:latest
```

Anyone can then run your published image:

```bash
docker run --rm -p 8000:8000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(pwd)/tars:/app/tars" \
    <YOUR_USERNAME>/trivy-image-scanner:latest
```

### Multi-arch build (optional)

To publish images that work on both `amd64` (Intel/AMD) and `arm64` (Apple
Silicon, ARM servers):

```bash
docker buildx create --use --name multiarch || true
docker buildx build --platform linux/amd64,linux/arm64 \
    -t <YOUR_USERNAME>/trivy-image-scanner:1.0.0 \
    -t <YOUR_USERNAME>/trivy-image-scanner:latest \
    --push .
```

## Notes

- Image filenames are derived from the repo name: e.g.
  `registry/team/my-service:tag` → `my-service.tar`.
- Pull timeout is 30 minutes per image; scan timeout is 15 minutes.
- Credentials sent to `/api/docker/login` are forwarded to the local docker CLI
  via stdin and **not stored** by the app — the docker daemon stores them as it
  normally would in `~/.docker/config.json`.
- Delete `./bin/trivy` to reset Trivy installation.
# trivy-scan-app
