# DeploymentHub

Nền tảng Self-Hosted PaaS & quản lý Docker tối ưu trải nghiệm nhà phát triển (Go Control Plane + Embedded Web UI + Hybrid 2-Tier Auto-Detection + AES-256-GCM Vault + Traefik v3 Auto-SSL).

## Kiến trúc & Thư mục chính

- `cmd/deploymenthub/main.go`: Entrypoint khởi động HTTP server và nhúng Web UI (`web.StaticFS`).
- `internal/vault/`: Mã hóa AES-256-GCM (`enc:v1:...`) cho GitHub PAT/Secrets, xác thực HMAC-SHA256 webhook, và lọc ẩn token trong logs.
- `internal/detector/`: Hybrid 2-Tier Auto-Detection Engine (Tầng 1 quét file/manifest `< 100ms`, Tầng 2 AI Smart Analyzer & Build Doctor gợi ý native OS deps + diff patch) cho Next.js, SPA (React/Angular/Vite), Go, Rust, và Full-stack Compose.
- `internal/docker/`: Thread-safe Docker Engine Orchestrator (hỗ trợ cả Docker Socket/Proxy qua `DOCKER_HOST` và chế độ Simulator sẵn sàng chạy ngay không cần Docker daemon), SSE deployment streaming, Docker multiplexed log parser, Image Prune và 1-Click Rollback.
- `internal/server/`: HTTP REST + SSE API (`/api/v1/...`), GitHub Webhook receiver và static Web UI server.
- `web/index.html` & `web/embed.go`: Giao diện Desktop + Mobile (`390px`) được embed thẳng vào binary Go.

## Yêu cầu môi trường

- **Chạy local / build từ mã nguồn**: Go `1.22+` (chỉ sử dụng Go standard library, không cần tải dependency ngoài).
- **Deploy lên VPS**: Docker Engine & Docker Compose v2.

## Chạy Local (Development & Simulator Mode)

Mặc định khi không truyền `DOCKER_HOST`, DeploymentHub chạy ở chế độ **Simulator** (seed sẵn 5 projects, 7 containers, 6 images gồm dangling images và 5 Traefik proxy routes) để bạn kiểm thử toàn bộ luồng E2E ngay lập tức:

```powershell
# Chạy toàn bộ unit & integration tests
go test ./... -v

# Khởi động server tại http://localhost:4180
go run ./cmd/deploymenthub
```

Hoặc build thành 1 binary duy nhất:

```powershell
go build -o bin/deploymenthub.exe ./cmd/deploymenthub
./bin/deploymenthub.exe
```

## Biến môi trường cấu hình

| Biến | Mặc định | Mô tả |
| :--- | :--- | :--- |
| `PORT` | `4180` | Cổng lắng nghe HTTP cho Web UI và API |
| `DOCKER_HOST` | *(rỗng — Simulator)* | Endpoint Docker Engine hoặc Socket Proxy (vd `tcp://docker-socket-proxy:2375` hoặc `unix:///var/run/docker.sock`) |
| `HUB_MASTER_KEY` | *(tự sinh ngẫu nhiên)* | Khóa gốc dùng để dẫn xuất key AES-256-GCM cho Crypto Vault |
| `GITHUB_WEBHOOK_SECRET` | `deploymenthub-dev-webhook-secret` | Secret dùng để xác thực chữ ký `X-Hub-Signature-256` trên `/api/v1/webhooks/github` |
| `WEB_DIR` | *(rỗng — dùng embedded UI)* | Đường dẫn thư mục chứa `index.html` nếu muốn load UI trực tiếp từ đĩa khi phát triển |

## Deploy lên VPS với Docker Compose (Production)

File `docker-compose.yml` cấu hình sẵn **DeploymentHub** đi cùng **`tecnativa/docker-socket-proxy`** (cô lập quyền Docker socket) và **`traefik:v3.0`** (Auto-SSL Let's Encrypt):

```bash
export HUB_DOMAIN="hub.yourdomain.com"
export ACME_EMAIL="you@yourdomain.com"
export HUB_MASTER_KEY="$(openssl rand -hex 32)"
export GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"

docker compose up -d --build
```

Sau khi chạy, truy cập `https://hub.yourdomain.com` (hoặc `http://<vps-ip>:4180` khi test nội bộ).

## Danh sách API Endpoints (`/api/v1`)

| Method & Path | Chức năng |
| :--- | :--- |
| `GET /api/v1/health` | Kiểm tra trạng thái control plane & runtime mode |
| `GET /api/v1/overview` | Lấy toàn bộ VPS stats, projects, containers, images, proxy routes |
| `GET /api/v1/projects` | Danh sách projects |
| `POST /api/v1/projects/{id}/redeploy` | Kích hoạt redeploy nhanh cho project |
| `POST /api/v1/projects/{id}/restart` | Khởi động / restart project & container |
| `POST /api/v1/scm/verify-pat` | Kiểm tra GitHub PAT, mã hóa AES-256-GCM và chạy Auto-Detect |
| `POST /api/v1/detect` | Chạy Hybrid 2-Tier Stack Auto-Detection (`file` hoặc `hybrid`) |
| `POST /api/v1/detect/dockerfile` | Sinh multi-stage `Dockerfile` hoặc `docker-compose.yml` |
| `POST /api/v1/detect/diagnose` | Chạy AI Build Doctor phân tích 50 dòng error log cuối |
| `POST /api/v1/deployments` | Bắt đầu pipeline deploy E2E 5 giai đoạn (`202 Accepted`) |
| `GET /api/v1/deployments/{id}` | Xem chi tiết trạng thái bản deploy |
| `GET /api/v1/deployments/{id}/stream` | Stream `DeployEvent` theo thời gian thực qua SSE |
| `POST /api/v1/containers/{id}/action` | Thực thi `start`, `stop`, `restart`, hoặc `rollback` |
| `POST /api/v1/images/prune` | Dọn dẹp dangling Docker images (`<none>`) và hoàn trả dung lượng |
| `POST /api/v1/proxy/routes/{id}/toggle-ssl` | Bật/tắt Auto Let's Encrypt SSL cho domain route |
| `POST /api/v1/webhooks/github` | Nhận GitHub Push Webhook (bắt buộc chữ ký HMAC-SHA256 hợp lệ) |
