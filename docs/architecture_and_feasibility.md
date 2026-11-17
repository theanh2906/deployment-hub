# DeploymentHub — Đánh giá Tính khả thi & Kiến trúc Kỹ thuật E2E

> **Mục tiêu sản phẩm**: Xây dựng nền tảng tự động hóa triển khai ứng dụng (Self-hosted PaaS) trên VPS cá nhân hoặc hạ tầng doanh nghiệp, kết hợp trải nghiệm **Developer Experience (DX) mượt mà như Vercel/Railway** với khả năng **kiểm soát toàn diện Docker & VPS như Coolify/Dokploy/Portainer**, tối ưu cho cả Desktop lẫn thao tác khẩn cấp trên Mobile.

---

## 1. Đánh giá tính khả thi (Feasibility Assessment)

### 1.1. Kết luận tổng quan: Khả thi 100%

Về mặt kỹ thuật, **DeploymentHub hoàn toàn khả thi 100%** để xây dựng và đưa vào vận hành thực tế. Các nền tảng nguồn mở tương đương như **Coolify**, **Dokploy**, **CapRover** và **Portainer** đã chứng minh mô hình dùng **Docker Engine API + BuildKit + Reverse Proxy động (Traefik/Caddy)** trên VPS chạy ổn định ở quy mô production.

Điểm khác biệt cốt lõi tạo nên giá trị cạnh tranh của DeploymentHub không nằm ở việc phát minh lại container runtime, mà ở **trải nghiệm E2E thống nhất**:
- **Auto-Detect Polyglot thông minh**: Tự động nhận diện Next.js, React/Angular, Go, Rust và Monorepo FE+BE để sinh multi-stage `Dockerfile` / `docker-compose.yml` chuẩn production (~15–150MB) mà dev không cần viết tay boilerplate.
- **Linh hoạt SCM kép (Dual SCM Flow)**: Hỗ trợ cả **GitHub OAuth / App** (tự động gắn Webhook push-to-deploy) lẫn **GitHub Personal Access Token (PAT) Quick-Import** cho repo private ở nhiều tài khoản/tổ chức khác nhau.
- **Vận hành Docker trực quan + Mobile-First Ops**: Không tách rời giữa "PaaS deploy" và "Docker management", tích hợp thẳng Start/Stop/Restart, Live Logs, Dangling Image Prune, 1-Click Rollback và cảnh báo tài nguyên VPS ngay trên giao diện điện thoại.

| Tiêu chí | Vercel / Railway | Portainer | Coolify / Dokploy | **DeploymentHub (Mục tiêu)** |
| :--- | :--- | :--- | :--- | :--- |
| **Triển khai Self-hosted VPS** | Không (Managed Cloud) | Có (chỉ quản lý container) | Có | **Có (1-container Control Plane + SSH Remote)** |
| **Auto-Detect & Build đa ngôn ngữ** | Rất tốt (Cloud build) | Không | Tốt (Nixpacks / Dockerfile) | **Rất tốt (Multi-stage tối ưu size + Nixpacks fallback)** |
| **GitHub OAuth + PAT Quick-Import** | OAuth là chính | Hạn chế (Stack Git) | GitHub App + Deploy Key | **Cả OAuth Auto-Webhook & PAT đa tài khoản** |
| **Quản lý Docker Image / Prune** | Ẩn hoàn toàn | Rất mạnh | Cơ bản | **Trực quan (Tag history, Prune, 1-click Rollback)** |
| **Mobile-First Emergency Ops** | Xem status cơ bản | Khó thao tác trên mobile | Responsive cơ bản | **Thiết kế ưu tiên xử lý sự cố < 3 chạm trên Mobile** |

---

### 1.2. Phân tích thách thức kỹ thuật & Giải pháp cụ thể

Dù mô hình tổng thể đã được kiểm chứng, xây dựng một hệ thống PaaS tự host an toàn và ổn định trên các VPS phổ thông (1–8GB RAM) đòi hỏi giải quyết triệt để **4 thách thức kỹ thuật cốt lõi** sau:

#### Thách thức 1: Bảo mật `/var/run/docker.sock` (Nguy cơ leo thang đặc quyền Root)
- **Rủi ro**: Container nào được mount trực tiếp `/var/run/docker.sock` đều có toàn quyền điều khiển Docker daemon trên host (có thể tạo container `--privileged`, mount `/` của host, đọc toàn bộ dữ liệu và chiếm quyền root). Nếu tầng Web/API của DeploymentHub có lỗ hổng (như SSRF hay Command Injection), toàn bộ VPS sẽ bị xâm nhập.
- **Giải pháp kỹ thuật**:
  1. **Docker Socket Proxy (Lớp chặn bắt buộc)**: Không mount trực tiếp `docker.sock` vào container web/API đối mặt Internet. Thay vào đó, đặt một service trung gian như `tecnativa/docker-socket-proxy` (hoặc sidecar proxy nội bộ) trong mạng bridge cô lập, chỉ mở các API group tối thiểu cần thiết: `CONTAINERS=1`, `IMAGES=1`, `NETWORKS=1`, `VOLUMES=1`, `EVENTS=1`, `INFO=1`, và **tắt các nhóm nguy hiểm** như `SWARM=0`, `SECRETS=0`, `NODES=0`, đồng thời kiểm tra policy ở tầng Orchestrator để **cấm tuyệt đối** tạo container ứng dụng với `Privileged: true`, `NetworkMode: host`, `PidMode: host` hay mount đường dẫn hệ thống nhạy cảm (`/etc`, `/var/run/docker.sock`).
  2. **Tách biệt Control Plane & Builder Worker**: API phục vụ UI chỉ đẩy job vào hàng đợi; tiến trình Worker xử lý build/deploy chạy với quyền kiểm soát chặt chẽ và xác thực toàn bộ input (repo URL, branch name, build command, env key) trước khi gọi Docker SDK.
  3. **Bảo vệ Secrets bằng Envelope / AES-256-GCM**: Toàn bộ GitHub Token, PAT, SSH Private Key và Environment Variables được mã hóa AES-256-GCM trước khi ghi DB, không bao giờ đưa biến runtime nhạy cảm vào `ARG` của Dockerfile (tránh lưu vết trong `docker history`).

#### Thách thức 2: Cô lập quá trình Build (Build Isolation & Resource Contention)
- **Rủi ro**: Quá trình build (`npm run build`, `cargo build --release`) tạo ra tải CPU/I/O đột biến, có thể làm lag ứng dụng production đang phục vụ user trên cùng VPS; ngoài ra cache build hoặc file tạm giữa các project có thể xung đột.
- **Giải pháp kỹ thuật**:
  1. **Sử dụng Docker BuildKit với Isolated Cache Mounts**: Bật `DOCKER_BUILDKIT=1`, cô lập cache từng project bằng ID riêng (`--mount=type=cache,id=hub-proj-<project_id>-npm`), tránh đụng độ dependency cache giữa các repo.
  2. **Giới hạn cgroups cho Build Job**: Gắn `--memory`, `--cpus` và `--cpuset-cpus` / CPU quota thấp hơn container production (ví dụ cấp tối đa 70% CPU/RAM khả dụng cho tiến trình build) để web/API production luôn còn tài nguyên phản hồi request.
  3. **Build Queue & Concurrency Control**: Trên VPS đơn cấu hình nhỏ (`<= 4GB RAM`), hàng đợi build mặc định thiết lập **concurrency = 1** (build tuần tự FIFO, hiển thị trạng thái `Queued` trên UI). Với VPS lớn hơn (`>= 8GB RAM`), cho phép cấu hình `MAX_CONCURRENT_BUILDS=2..4`.
  4. **Ephemeral Workspace Cleanup**: Sau khi `docker build` hoàn tất, thư mục source clone tạm (`/var/lib/deploymenthub/builds/<deploy_id>`) được dọn sạch ngay lập tức; giữ lại source/git cache riêng nếu bật incremental fetch.

#### Thách thức 3: Zero-Downtime Deployment (Triển khai không gián đoạn)
- **Rủi ro**: Cách làm thô sơ (`docker stop app && docker rm app && docker run app`) gây downtime từ 5 giây đến 60 giây (đặc biệt với Next.js SSR hoặc API cần warmup DB pool), hoặc gây lỗi `502 Bad Gateway` khi Reverse Proxy trỏ vào container vừa start nhưng process bên trong chưa sẵn sàng lắng nghe cổng.
- **Giải pháp kỹ thuật (Blue-Green / Rolling Container Swap + Healthcheck)**:
  1. **Tag ảnh bất biến (Immutable Tagging)**: Mỗi bản build được gắn tag theo deploy ID hoặc commit SHA (`<project>:sha-8f92a1`).
  2. **Khởi chạy song song (Parallel Startup)**: Container mới (`<app>-<deploy_id>`) được start song song bên cạnh container cũ trên cùng Docker network. Không gắn cố định host port (tránh xung đột port trên host); mọi giao tiếp đi qua internal container port (`3000`, `8080`, `80`) thông qua Reverse Proxy.
  3. **Kiểm tra sức khỏe chủ động (Active Healthcheck)**: DeploymentHub theo dõi trạng thái `Health` từ Docker Engine (qua `HEALTHCHECK` HTTP `/healthz` hoặc TCP probe, cấu hình `interval=3s`, `retries=10`, `start_period=15s`).
  4. **Chuyển mạch mượt qua Traefik v3**: Chỉ khi container mới đạt trạng thái `healthy`, DeploymentHub mới cập nhật/kích hoạt label routing (hoặc Traefik tự nhận container `healthy` mới qua Docker Provider), đẩy traffic mới sang container mới và để container cũ hoàn tất các request đang xử lý (`graceful shutdown SIGTERM` trong 10-15s) trước khi dừng. Nếu container mới `unhealthy`, giữ nguyên container cũ 100% và báo lỗi deploy trên UI!

#### Thách thức 4: Giới hạn RAM và Disk trên VPS nhỏ (1GB – 4GB RAM)
- **Rủi ro**: Biên dịch Next.js (`webpack`/`turbopack`), Angular (`ng build`) hoặc Rust (`rustc` song song nhiều crate) rất dễ chạm ngưỡng **OOM Killer (Exit Code 137)** trên VPS 1–2GB RAM. Ngoài ra, dangling `<none>` images và BuildKit cache nhanh chóng làm đầy ổ cứng 20–40GB.
- **Giải pháp kỹ thuật**:
  1. **Pre-flight Host Check & Swap Guard**: Khi cài đặt hoặc trước lúc build, kiểm tra dung lượng RAM + Swap trống. Nếu VPS `<= 2GB RAM` và chưa có Swap, hệ thống khuyến nghị (hoặc cung cấp script setup 1 dòng) tạo Swapfile 2–4GB.
  2. **Adaptive Build Flags theo cấu hình VPS**:
     - Node.js (Next.js / React / Angular): Tự động inject `NODE_OPTIONS="--max-old-space-size=<70%_RAM_MB>"` (ví dụ `1024` trên VPS 2GB) vào stage builder.
     - Rust: Tự động giới hạn `-j 2` (`CARGO_BUILD_JOBS=2`) trên VPS có `<= 2 vCPU` hoặc `<= 2GB RAM` để tránh `rustc` ngốn hết RAM khi link.
  3. **Retention Policy & Auto-Prune**: Mặc định giữ tối đa `N = 3` (hoặc `5`) image tags thành công gần nhất cho 1-click rollback; tự động xóa dangling images (`<none>`) và cảnh báo khi Disk usage vượt ngưỡng `80%` / `90%`.
  4. **Tùy chọn Remote Registry / CI Offload (Mở rộng Phase 3)**: Cho phép build image từ GitHub Actions rồi push lên GHCR/Docker Hub, VPS nhỏ chỉ thực hiện `docker pull` image thành phẩm (~25MB) và chạy.

---

## 2. Kiến trúc tổng thể E2E (System Architecture)

### 2.1. Sơ đồ kiến trúc thành phần (Component Architecture)

Kiến trúc DeploymentHub chia thành 3 tầng rõ rệt: **Client Experience Layer**, **Control Plane (Core Engine)** và **Data Plane (VPS Runtime & Reverse Proxy)**.

```mermaid
flowchart TB
    subgraph Client["Tầng Giao diện (Client Layer)"]
        WebUI["Web Dashboard (Desktop Sidebar & Mobile Bottom Nav)"]
        StreamClient["Live Terminal & Metrics Client (WebSocket / SSE)"]
    end

    subgraph ControlPlane["Tầng Điều phối (DeploymentHub Control Plane)"]
        Gateway["API Gateway & Auth RBAC"]
        Vault["Crypto Vault (AES-256-GCM Tokens & Env)"]
        SCM["SCM Manager (GitHub OAuth / PAT & Webhook HMAC)"]
        Queue["Build Queue & Worker Pool (Concurrency Limit)"]
        Detector["Polyglot Auto-Detector & Dockerfile Generator"]
        Orchestrator["Docker & SSH Orchestrator"]
        Telemetry["Telemetry Collector & Alert Engine"]
    end

    subgraph DataPlane["Tầng Hạ tầng & Runtime (VPS Host / Remote VPS)"]
        SockProxy["Docker Socket Proxy (Restricted API)"]
        BuildKit["Docker BuildKit Engine"]
        DockerAPI["Docker Engine (/var/run/docker.sock or SSH)"]
        Traefik["Traefik v3 Reverse Proxy (Auto Let's Encrypt SSL)"]
        NetProxy["Docker Network: deploymenthub_proxy"]
        NetInternal["Docker Network: proj_internal (Isolated DB/BE)"]
        Containers["App Containers (Next.js / SPA / Go / Rust / Compose)"]
    end

    WebUI -->|"HTTPS REST API"| Gateway
    StreamClient <-->|"WSS / SSE Real-time Logs & Stats"| Gateway
    Gateway --> Vault
    Gateway --> SCM
    Gateway --> Queue
    Gateway --> Orchestrator
    SCM -->|"Trigger Enqueue"| Queue
    Queue --> Detector
    Detector -->|"Generated Dockerfile / Compose"| BuildKit
    Orchestrator --> SockProxy
    SockProxy --> DockerAPI
    BuildKit --> DockerAPI
    Telemetry -->|"Poll Stats & Docker Events"| SockProxy
    Telemetry -->|"Push Alerts (RAM/Disk/Crash)"| Gateway
    Traefik -->|"Route HTTPS :443"| NetProxy
    NetProxy --> Containers
    Containers <-->|"Private DNS"| NetInternal
```

**Lựa chọn Reverse Proxy & Auto-SSL (Traefik v3 vs Caddy)**:
- **Traefik v3 (Mặc định khuyên dùng)**: Đọc trực tiếp Docker Labels (`traefik.http.routers.*`), hỗ trợ chuyển mạch zero-downtime dựa theo Docker Healthcheck mà không cần reload file cấu hình, mạnh về path-based routing (`/api/*`) + middleware (`StripPrefix`, rate-limit) và Let's Encrypt ACME HTTP-01/DNS-01.
- **Caddy + `caddy-docker-proxy` (Tùy chọn nhẹ hơn)**: Cấu hình cực đơn giản, tự động cấp chứng chỉ Let's Encrypt + ZeroSSL mặc định, tiêu thụ RAM rất thấp (~20–30MB), phù hợp VPS siêu nhỏ 1GB RAM nếu chỉ cần routing subdomain cơ bản.

### 2.2. Luồng triển khai E2E (Sequence Diagram)

Sơ đồ dưới đây mô tả luồng khép kín từ khi lập trình viên nhấn **Deploy** (hoặc `git push` kích hoạt Webhook) cho đến khi tên miền HTTPS live không gián đoạn:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant GH as GitHub SCM
    participant Hub as DeploymentHub API & Queue
    participant Vault as Crypto Vault AES-256-GCM
    participant Builder as Build Engine & BuildKit
    participant Docker as Docker Engine Proxy
    participant Traefik as Traefik v3 Proxy

    Dev->>GH: git push origin main
    GH->>Hub: POST Webhook (X-Hub-Signature-256)
    Hub->>Hub: Verify HMAC-SHA256 and match branch
    Hub->>Vault: Decrypt GitHub Token or PAT and Env Vars in memory
    Vault-->>Hub: Plaintext credentials (in-memory only)
    Hub->>Builder: Enqueue Build Job and open SSE log stream
    Builder->>GH: Shallow git clone via GIT_ASKPASS (no token persisted)
    Builder->>Builder: Scan repo files, Auto-Detect stack and generate Dockerfile
    Builder->>Docker: docker build (BuildKit + cache mount + cgroup cap)
    Docker-->>Hub: Stream build logs to Client UI
    Builder-->>Hub: Image built (app-slug tag sha-8f92a1)

    Hub->>Docker: Create and Start new container with Traefik labels and Healthcheck
    loop Wait until Healthy
        Docker-->>Hub: Container Health Status (starting to healthy)
    end
    Docker-->>Traefik: Docker Event container healthy on proxy network
    Traefik->>Traefik: Issue or Verify Let's Encrypt SSL and route domain
    Hub->>Docker: Graceful stop and remove old container (keep old image for rollback)
    Hub-->>Dev: Notify Deploy Success (Live URL and Rollback snapshot saved)
```

### 2.3. Vòng đời trạng thái Deployment (Deployment State Machine)

```mermaid
stateDiagram-v2
    [*] --> Queued: User Trigger / Webhook / Rollback
    Queued --> Cloning: Worker acquires build slot
    Cloning --> Detecting: Source fetched
    Detecting --> Building: Dockerfile or Compose ready
    Building --> Starting: Image tagged
    Starting --> Healthcheck: Container running
    Healthcheck --> Live: Probe returns Healthy
    Cloning --> Failed: Auth or Git error
    Detecting --> Failed: Unsupported or missing entry
    Building --> Failed: Compile error or OOM
    Healthcheck --> Failed: Timeout or Unhealthy (keep old Live)
    Live --> Superseded: Newer deployment becomes Live
    Superseded --> Live: 1-Click Rollback triggered
```

---

## 3. Chiến lược Build đa ngôn ngữ / đa Framework (Polyglot Auto-Detection)

### 3.1. Kiến trúc Hybrid 2-Tier Auto-Detection (File Heuristic + AI Smart Assist)

Thay vì phụ thuộc hoàn toàn vào bộ quy tắc cứng (dễ gãy với monorepo dị biệt hoặc thiếu native OS library) hay dùng AI quét toàn bộ repo (chậm, tốn chi phí và rủi ro lộ mã nguồn), DeploymentHub áp dụng mô hình **Hybrid 2-Tier Auto-Detection** cho phép người dùng chuyển đổi linh hoạt ngay trên Deploy Wizard giữa **`Detect bằng File (Rule-based)`** và **`Hybrid: File + AI Assist (Khuyên dùng)`**.

#### Bảng so sánh 3 phương pháp nhận diện Stack

| Tiêu chí đánh giá | Detect bằng File (Rule-based) | Detect thuần bằng AI (LLM) | **Hybrid: File + AI (Khuyên dùng)** |
| :--- | :--- | :--- | :--- |
| **Tốc độ phản hồi** | Cực nhanh (`< 100ms`) | Chậm (`2–6 giây` gọi LLM + đọc ngữ cảnh) | **Nhanh (`< 100ms` Tầng 1, `~1–2s` Tầng 2 opt-in)** |
| **Chi phí vận hành (Token)** | `0 Token` (Chạy local 100%) | Tốn nhiều token cho mọi repo, kể cả repo đơn giản | **Gần như 0đ với repo chuẩn; siêu tiết kiệm (~1–2KB metadata)** |
| **Độ chính xác với repo chuẩn** | Rất cao (100% deterministic với Next.js, Go, Rust, Vite) | Cao nhưng có thể hallucinate version/cờ lệnh | **100% deterministic ở Tầng 1 cho stack chuẩn** |
| **Xử lý repo phức tạp / Custom Monorepo** | Hạn chế (dễ nhận nhầm thư mục con hoặc thiếu system libs) | Rất tốt (hiểu cấu trúc workspace, Makefile, turbo.json) | **Tối ưu (Tầng 2 AI phân tích các case phức tạp / fallback)** |
| **Bảo mật Source Code** | Tuyệt đối an toàn (không rời VPS) | Rủi ro gửi mã nguồn nghiệp vụ lên API LLM ngoài | **An toàn tuyệt đối (Chỉ gửi metadata ~1–2KB, không gửi source code)** |
| **Tự sửa lỗi build (Self-healing)** | Không có (chỉ báo log lỗi thô) | Có thể gợi ý sửa nhưng dễ sửa sai cấu trúc chuẩn | **AI Build Doctor đọc 50 dòng lỗi cuối, đề xuất Diff Preview cho user duyệt** |

#### Chi tiết vận hành 2 tầng

1. **Tầng 1 — Deterministic File & Manifest Scanner (`< 100ms`, `0 Token`)**:
   - **Quét siêu nhanh qua GitHub Trees API trước khi clone**: Sử dụng `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1` (hoặc quét trực tiếp workspace sau khi clone nông `--depth 1`) để đọc danh sách đường dẫn và các file cấu hình trọng yếu.
   - **Các marker & manifest được nhận diện**:
     - Hạ tầng có sẵn: `Dockerfile`, `docker-compose.yml`, `compose.yaml`.
     - JS/TS & Frontend: `package.json`, lockfiles (`pnpm-lock.yaml`, `yarn.lock`, `package-lock.json`, `bun.lockb`), `next.config.*`, `angular.json`, `vite.config.*`, `.nvmrc`, `turbo.json`, `pnpm-workspace.yaml`.
     - Backend biên dịch: `go.mod`, `go.work`, `Cargo.toml`, `rust-toolchain.toml`.
     - Gợi ý môi trường & ORM: `.env.example`, `prisma/schema.prisma`, `Makefile`.
   - **Kết quả**: Sinh điểm tin cậy (`Confidence Score 0–100%`) và bộ preset chuẩn hóa ngay lập tức. Nếu user chọn mode **Rule-based** hoặc repo đạt `Confidence >= 90%` không cần tinh chỉnh thêm, bỏ qua hoàn toàn Tầng 2.

2. **Tầng 2 — AI Smart Analyzer & Build Doctor (Opt-in / Fallback)**:
   - **Chính sách gửi ngữ cảnh tối thiểu (Metadata-Only ~1–2 KB)**: Tuyệt đối **không bao giờ** gửi mã nguồn nghiệp vụ (`.ts`, `.tsx`, `.go`, `.rs`, `.py`, `.sql`) hay giá trị secrets thật. Payload gửi lên AI Provider (hoặc Local Ollama / OpenAI / Gemini API cấu hình bởi admin) chỉ gồm:
     - Cây thư mục thu gọn 2 cấp (`tree -L 2`).
     - Nội dung manifest (`package.json`, `go.mod`, `Cargo.toml`, `Makefile`, `turbo.json`).
     - Khóa biến môi trường trong `.env.example` (đã lược bỏ giá trị mẫu nhạy cảm).
     - Tối đa **50 dòng cuối của build error log** (chỉ khi gọi AI Build Doctor lúc build thất bại).
   - **Các năng lực bổ trợ thông minh**:
     - *Phát hiện Native OS Dependencies ẩn*: Nhận diện `prisma` -> tự chèn `apk add --no-cache openssl`; nhận diện `sharp` -> chèn `vips-dev`; nhận diện `fluent-ffmpeg` -> chèn `ffmpeg`; nhận diện Rust crate cần `pkg-config`/`musl-dev` -> tự thêm vào stage `builder`.
     - *Trích xuất `.env.example` & Monorepo Routing*: Tự điền danh sách biến môi trường bắt buộc lên UI và ánh xạ đúng `frontend` (`:80`) vs `backend` (`:8080`) cho monorepo chưa có sẵn `docker-compose.yml`.
     - *AI Build Doctor (Self-healing có kiểm soát)*: Khi `docker build` gặp lỗi (ví dụ thiếu libc6-compat hoặc sai đường dẫn output Angular `dist/<app>/browser`), AI đề xuất bản vá dạng **Diff Preview (Human-in-the-loop)** để developer xem xét và nhấn duyệt trước khi rebuild.

#### Sơ đồ luồng Hybrid 2-Tier Auto-Detection

```mermaid
flowchart TD
    Input["GitHub Trees API or Cloned Workspace"] --> Tier1["Tier 1: Deterministic File and Manifest Scanner (< 100ms, 0 Token)"]
    Tier1 --> ScanMarkers["Scan Dockerfile, compose, package.json, lockfiles, go.mod, Cargo.toml, .env.example"]
    ScanMarkers --> ModeCheck{"Chế độ Detect hoặc Độ tin cậy?"}
    ModeCheck -->|"Rule-based Mode (0 Token)"| PresetOut["Sinh Preset Stack chuẩn hoặc Nixpacks Fallback"]
    ModeCheck -->|"Hybrid Mode (hoặc Low Confidence Opt-in)"| BuildMeta["Đóng gói Metadata Context (~1-2KB, không gửi source code)"]
    BuildMeta --> Tier2["Tier 2: AI Smart Analyzer (Phát hiện OS deps ẩn, map .env.example, monorepo)"]
    Tier2 --> HumanReview["Human Review Preview (Chỉnh sửa Stack, Env Vars, Dockerfile Diff)"]
    PresetOut --> HumanReview
    HumanReview -->|"User xác nhận Deploy"| BuildRun["BuildKit Execute Image"]
    BuildRun -->|"Build Success"| LiveReady["Image Ready: Healthcheck & Traefik SSL"]
    BuildRun -->|"Build Failed"| Doctor["AI Build Doctor (50 dòng error log cuối: Đề xuất Diff Patch)"]
    Doctor --> HumanReview
```

### 3.2. Bảng tổng hợp chiến lược đóng gói theo từng Stack

| Stack / Framework | Dấu hiệu nhận diện (Markers) | Base Builder Image | Base Runtime Image | Cổng mặc định | Kích thước Image | Chiến lược tối ưu trọng tâm |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Next.js (SSR/ISR)** | `package.json` chứa `"next"` | `node:20-alpine` | `node:20-alpine` | `3000` | **~110–155 MB** | Bật `output: 'standalone'`, bỏ `node_modules` thừa, chạy non-root `node server.js` |
| **React / Angular (SPA)** | `vite.config.*`, `react-scripts`, `angular.json` | `node:20-alpine` | `nginx:1.27-alpine` / `caddy:2-alpine` | `80` / `8080` | **~22–28 MB** | Chỉ copy static bundle `dist/`, cấu hình `try_files` cho Client-side Router |
| **Go REST API** | `go.mod` | `golang:1.22-alpine` | `gcr.io/distroless/static-debian12:nonroot` | `8080` | **~12–25 MB** | `CGO_ENABLED=0`, `-ldflags="-s -w"` strip debug symbols, binary tĩnh |
| **Rust REST API** | `Cargo.toml` | `rust:1.80-alpine` (hoặc `cargo-chef`) | `gcr.io/distroless/cc-debian12` / `alpine:3.20` | `8080` | **~15–30 MB** | `cargo-chef` cache crates layer, `cargo build --release`, strip binary |
| **Full-stack FE + BE** | Monorepo `frontend/` + `backend/` | Đa stage theo từng service | Tách container riêng + DB/Redis | `80` + `8080` | Tổng **~45–180 MB** | Orchestrate qua Compose, mạng internal cô lập DB, routing subdomain hoặc `/api/*` |

---

### 3.3. Chi tiết Dockerfile & Kiến trúc đóng gói cho từng Stack

#### A. Next.js — Multi-stage Node Alpine (`output: 'standalone'`)
- **Xử lý tự động**: Engine đọc `next.config.mjs` / `next.config.ts` / `next.config.js`. Nếu chưa có `output: 'standalone'`, DeploymentHub đề xuất bật hoặc inject wrapper config tạm thời trong quá trình build để Next.js chỉ trace và đóng gói những file thực sự cần thiết.
- **Template Dockerfile chuẩn**:
```dockerfile
FROM node:20-alpine AS base

# Stage 1: Cai dat dependencies theo lockfile
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN \
  if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm i --frozen-lockfile; \
  else npm i; fi

# Stage 2: Build Next.js
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NODE_OPTIONS="--max-old-space-size=1024"
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# Stage 3: Runner sieu gon (standalone)
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || wget -qO- http://127.0.0.1:3000/ || exit 1
CMD ["node", "server.js"]
```

#### B. React / Angular (SPA) — Multi-stage Node Build -> Nginx Alpine (~25MB)
- **Lưu ý kỹ thuật**:
  - Angular 17+ (`@angular/build:application`) xuất output vào `dist/<project-name>/browser`; Vite xuất ra `dist/`; Create React App xuất ra `build/`. Detector đọc `angular.json` hoặc `vite.config.*` để điền đúng đường dẫn `BUILD_OUT_DIR`.
  - Bắt buộc cấu hình **SPA fallback** (`try_files $uri $uri/ /index.html;`) để tránh lỗi `404` khi user F5 ở các route con như `/dashboard/settings`, đồng thời đặt `Cache-Control: immutable` cho thư mục `/assets/` và `no-cache` cho `index.html`.
- **Template Dockerfile chuẩn**:
```dockerfile
# Stage 1: Build static bundle
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* ./
RUN npm ci
COPY . .
ARG BUILD_CMD="npm run build"
RUN sh -c "$BUILD_CMD"

# Stage 2: Serve static voi Nginx (~24MB)
FROM nginx:1.27-alpine AS runner
ARG DIST_DIR=dist
COPY --from=builder /app/${DIST_DIR} /usr/share/nginx/html
RUN printf 'server {\n\
  listen 80;\n\
  root /usr/share/nginx/html;\n\
  index index.html;\n\
  gzip on;\n\
  gzip_types text/plain text/css application/javascript application/json image/svg+xml;\n\
  location /assets/ { expires 1y; add_header Cache-Control "public, immutable"; }\n\
  location / { try_files $uri $uri/ /index.html; }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:80/ >/dev/null || exit 1
CMD ["nginx", "-g", "daemon off;"]
```

#### C. Go / Rust REST API — Static Binary -> Distroless / Alpine (~15–30MB)
- **Go REST API**:
  - Biên dịch hoàn toàn tĩnh với `CGO_ENABLED=0` và cờ `-ldflags="-s -w"` (loại bỏ symbol table và DWARF debug info).
  - Dùng `gcr.io/distroless/static-debian12:nonroot` (chỉ ~2MB base + CA certs + tzdata, không chứa shell/package manager nên diện tích bề mặt tấn công gần như bằng 0). Nếu app cần shell hoặc công cụ debug nhẹ, tùy chọn chuyển sang `alpine:3.20`.
```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG ENTRY_PATH=.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/api-server ${ENTRY_PATH}

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/api-server /app/api-server
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/api-server"]
```
- **Rust REST API**:
  - Điểm nghẽn lớn nhất của Docker Rust là biên dịch lại hàng trăm crates mỗi lần đổi 1 dòng code. DeploymentHub sử dụng mô hình **`cargo-chef`** để tách việc biên dịch dependencies (`recipe.json`) thành layer cache riêng biệt, giúp các lần deploy sau nhanh gấp 5–10x.
  - Biên dịch `--release` (target `x86_64-unknown-linux-musl` với `alpine:3.20` hoặc binary glibc với `gcr.io/distroless/cc-debian12:nonroot`) + `strip` binary.
```dockerfile
FROM lukemathwalker/cargo-chef:latest-rust-1.80-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev pkgconfig openssl-dev

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
ARG CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bin app-api && strip target/release/app-api

FROM alpine:3.20 AS runner
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 appuser
COPY --from=builder /app/target/release/app-api /usr/local/bin/app-api
USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/app-api"]
```

#### D. Combined FE + BE (Monorepo / Full-stack Compose Orchestration)
- **Kịch bản phổ biến**: Monorepo chứa cả Frontend (React/Angular/Next.js) và Backend API (Go/Rust/Node) cùng cơ sở dữ liệu (PostgreSQL/Redis).
- **Chiến lược mạng & điều phối**:
  1. **Internal Isolated Network**: Tạo riêng mạng nội bộ `proj_<id>_internal` (`internal: true` cho database/redis để không bao giờ ra được Internet hay bị truy cập từ ngoài) và mạng `deploymenthub_proxy` chỉ gắn vào `frontend` và `backend`.
  2. **Service Discovery qua Docker DNS**: `backend` kết nối DB bằng hostname `postgres:5432`, `frontend` SSR (nếu dùng Next.js) gọi backend nội bộ qua `http://backend:8080` với độ trễ gần bằng 0ms.
  3. **2 Chế độ Routing linh hoạt qua Traefik Labels**:
     - **Chế độ 1 — Subdomain Routing (Khuyên dùng cho API độc lập/Mobile app)**:
       - `app.domain.com` -> service `frontend:80`
       - `api.domain.com` -> service `backend:8080`
     - **Chế độ 2 — Path-based Routing (Single Domain, không gặp rắc rối CORS/SameSite Cookie)**:
       - `crm.domain.com` (PathPrefix `/`) -> service `frontend:80` (Priority 1)
       - `crm.domain.com` (PathPrefix `/api`) -> service `backend:8080` (Priority 100, tùy chọn middleware `StripPrefix=/api`)
- **Cấu trúc `docker-compose.generated.yml` mẫu (Path-based + Internal Network)**:
```yaml
services:
  frontend:
    build:
      context: ./apps/web
      dockerfile: Dockerfile.hub
    restart: unless-stopped
    networks:
      - deploymenthub_proxy
      - proj_internal
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=deploymenthub_proxy"
      - "traefik.http.routers.crm-fe.rule=Host(`crm.anna.dev`)"
      - "traefik.http.routers.crm-fe.entrypoints=websecure"
      - "traefik.http.routers.crm-fe.tls.certresolver=letsencrypt"
      - "traefik.http.routers.crm-fe.priority=1"
      - "traefik.http.services.crm-fe.loadbalancer.server.port=80"

  backend:
    build:
      context: ./apps/api
      dockerfile: Dockerfile.hub
    restart: unless-stopped
    env_file: .env.backend
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - deploymenthub_proxy
      - proj_internal
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=deploymenthub_proxy"
      - "traefik.http.routers.crm-be.rule=Host(`crm.anna.dev`) && PathPrefix(`/api`)"
      - "traefik.http.routers.crm-be.entrypoints=websecure"
      - "traefik.http.routers.crm-be.tls.certresolver=letsencrypt"
      - "traefik.http.routers.crm-be.priority=100"
      - "traefik.http.services.crm-be.loadbalancer.server.port=8080"

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    volumes:
      - crm_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks:
      - proj_internal

networks:
  deploymenthub_proxy:
    external: true
  proj_internal:
    internal: true

volumes:
  crm_pgdata:
```

---

## 4. Quản lý SCM (GitHub OAuth & PAT)

Để cân bằng giữa tính tự động hóa cao (Zero-config Webhook) và sự linh hoạt cho freelancer/agency (quản lý nhiều tài khoản GitHub hoặc repo của khách hàng), DeploymentHub hỗ trợ **2 luồng kết nối SCM song song**:

```mermaid
flowchart LR
    User["Developer"] --> Choice{"Chọn phương thức SCM"}
    Choice -->|"Luồng 1: GitHub App hoặc OAuth"| OAuth["OAuth Flow + Grant Repo Permissions"]
    OAuth --> RepoPicker["Chọn Repo và Branch từ danh sách"]
    RepoPicker --> AutoHook["Auto-Register Webhook (push event + HMAC Secret)"]
    AutoHook --> PushDeploy["Auto-Deploy mỗi khi git push"]

    Choice -->|"Luồng 2: GitHub PAT Quick-Import"| PATInput["Nhập Repo URL + Fine-Grained PAT"]
    PATInput --> ValidateAPI["Verify Token qua GitHub REST API"]
    ValidateAPI --> CheckScope{"Có quyền admin:repo_hook?"}
    CheckScope -->|"Có"| AutoHook
    CheckScope -->|"Chỉ Read-Only Contents"| PollingOrManual["Manual Deploy / Deploy Webhook URL / Polling"]

    OAuth --> Encrypt["Mã hóa AES-256-GCM vào Crypto Vault"]
    PATInput --> Encrypt
```

### 4.1. Luồng 1: GitHub OAuth App / GitHub App (Auto-Webhook Push-to-Deploy)
- **Cơ chế kết nối**:
  - Hỗ trợ **GitHub App** (ưu tiên hàng đầu vì cấp quyền chi tiết theo từng repo cụ thể và tạo Installation Token tự hết hạn sau 1 giờ) và **GitHub OAuth App** (scopes `repo`, `admin:repo_hook`, `read:user`).
  - Khi người dùng chọn repository + branch (ví dụ `main` hoặc `production`), DeploymentHub tự động gọi `POST /repos/{owner}/{repo}/hooks` để đăng ký Webhook URL duy nhất của project (`https://hub.domain.com/api/v1/webhooks/github/{project_id}`) kèm một chuỗi `webhook_secret` 32-byte sinh ngẫu nhiên.
- **Xác thực Webhook an toàn**:
  - Mọi request tới endpoint webhook bắt buộc kiểm tra header `X-Hub-Signature-256` bằng thuật toán **HMAC-SHA256** với hàm so sánh thời gian hằng số (`hmac.Equal` / `crypto.timingSafeEqual`) để chống timing attack và giả mạo webhook.
  - Chỉ trigger build khi event là `push`, đúng `ref` (`refs/heads/<configured_branch>`), và không chứa flag `[skip ci]` trong commit message (tùy chọn).

### 4.2. Luồng 2: Personal Access Token (PAT) Quick-Import
- **Bài toán giải quyết**: Trong thực tế, dev thường cần deploy nhanh một private repo thuộc tài khoản GitHub khác, tài khoản tổ chức không cho cài GitHub App bên thứ ba, hoặc dùng **Fine-grained PAT** chỉ cấp quyền `Contents: Read-only` cho đúng 1 repository.
- **Quy trình xử lý**:
  1. User dán URL repo (`https://github.com/org/private-repo`) và chọn PAT đã lưu hoặc nhập PAT mới (gắn nhãn phân biệt như `Personal PAT`, `Client-A PAT`).
  2. Backend gọi `GET https://api.github.com/repos/{owner}/{repo}` với header `Authorization: Bearer <PAT>` để xác thực kết nối, đọc quyền (`permissions.pull`, `permissions.admin`), lấy default branch và danh sách branches.
  3. **Clone an toàn không để lộ PAT**: Khi `git clone`, tuyệt đối không nhúng token vào URL lệnh CLI (`https://x-access-token:PAT@github.com/...` có thể lộ trong `ps aux`, `.git/config`, hoặc stacktrace lỗi). Thay vào đó, sử dụng biến môi trường tạm thời `GIT_ASKPASS` trỏ tới helper script in-memory hoặc truyền qua HTTP header `Authorization: Basic ...` với `-c http.extraheader` chỉ tồn tại trong tiến trình clone rồi xóa ngay sau đó.
  4. **Xử lý khi PAT chỉ có quyền Read-Only**: Hệ thống không báo lỗi mà vẫn cho import/deploy; đồng thời cung cấp **Deploy Webhook URL riêng của DeploymentHub** (có bearer token) để user gắn vào GitHub Actions hoặc chạy thủ công bằng 1 nút bấm.

### 4.3. Lưu trữ Token & Secrets an toàn (AES-256-GCM)
- Toàn bộ OAuth Access/Refresh Token, PAT, SSH Private Keys và Env Vars nhạy cảm đều được mã hóa ở tầng ứng dụng bằng **AES-256-GCM (Authenticated Encryption)**:
  - **Master Key (KEK/DEK)**: Khóa 32-byte (256-bit) nạp từ biến môi trường `HUB_MASTER_KEY` khi khởi động Control Plane (không lưu trong SQLite/Postgres).
  - **Nonce/IV độc nhất**: Mỗi lần mã hóa một giá trị, sinh một **Nonce 96-bit (12 bytes)** ngẫu nhiên bằng CSPRNG (`crypto/rand`).
  - **Integrity Tag**: GCM sinh Authentication Tag 128-bit đi kèm ciphertext, đảm bảo phát hiện ngay lập tức nếu dữ liệu DB bị chỉnh sửa trái phép.
  - **Định dạng lưu DB**: `enc:v1:<base64_nonce>:<base64_ciphertext_and_tag>`.
  - **Log Redaction Filter**: Mọi stream log build và API log response đều đi qua bộ lọc redaction để thay thế bất kỳ giá trị token/secret nào xuất hiện tình cờ thành `[REDACTED]`.

---

## 5. Quản lý Docker Container & Image

### 5.1. Giao tiếp Docker Engine API (Local & Remote VPS)
- **Local VPS Host**: Giao tiếp trực tiếp với Docker Engine REST API (`v1.45+`) thông qua `docker-socket-proxy` đặt trước `/var/run/docker.sock`. Sử dụng official Docker SDK để đảm bảo tương thích đầy đủ streaming logs, stats, events và BuildKit.
- **Multi-VPS / Remote Node Management**:
  - **Phương án ưu tiên (Agentless SSH Tunnel)**: Sử dụng thư viện SSH native (`golang.org/x/crypto/ssh` hoặc Docker context `ssh://deploy@vps-ip:22`) xác thực bằng Ed25519 key (đã mã hóa AES-256-GCM). Ưu điểm: **Không cần cài thêm daemon/agent phức tạp trên VPS đích**, chỉ cần VPS đích có Docker và user nằm trong group `docker`.
  - **Phương án mở rộng (Lightweight Hub Agent)**: Ở quy mô nhiều node (>= 5 VPS) hoặc VPS nằm sau NAT không mở port SSH public, triển khai container `deploymenthub-agent` nhỏ gọn trên VPS đích giữ kết nối outbound WebSocket/gRPC (mTLS) về Control Plane.

### 5.2. Điều khiển vòng đời Container & Real-time Streaming Logs
- **Thao tác Container**:
  - `Start` (`POST /containers/{id}/start`), `Stop` (`POST /containers/{id}/stop?t=15` — gửi `SIGTERM` trước để app đóng kết nối DB an toàn rồi mới `SIGKILL`), `Restart` (`POST /containers/{id}/restart?t=15`), `Recreate` (áp dụng khi sửa Env Vars hoặc port mapping).
  - Lắng nghe **Docker Events Stream** (`GET /events?filters={"type":["container"]}`) theo thời gian thực để đồng bộ trạng thái (`running`, `restarting`, `exited`, `oom`, `healthy`, `unhealthy`) lên UI ngay lập tức mà không cần user F5.
- **Real-time Build & Container Logs (WebSocket / SSE)**:
  - **Build Logs**: Khi BuildKit chạy, từng dòng output được gắn timestamp và đẩy qua **SSE (Server-Sent Events)** hoặc **WebSocket** tới client, đồng thời ghi ra file log xoay vòng trên đĩa (`/data/logs/builds/<deploy_id>.log`) để xem lại lịch sử bất cứ lúc nào.
  - **Container Logs**: Kết nối `GET /containers/{id}/logs?follow=true&stdout=true&stderr=true&tail=300&timestamps=true`. Lưu ý kỹ thuật quan trọng: khi container chạy với `Tty=false`, Docker trả về **8-byte multiplexed header** ở đầu mỗi frame (byte `0` cho biết stream `1=stdout` hay `2=stderr`, bytes `4..7` chứa kích thước payload big-endian). Backend bắt buộc phải parse đúng 8-byte header này để phân biệt màu sắc `stdout` vs `stderr` sạch sẽ trên Terminal UI.

### 5.3. Quản lý Docker Image, Prune & 1-Click Rollback
- **Image Inventory & Dangling Prune**:
  - Liệt kê toàn bộ Docker Images kèm tên project liên kết, Tag (`sha-8f92a1`, `v1.4.2`, `<none>`), kích thước thực tế, và trạng thái (`In Use` / `Rollback Standby` / `Dangling`).
  - Nút **"Dọn dẹp Image rác (Docker Prune)"** gọi đồng thời `POST /images/prune` (`dangling=true`) và `POST /build/prune` (tùy chọn giữ cache mới nhất), trả về tổng dung lượng ổ đĩa vừa thu hồi (ví dụ `Reclaimed 2.48 GB`).
  - **Chính sách giữ lại (Retention Policy)**: Mặc định giữ lại **3–5 tagged images thành công gần nhất** của mỗi project (đánh dấu bảo vệ `Rollback Standby`) để tránh việc prune vô tình xóa mất bản dự phòng.
- **Cơ chế 1-Click Rollback (~3–8 giây)**:
  1. Mỗi lần deploy thành công tạo bản ghi snapshot bất biến trong bảng `deployments`: lưu `image_tag` (ví dụ `nextjs-commerce:dep-1042`), `git_sha`, `env_snapshot_encrypted`, `port`, và `traefik_labels`.
  2. Khi phát hiện lỗi trên bản mới (ví dụ `v1.5.0` vừa lên bị crash loop), user nhấn **Rollback về `v1.4.2`**.
  3. Hệ thống **không cần clone code hay build lại**, lấy thẳng image `app:dep-1041` đang nằm sẵn trong Docker Engine local -> tạo container mới với env/network của snapshot cũ -> đợi Healthcheck đạt `healthy` -> Traefik trỏ traffic về bản cũ -> dừng container lỗi. Thời gian khôi phục chỉ mất vài giây!

---

## 6. UX & Mobile-First Design

Khác với dashboard hạ tầng truyền thống chỉ dùng được trên màn hình rộng, **DeploymentHub xem Mobile là giao diện xử lý sự cố khẩn cấp (On-Call First)**.

### 6.1. Kiến trúc Adaptive Layout

| Thành phần UI | Desktop View (`>= 1024px`) | Mobile View (`< 768px`, ví dụ `390px`) |
| :--- | :--- | :--- |
| **Điều hướng chính** | Fixed Left Sidebar (`240px`) với 4 mục chính + Project switcher | Ẩn Sidebar; dùng **Sticky Bottom Navigation Bar** (4 tab cốt lõi, touch target `>= 44x44px`, hỗ trợ `safe-area-inset-bottom`) |
| **Thanh trạng thái VPS** | Top Header Bar hiển thị đầy đủ: Node name, CPU %, RAM GB, Disk %, Docker version | Top Compact Bar hiển thị pill tóm tắt `vps-sg-01 • 24% CPU • 48% RAM` (chạm để mở drawer chi tiết) |
| **Danh sách Projects / Containers** | Grid cards 2–3 cột hoặc Bảng dữ liệu đa cột với các action buttons | **Single-Column Action Cards** dạng dọc; gom thông số CPU/RAM/Domain gọn gàng, nút thao tác chính nằm vừa tầm ngón tay cái |
| **Terminal Logs & Deploy Wizard** | Split-pane (bên trái cấu hình/pipeline, bên phải terminal live) | Full-screen Bottom Sheet / Tabbed Drawer với font monospace `12px–13px`, nút toggle `Wrap lines` & `Errors only` |

### 6.2. Các luồng xử lý khẩn cấp trên Mobile (Emergency Mobile Workflows)

Mọi thao tác cứu hộ production trên điện thoại được thiết kế hoàn thành trong **tối đa 2–3 chạm**:

1. **Inspect Logs tức thì (2 chạm)**:
   - Từ màn hình Tổng quan hoặc link thông báo sự cố -> chạm thẳng vào nút **"Logs"** trên card Project -> mở ngay Terminal Drawer bám đáy màn hình với bộ lọc nhanh `Tất cả` / `Chỉ Lỗi (stderr)` và nút **"Copy 50 dòng cuối"** để chia sẻ nhanh qua Slack/Zalo/Telegram.
2. **Restart Container an toàn (2 chạm)**:
   - Chạm **"Restart"** trên card đang báo `Unhealthy` -> hiện Confirm Sheet rõ tên container (tránh chạm nhầm trên màn hình nhỏ) -> xác nhận và theo dõi spinner chuyển sang badge xanh `Healthy`.
3. **1-Click Rollback khẩn cấp (2 chạm)**:
   - Khi một project vừa deploy xong nhưng chuyển trạng thái `Unhealthy` hoặc `CrashLoopBackOff`, card project trên Mobile tự động hiển thị dải banner cảnh báo đỏ kèm nút **"Rollback về bản ổn định trước (sha-8f92a1)"**. Chạm -> Xác nhận -> Khôi phục traffic trong vài giây.
4. **Cảnh báo tài nguyên VPS & Dọn đĩa khẩn cấp (1–2 chạm)**:
   - Khi RAM hoặc Disk vượt ngưỡng cảnh báo (`>= 85%`), Top Header chuyển màu Amber/Red; chạm vào pill cảnh báo mở ra bảng tóm tắt top container ăn nhiều RAM nhất (kèm nút Restart nhanh) và nút **"Dọn Image rác (Prune)"** giúp giải phóng dung lượng đĩa ngay trên điện thoại.

---

## 7. Đề xuất Tech Stack & Lộ trình phát triển (MVP Roadmap)

### 7.1. Đề xuất Tech Stack cho chính DeploymentHub

Mục tiêu kỹ thuật: Bản thân DeploymentHub phải **siêu nhẹ** (chạy trên VPS 1GB RAM chỉ chiếm ~40–80MB RAM khi idle), cài đặt bằng **1 lệnh `docker run` hoặc 1 container duy nhất**, không kéo theo hệ sinh thái nặng nề.

- **Backend Control Plane — Go (Golang 1.22+)** *(Khuyên dùng)*:
  - *Lý do chọn Go*: Dùng chính Official Docker Engine Go SDK (`github.com/docker/docker/client`) và `golang.org/x/crypto/ssh`; concurrency model (goroutines + channels) cực kỳ lý tưởng cho việc stream hàng chục WebSocket/SSE logs và lắng nghe Docker Events đồng thời với footprint RAM chỉ **~30–50MB**. Biên dịch ra **1 static binary duy nhất** không cần runtime Node/Python đi kèm.
  - *Framework đề xuất*: `chi` hoặc `fiber` / `echo` cho HTTP/SSE/WS; `asynq` hoặc queue tự viết trên SQLite cho Build Worker.
  - *(Phương án thay thế)*: Nếu đội ngũ phát triển thuần TypeScript, có thể dùng **Node.js / Bun + Hono / Fastify + `dockerode` + `ssh2`** (đánh đổi tốn ~120–180MB RAM hơn Go một chút nhưng chia sẻ type TS trực tiếp với frontend).
- **Frontend UI — React 18+ + Vite + TypeScript + Tailwind CSS**:
  - Đóng gói thành static bundle và **nhúng thẳng vào Go binary bằng `//go:embed`**! Kết quả: Toàn bộ DeploymentHub (Backend + Frontend + Worker) chạy gọn trong **1 container Docker duy nhất (~35MB)**, phản hồi tức thì, không tốn thêm RAM chạy một server Next.js riêng cho trang quản trị.
- **Database — SQLite (WAL Mode) -> PostgreSQL (Optional Scale)**:
  - **MVP dùng SQLite ở chế độ `WAL` (`_journal_mode=WAL`)**: Zero setup, không tốn RAM chạy thêm Postgres cho Control Plane, dễ backup toàn bộ cấu hình chỉ với 1 file `.db`.
  - Thiết kế tầng Repository Interface sạch sẽ (hoặc dùng `sqlc` / `gorm` với migration chuẩn) để ở Phase 3 (Multi-team Enterprise) có thể trỏ sang PostgreSQL nếu cần.
- **Reverse Proxy mặc định — Traefik v3**:
  - Tự động phát hiện container qua Docker labels (`traefik.enable=true`), hỗ trợ chuyển mạch zero-downtime dựa trên Docker Healthcheck, và tích hợp sẵn Let's Encrypt ACME HTTP-01 / DNS-01 Auto-SSL.

### 7.2. Thiết kế mô hình dữ liệu cốt lõi (Core ER Diagram)

```mermaid
erDiagram
    VPS_NODE ||--o{ PROJECT : hosts
    SCM_CONNECTION ||--o{ PROJECT : authorizes
    PROJECT ||--o{ SERVICE : defines
    PROJECT ||--o{ ENV_VAR : stores
    PROJECT ||--o{ DEPLOYMENT : records
    PROJECT ||--o{ DOMAIN : exposes
    VPS_NODE ||--o{ ALERT_EVENT : triggers

    VPS_NODE {
        string id PK
        string name
        string mode
        string ssh_host
        string encrypted_ssh_key
        int cpu_cores
        int ram_mb
        string status
    }
    SCM_CONNECTION {
        string id PK
        string provider
        string auth_type
        string account_label
        string encrypted_token
        datetime expires_at
    }
    PROJECT {
        string id PK
        string node_id FK
        string scm_id FK
        string slug
        string repo_url
        string branch
        string stack_type
        string webhook_secret
        int retention_count
    }
    SERVICE {
        string id PK
        string project_id FK
        string name
        string role
        string build_context
        string dockerfile_mode
        int internal_port
        string healthcheck_path
    }
    ENV_VAR {
        string id PK
        string project_id FK
        string service_name
        string key
        string encrypted_value
        boolean is_build_arg
    }
    DEPLOYMENT {
        string id PK
        string project_id FK
        string commit_sha
        string image_tag
        string trigger_type
        string status
        string log_path
        datetime finished_at
    }
    DOMAIN {
        string id PK
        string project_id FK
        string service_name
        string hostname
        string path_prefix
        boolean auto_ssl
        string ssl_status
    }
    ALERT_EVENT {
        string id PK
        string node_id FK
        string metric_type
        float value_percent
        string severity
        datetime created_at
    }
```

### 7.3. Lộ trình phát triển (MVP Roadmap)

```mermaid
flowchart LR
    P1["Phase 1: Core MVP (Tuần 1 - 4) - Single VPS & Polyglot Deploy"] --> P2["Phase 2: Production & Mobile Ops (Tuần 5 - 8) - Compose, Rollback & Alerts"]
    P2 --> P3["Phase 3: Multi-VPS & Scale (Tuần 9 - 12+) - SSH Cluster, DBs & RBAC"]
```

| Giai đoạn | Mục tiêu chính | Hạng mục bàn giao kỹ thuật (Deliverables) | Tiêu chí nghiệm thu (Definition of Done) |
| :--- | :--- | :--- | :--- |
| **Phase 1: Core MVP**<br>*(Tuần 1 – 4)* | Deploy E2E 1 ứng dụng từ GitHub lên Single VPS có HTTPS tự động | - Core Go Control Plane + SQLite WAL + React SPA (`go:embed`).<br>- Docker Socket Proxy + Auto-bootstrap Traefik v3 (Let's Encrypt).<br>- GitHub OAuth + PAT Quick-Import + Crypto Vault AES-256-GCM.<br>- Webhook receiver HMAC-SHA256.<br>- Auto-Detect & Multi-stage DockerBuilder (Next.js, React/Angular, Go, Rust).<br>- SSE Real-time Build & Container Logs; Start/Stop/Restart; Adaptive Desktop/Mobile UI. | Người dùng dán PAT hoặc chọn repo OAuth và deploy thành công 4 stack mẫu lên VPS với domain HTTPS xanh trong `< 3 phút`. |
| **Phase 2: Production Hardening & Mobile Ops**<br>*(Tuần 5 – 8)* | Vận hành chuẩn Production không downtime & cứu hộ trên Mobile | - **Full-stack FE+BE Compose Orchestrator**: internal network, subdomain & `/api/*` path routing.<br>- **Zero-Downtime Swap** dựa trên Docker Healthcheck.<br>- **1-Click Rollback** về snapshot tag cũ (`< 8 giây`).<br>- Quản lý Docker Images, Retention policy & Dangling Image Prune.<br>- Build Queue OOM Guard (dynamic `NODE_OPTIONS`, `CARGO_BUILD_JOBS`, swap check).<br>- Telemetry CPU/RAM/Disk real-time + Mobile PWA + Emergency Alerts (Telegram/Webhook). | Deploy lại không rớt request (`0%` 502 error); rollback tức thì trên màn hình Mobile 390px; prune giải phóng disk chính xác. |
| **Phase 3: Multi-VPS & Team Scale**<br>*(Tuần 9 – 12+)* | Mở rộng đa server, dịch vụ dữ liệu và cộng tác nhóm | - **Remote VPS Management** qua SSH Tunnel & Lightweight Outbound Agent.<br>- One-click Managed Databases (PostgreSQL, Redis, MySQL) kèm auto-backup S3/Cloudflare R2.<br>- Hỗ trợ GitLab / Bitbucket SCM & Private Registry (GHCR/Docker Hub offload build).<br>- PR Preview Environments (tự tạo subdomain tạm cho mỗi Pull Request) & Multi-user RBAC / Audit Log. | Quản lý đồng thời `>= 3 VPS` trên 1 dashboard; tự động tạo & xóa preview environment theo vòng đời PR. |

---

## 8. Bước tiếp theo đề xuất (Next Steps)

1. **Chốt Tech Stack Core**: Xác nhận phương án **Go + React/Vite (`go:embed`) + SQLite WAL + Traefik v3** để bắt đầu khởi tạo repository khung cho Phase 1.
2. **Thiết kế Contract API & Database Migration**: Đặc tả OpenAPI/REST + WebSocket events cho `deployments`, `containers`, `images` và `scm`.
3. **Thử nghiệm Prototype Docker Builder**: Kiểm thử thực tế bộ 5 template Dockerfile/Compose trên một VPS 2GB RAM với áp lực build song song để tinh chỉnh tham số cgroups và OOM guard.
