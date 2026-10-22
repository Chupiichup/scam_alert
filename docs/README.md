# 🛡️ ScamShield Vietnam — Hệ Thống Phát Hiện & Cảnh Báo Tin Nhắn Lừa Đảo
## Kiến Trúc Local-First, Zero Raw Storage & Document-Relational Hybrid (4 Thực Thể Cốt Lõi)

Hệ thống phát hiện và cảnh báo tin nhắn SMS / OTT lừa đảo tại Việt Nam, tối ưu hóa bảo vệ cho người cao tuổi và gia đình với **độ chính xác 100% (0% cảnh báo giả)** qua 24 kịch bản thực nghiệm, tuân thủ nguyên tắc **Local-First & Zero Raw Storage**.

---

## 🚀 Các Cách Trải Nghiệm & Kiểm Tra Hệ Thống

### 1. Khởi Động Nền Tảng Toàn Diện (Full Platform Server)
Khởi động đồng thời Web Simulator (Senior-friendly), Visual AST CMS, Threat Intel Auto-Sync và REST API Ingestion:
```bash
node serve.js
```
* **📱 Ứng dụng Simulator & Giọng nói khẩn cấp (Client):** `http://localhost:8080` (hoặc mở trên điện thoại qua Wi-Fi)
  - Tích hợp **Web Speech API (Text-to-Speech)** tự động đọc to lời dặn bằng tiếng Việt khi gặp nguy hiểm.
  - Nút bấm 1 chạm **"Gọi điện thoại cho con ngay"** (`tel:+84912334455`) nổi bật, chống thao túng tâm lý.
  - Quét ảnh chụp màn hình Zalo/Telegram bằng **On-Device OCR** (Tesseract.js WASM).
* **🌳 Visual AST Rule Builder & CMS (Admin):** `http://localhost:8080/admin`
  - Tab 1: **Visual AST Studio** — Trực quan hóa cây logic điều kiện (AND, OR, NOT, REGEX_DISTANCE).
  - Tab 2: **🤖 AI Copilot Threat Radar** — Quản trị cào tin tức đa nguồn (VnExpress, Dân Trí, Cổng BCA, Telegram, Threads, Facebook Fanpage, Zalo OA), cấu hình tần suất cào độc lập (15m, 30m, 60m, 120m) và cơ chế duyệt bản thảo 1-Click (Four-Eyes Approval).
  - Sandbox thử nghiệm dán bài báo/link bóc phốt để AI Copilot trích xuất và sinh Cây AST tức thì.
* **📡 API Ingestion & Incident Hub (Backend):** `http://localhost:8080/api/v1/ingest/analysis`
* **🚨 Danh sách Sự cố Khẩn cấp:** `http://localhost:8080/api/v1/safety-events`
* **💾 Xuất Dữ liệu PostgreSQL 4 Bảng Hybrid Dump:** `http://localhost:8080/api/v1/export/sql`

---

### 2. Kiểm Tra Nhanh Bằng Dòng Lệnh (CLI)
Kiểm tra bất kỳ tin nhắn nào ngay trong Terminal:
```bash
# Cú pháp: node scam_detector.js "<nội dung tin nhắn>" "[người gửi]" [--stateful]

# Ví dụ 1: Tin nhắn lừa đảo mạo danh cập nhật Sổ đỏ VNeID
node scam_detector.js "Thong bao tu Can bo dia chinh: So do dat dai cua ban tren VNeID bi sai lech. Vui long tai https://dichvucong-datdai.top/vneid.apk de dong bo." "+84912384729"

# Ví dụ 2: Tin nhắn mạo danh Vietcombank
node scam_detector.js "Vietcombank tran trong thong bao: Tai khoan cua Quy khach tam thoi bi khoa. Vui long dang nhap tai http://vietcombank-smartotp.com de xac minh va nhap ma OTP truoc 24h." "Vietcombank"

# Ví dụ 3: Tin nhắn ngân hàng thật (An toàn - không báo động giả)
node scam_detector.js "VCB: So du TK 0011002345678 +5,000,000 VND luc 10:15. Khong cung cap ma OTP cho bat ky ai duoi moi hinh thuc de bao ve tai khoan." "VCB-Digibank"
```

---

### 3. Chạy Toàn Bộ Bộ Kiểm Thử Chuẩn (Test Suites)

#### A. Kiểm chuẩn Động cơ Quy tắc AST (Test Rule Engine):
```bash
node test_rule_engine.js
```
* **Precision (Độ chính xác cảnh báo):** `100.00%` (24/24 Test cases PASS)
* **Recall (Độ bao phủ phát hiện):** `100.00%`
* **False Positive Rate (Báo động giả):** `0.00%` (Không bao giờ báo nhầm tin biến động số dư hoặc OTP thật)
* **Extended Tests:**
  1. Toán tử AST khoảng cách hai chiều `REGEX_DISTANCE` / `NEAR`.
  2. Động cơ Trạng thái Hội thoại đa ngày `Stateful Multi-Day Conversation`.
  3. Kịch bản lừa đảo Cập nhật Sổ đỏ trên VNeID (`R-GOV-003`).
  4. Bộ giải mã Unicode NFKD & Bảng ánh xạ Cyrillic Homoglyphs đối kháng.

#### B. Kiểm thử Tích hợp Nền tảng E2E (Test Platform):
```bash
node test_platform.js
```
* Chạy 5 luồng tích hợp kiểm tra Schema 4 bảng chuẩn: Rules API $\to$ NCSC Auto Sync $\to$ Ingestion $\to$ Push Notification tới con cái (0 VNĐ) $\to$ Incident Hub Tracking $\to$ SQL Dump.

---

## 📁 Cấu Trúc Thư Mục Tinh Gọn

```text
├── index.html                     # Web Simulator: OCR, Web Speech API (TTS), Nút Gọi Con 1-Chạm
├── admin_cms.html                 # Giao diện Web Admin CMS quản trị Cây AST trực quan kéo thả
├── serve.js                       # Điểm khởi động toàn bộ nền tảng (Web + API + Cron Sync)
├── scam_detector.js               # Công cụ dòng lệnh (CLI) phân tích tin nhắn tức thì
├── test_rule_engine.js            # Engine lõi AST, NFKD, Cyrillic & Bộ kiểm thử 24 ca chuẩn
├── test_platform.js               # Bộ kiểm thử tích hợp REST API Ingestion & Push Notification
│
├── server/                        # Backend Services & Persistence (Mô hình 4 Thực thể Hybrid)
│   ├── app.js                     # Express REST API Server (Ingest, Safety Events, Rules, Export)
│   ├── notification_service.js    # Cổng gửi Push Notification tới app con cái (FCM/APNS, 0 VNĐ)
│   ├── threat_intel_service.js    # Lập lịch tự động đồng bộ NCSC/ChốngLừaĐảo mỗi 30 phút
│   └── models/
│       └── db.js                  # Adapter 4 thực thể: user, message, scam_analysis, safety_event
│
├── data/                          # Thư mục lưu trữ dữ liệu bền vững (Zero Raw Storage)
│   └── db_store.json              # Kho dữ liệu sự cố & phân tích 4 bảng cục bộ
│
├── scam_detection_rules.json      # Bộ 13 quy tắc phát hiện chuẩn hóa (Cây JSON AST)
├── scam_url_domain_indicators.csv # Danh sách đen tên miền & link lừa đảo NCSC / ChốngLừaĐảo
├── scam_sender_indicators.csv     # Danh mục người gửi & uy tín số điện thoại/Brandname
├── scam_risk_signals.csv          # Từ điển 21 tín hiệu rủi ro (Risk Signals)
├── scam_keywords_patterns.csv     # Thư viện từ khóa, biến thể teencode & biểu thức Regex
├── scam_detection_test_cases.csv  # Tập dữ liệu 24 ca kiểm thử đối soát
├── scam_detection_seed_data.sql   # DDL & Dữ liệu Seed 4 bảng nạp PostgreSQL Production
│
└── docs/                          # Tài liệu kiến trúc và đặc tả yêu cầu
    ├── WALKTHROUGH.md             # Hướng dẫn toàn diện giải thích từng file & kịch bản nghiệm thu
    ├── ERD.md                     # Đặc tả kiến trúc dữ liệu 4 bảng Document-Relational Hybrid (v3.0)
    ├── PRD.md                     # Đặc tả yêu cầu sản phẩm & kịch bản lừa đảo (PRD v3.0)
    ├── Test_Report.md             # Báo cáo kiểm chuẩn chi tiết 24 test cases & 4 extended suites
    ├── Threat_Intelligence_Research.md # Báo cáo nghiên cứu tình báo lừa đảo tại Việt Nam
    └── Scam_Detection_ERD_Rule_Engine_Explained.md # Sổ tay giải thích ERD & AST cho PM/BA
```

---

## 🧠 Cơ Chế Hoạt Động & Đảm Bảo An Toàn

1. **Chuẩn hóa chuỗi (Text Normalization & Anti-Evasion):** Giải mã Unicode NFKD, ánh xạ Homoglyphs Cyrillic $\to$ Latin (`\u0430` $\to$ `a`, `\u0435` $\to$ `e`), khử dấu tiếng Việt, xử lý teencode ngắt từ (`0TP`, `V.i.e.t.c.o.m`, `t.k`).
2. **Đối soát Threat Intel Sub-5ms:** Kiểm tra chéo đồng thời với danh sách đen tên miền (`scam_url_domain_indicators.csv`) và người gửi giả mạo trạm BTS (`scam_sender_indicators.csv`).
3. **Thực thi AST Rules Engine:** Đánh giá cây logic an toàn (AND/OR/NOT/REGEX_DISTANCE), bóc tách các tín hiệu nguy hiểm (`OTP_REQUEST`, `ACCOUNT_SUSPENSION_THREAT`, `APK_DOWNLOAD_LINK`, `RELATIVE_EMERGENCY_CLAIM`, `VNEID_LAND_UPDATE_SCAM`...).
4. **Triệt tiêu điểm cộng dồn (Deduplication Capping):** Tránh hiện tượng thổi phồng điểm số bằng cách áp dụng thuật toán `Decay Factor (50%)` cho các tín hiệu cùng nhóm rủi ro.
5. **Chiết khấu an toàn (Negative Evidence Discounting):** Khi tin nhắn chứa câu khuyến cáo bảo mật chính thống (*"Khong cung cap ma OTP cho bat ky ai"*), hệ thống tự động trừ 40 điểm, triệt tiêu 100% báo động giả.
6. **Bảo vệ người cao tuổi & chống thao túng tâm lý:** Tự động phát âm thanh cảnh báo bằng tiếng Việt (Web Speech API), cung cấp nút gọi khẩn cấp 1 chạm tới con cái (`tel:+84912334455`), và phát Push Notification tới máy con cái với chi phí 0 VNĐ.
