# BÁO CÁO CHI TIẾT ĐỘ BAO PHỦ KIỂM THỬ (WIDE COVERAGE AUDIT REPORT)
## Run ID: RUN-20261029-E2E-AUDIT | Ngày thực hiện: 29/10/2026 | Nền tảng: ScamAlert Production

---

### 1. Độ Bao Phủ Theo 5 Hướng Thu Thập Dữ Liệu (5 Data Streams Audit)

| Hướng Thu Thập | Số Mẫu Dự Kiến | Số Mẫu Đã Chạy | Tỷ Lệ Phát Hiện (TP Rate) | Đánh Giá Mức Độ Đầy Đủ & Khoảng Trống |
| :--- | :---: | :---: | :---: | :--- |
| **Stream 1: Tin nhắn lừa đảo thực tế (Real-world Scam SMS)** | 49 | 49 | **97.96%** (48/49) | **Rất Đầy Đủ:** Trích xuất từ 63 ảnh thực tế tại Việt Nam, bao quát mạo danh ngân hàng, tuyển CTV, cờ bạc, phạt nguội. Chỉ hụt 1 ca domain mới. |
| **Stream 2: Cảnh báo chính thức (Official Authority Warnings)** | 9 | 9 | **100.00%** (9/9) | **Rất Đầy Đủ:** Bao gồm án lệ chính thức từ Bộ Công An (A05, C08), NCSC, Vietcombank, Cục CSGT. 100% bắt trúng. |
| **Stream 3: Báo chí uy tín & Kịch bản mở rộng (Investigation)** | 17 | 17 | **76.47%** (13/17) | **Cần Bổ Sung Production:** 4 kịch bản mới (Cấp cứu Chợ Rẫy, Deepfake tống tiền, Từ thiện bão lũ, Chuyển nhầm tiền) bị bỏ sót do rule chưa nạp lên production. |
| **Stream 4: Mẫu hợp lệ đối chứng (Benign Controls)** | 18 | 18 | **100.00% TN** (18/18) | **Rất Đầy Đủ:** Bao quát biến động số dư, OTP thật, thông báo điện lực EVN, Viettel, Shopee, giao hàng COD thật, chat gia đình. 0% False Positive. |
| **Stream 5: Biến thể đối kháng (Adversarial & Obfuscation)** | 17 | 17 | **94.12%** (16/17) | **Tốt:** Đã kiểm thử ký tự đồng hình Cyrillic (Homoglyph), teencode leetspeak (`0TP`, `k.h.o.a`, `du0c`), khoảng trắng gãy link, ngôn từ nhã nhặn. |

---

### 2. Độ Bao Phủ Theo Nhóm Kịch Bản Tấn Công (Scenarios Taxonomy)

| Nhóm Kịch Bản (Scenario Group) | Số Mẫu Test | Tỷ Lệ Phát Hiện (Recall) | Nhận Xét Kỹ Thuật |
| :--- | :---: | :---: | :--- |
| **Mạo danh Ngân hàng & Tài chính (Bank Impersonation)** | 35 | **97.14%** (34/35) | Cực kỳ vững chắc trước các bẫy khóa thẻ, trừ phí TikTok, cập nhật sinh trắc học QĐ 2345. |
| **Mạo danh Công an, Tòa án, CSGT (Gov / Legal Coercion)** | 16 | **100.00%** (16/16) | Bao phủ trọn vẹn phạt nguội đèn đỏ, lệnh bắt giam rửa tiền, tải app VNeID đất đai giả mạo. |
| **Tuyển dụng CTV & Đầu tư tài chính (Job / Investment)** | 10 | **100.00%** (10/10) | Nhận diện xuất sắc hứa hẹn thu nhập 800k/ngày, nhiệm vụ Shopee/Lazada/Tiki, lãi suất 25%/tuần. |
| **Dịch vụ thiết yếu: Điện lực, Viễn thông (Utilities / SIM)** | 6 | **100.00%** (6/6) | Bắt trọn vẹn EVN dọa cắt điện sau 17h và Cục Viễn thông dọa khóa SIM 2 chiều theo Nghị định 49. |
| **Cứu nạn Y tế & Học đường (Medical Emergency)** | 2 | **0.00%** (0/2) | **Khoảng trống nghiêm trọng:** Cần nạp gấp rule `R-MED-001` vào production. |
| **Tống tiền công nghệ cao & Deepfake (AI Extortion)** | 2 | **0.00%** (0/2) | **Khoảng trống nghiêm trọng:** Cần nạp gấp rule `R-EXT-001` vào production. |
| **Gian lận An sinh Xã hội & Trợ cấp (BHXH / BHYT)** | 4 | **100.00%** (4/4) | Nhận diện tốt trợ cấp thai sản và dọa khóa thẻ BHYT. |
| **Vay nóng & Tín dụng đen gài bẫy (Loan Trap)** | 4 | **75.00%** (3/4) | Bắt tốt duyệt vay siêu tốc, nhưng hụt ca cố tình chuyển nhầm tiền để ép vay nặng lãi. |
| **Từ thiện & Cứu trợ thiên tai (Fake Charity)** | 2 | **0.00%** (0/2) | **Khoảng trống nghiêm trọng:** Cần nạp gấp rule `R-CHARITY-001`. |

---

### 3. Phân Tích Độ Trễ & Hiệu Năng Thực Thi (Latency & Performance)
- **Tổng số request gửi tới Vercel:** 114 requests.
- **Tỷ lệ thành công HTTP 200:** **100.00% (0 lỗi mạng, 0 timeout)**.
- **Độ trễ trung vị (p50 Latency):** **274 ms**.
- **Độ trễ phân vị 95 (p95 Latency):** **350 ms**.
- **Đánh giá:** Hệ thống API Serverless trên Vercel phản hồi cực kỳ nhanh chóng và ổn định, sẵn sàng chịu tải cho ứng dụng thực tế.
