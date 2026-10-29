# BÁO CÁO TỔNG KẾT MỞ RỘNG KỊCH BẢN VÀ NĂNG LỰC NHẬN DIỆN LỪA ĐẢO
## Scam Scenario & Detection Coverage Expansion — Executive Summary

**Hệ thống:** ScamShield Vietnam / Scam Alert Detection Engine  
**Thời điểm hoàn tất:** Tháng 10/2026  
**Trạng thái tuân thủ:** 100% tuân thủ ranh giới kỹ thuật — Không thay đổi mã nguồn logic, scoring engine, threshold hay database schema.

---

## 1. Mục tiêu & Phương pháp tiếp cận

Dự án thực hiện mở rộng toàn diện độ bao phủ kịch bản và khả năng nhận diện gian lận viễn thông/trực tuyến tại Việt Nam trên hai trục song hành:
1. **Trục A (Scenario Coverage Expansion):** Nhận diện các cơ chế lừa đảo độc lập mới, các chuỗi tấn công đa giai đoạn, thủ đoạn công nghệ cao (AI Deepfake, mã độc Accessibility, Flash SMS/Fake BTS), và các bẫy tâm lý xã hội (cứu nạn y tế, khóa SIM Nghị định 49, điện lực EVN, trợ cấp BHXH/VNeID).
2. **Trục B (Detection Coverage Expansion):** Mở rộng từ khóa (chính tả, teencode, viết tắt, không dấu, biến thể ngắt âm), biểu thức quy chuẩn (regex), tín hiệu rủi ro ngữ cảnh (risk signals), và tập mẫu tin nhắn thực tế (empirical & synthetic SMS) mà không làm suy chuyển logic của Rule Engine.

---

## 2. Số liệu thống kê định lượng cốt lõi

### 2.1. Thống kê Kịch bản (Scenario Coverage Metrics)

| Chỉ số | Baseline (Trước) | Mở rộng (Bổ sung) | Tổng sau mở rộng | Ghi chú |
| :--- | :---: | :---: | :---: | :--- |
| **Tổng số kịch bản nhận diện** | **36** | **+17** | **53** | 17 kịch bản độc lập mới (`R-EVN-001` đến `R-SYN-001`) |
| **Nhóm lĩnh vực bao phủ (Taxonomy)** | 7 nhóm | +6 nhóm | 13 nhóm | Bao phủ trọn vẹn: Tiện ích công, Pháp lý, Y tế, Việc làm, AI Extortion, Hàng không... |
| **Ứng viên phân tích (Candidates)** | 0 | 24 | 24 | Khảo sát từ 18 nguồn chính thống |
| ├── Kịch bản độc lập (`ADD`) | - | 17 | 17 | Đã tạo rule AST chuẩn hóa trong `data/` |
| ├── Biến thể kịch bản (`VARIANT`) | - | 3 | 3 | Gán vào kịch bản mẹ (`CAND-018`, `019`, `022`) |
| ├── Tinh chỉnh kịch bản cũ (`REFINE`) | - | 1 | 1 | Tinh chỉnh `R-BNK-002` (xác thực sinh trắc học QĐ 2345) |
| ├── Gom cụm tối ưu (`MERGE`) | - | 1 | 1 | `CAND-023` (hợp nhất cụm Copilot AI redundant) |
| └── Cần nghiên cứu thêm (`RESEARCH_MORE`) | - | 2 | 2 | `CAND-020` (SIM ghép), `CAND-024` (Chiếm đoạt eSIM từ xa) |

---

### 2.2. Thống kê Năng lực Nhận diện (Detection Signals & Patterns)

| Thành phần Dữ liệu | Baseline | Bổ sung mới | Tổng sau cập nhật | File lưu trữ |
| :--- | :---: | :---: | :---: | :--- |
| **Từ khóa & Regex Patterns** | 321 entries | **+52 entries** | **373 entries** | `scam_keywords_patterns.csv` |
| ├── *Từ khóa tiếng Việt có dấu/ngữ cảnh* | - | +22 entries | - | EVN, cắt điện, chuẩn hóa thuê bao, Chợ Rẫy, giải cứu... |
| ├── *Teencode, viết tắt, không dấu* | - | +18 entries | - | `khoa sim`, `cat dien`, `cap cuu`, `vneid muc 2`, `ve tet`... |
| └── *Regex Pattern phức tạp* | - | +12 entries | - | Phone-only urgency, fine payment deadline, hospital fee |
| **Tín hiệu Rủi ro Ngữ cảnh (Risk Signals)** | 85 signals | **+19 signals** | **104 signals** | `scam_risk_signals.csv` |
| **Mẫu tin nhắn đại diện (SMS Samples)** | 42 samples | **+85 samples** | **127 samples** | `data/` & `docs/sms_examples_inventory.md` |
| ├── *Mẫu JSON AST có gán nhãn `SYNTHETIC_EXAMPLE`* | 0 | 68 samples | 68 samples | `data/scam_scenario_expansion_dataset.json` (4/rule) |
| └── *Mẫu phân tích chuyên sâu (`SMS-EXP-001` -> `017`)* | 42 | 17 samples | 59 samples | `docs/sms_examples_inventory.md` |

---

### 2.3. Bằng chứng kiểm chứng & Mức độ tin cậy nguồn (Source Evidence Tiers)

Toàn bộ kịch bản được đối soát qua 18 nguồn tài liệu xác thực tại [scam_scenario_research_sources.md](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/scam_scenario_research_sources.md):
- **Tier 1 — Cơ quan chức năng Việt Nam (60.4%):** Bộ Công an (A05, C08), Trung tâm Giám sát an toàn không gian mạng quốc gia (NCSC), EVN, Cục Viễn thông (Bộ TTTT), Bảo hiểm xã hội Việt Nam, Cục Hàng không, Ngân hàng Nhà nước.
- **Tier 2 — Báo chí uy tín phản ánh vụ án thật (24.5%):** Báo Tuổi Trẻ, Báo Lao Động, Báo Công an Nhân dân, Báo Dân Trí, VnExpress.
- **Tier 3 — Nghiên cứu an ninh mạng độc lập (9.4%):** Báo cáo phân tích mã độc Android Banking Trojan, Báo cáo lừa đảo trực tuyến NCSC 2023–2024.
- **Tier 4 — Phân tích suy luận kỹ thuật (5.7%):** Đánh giá rủi ro công nghệ mới (Flash SMS bypass, voice/video deepfake).

---

## 3. Danh mục 17 Kịch bản Độc lập Mới Bổ sung (`ADD`)

| ID Kịch bản | Tên kịch bản | Đối tượng mạo danh | Kênh dẫn dụ | Cơ chế & Thủ đoạn cốt lõi |
| :--- | :--- | :--- | :--- | :--- |
| **`R-EVN-001`** | Lừa đảo dọa cắt điện EVN | Điện lực Việt Nam (EVN) | SMS Brandname giả / OTT | Dọa ngừng cấp điện sau 2h nếu không thanh toán tiền điện qua link lạ. |
| **`R-SIM-001`** | Dọa khóa SIM chuẩn hóa TTTB | Cục Viễn thông / Nhà mạng | SMS / Cuộc gọi tự động | Viện dẫn Nghị định 49 yêu cầu chuẩn hóa gấp trong 2 giờ hoặc bị khóa SIM vĩnh viễn. |
| **`R-VNEID-001`** | Lừa kích hoạt VNeID mức 2 | Công an phường / C06 BCA | SMS / Zalo giả danh | Dụ cài app `vneid.gov-vn.apk` chứa mã độc Accessibility Service để kiểm soát máy. |
| **`R-MED-001`** | Tống tiền cấp cứu y tế | Bệnh viện Chợ Rẫy, Việt Đức | Cuộc gọi khẩn + SMS | Báo tin con/cháu bị tai nạn nguy kịch đang chờ mổ, ép phụ huynh chuyển tiền gấp. |
| **`R-LOAN-001`** | Lừa giải ngân vay duyệt nhanh | Công ty tài chính / App EasyLoan | SMS Spam / Telesale | Hứa duyệt hạn mức 50-200 triệu lãi suất 0%, sau đó đòi "phí giải ngân/phí sửa hồ sơ". |
| **`R-AIR-001`** | Lừa đổi vé máy bay hủy chuyến | Vietnam Airlines, Vietjet Air | SMS mạo danh hãng bay | Báo chuyến bay bị hủy gấp, dẫn link bồi thường hoặc tổng đài cước cao nhằm chiếm đoạt tài khoản. |
| **`R-TAX-001`** | Hoàn thuế / Quyết toán thuế TNCN | Tổng cục Thuế / Chi cục Thuế | SMS / Email giả mạo | Yêu cầu cập nhật định danh thuế qua link `gdt.gov-portal.com` để cài mã độc. |
| **`R-EXT-001`** | Tống tiền Deepfake hình ảnh nhạy cảm | Nhóm tống tiền nặc danh | SMS / Telegram | Dọa phát tán clip cắt ghép khuôn mặt nhạy cảm đến gia đình nếu không nộp tiền chuộc. |
| **`R-INVEST-001`** | Lừa đầu tư Forex / Tiền ảo bao lỗ | Sàn giao dịch quốc tế giả | SMS mời gọi / Zalo nhóm | Cam kết lợi nhuận 30-50%/ngày, cho rút lãi nhỏ ban đầu rồi chặn rút bắt đóng phí. |
| **`R-REFUND-001`** | Lừa hoàn tiền giao dịch TMĐT | Shopee, Lazada, TikTok Shop | SMS CSKH / Zalo | Giả vờ hoàn tiền đơn hàng bị lỗi, gửi link phishing để chiếm thông tin thẻ/OTP. |
| **`R-COD-001`** | Lừa giao hàng COD khống | Shipper giả mạo / Bưu cục | SMS giao hàng + Call | Báo có kiện hàng giá trị 0đ nhưng thu hộ COD 100k-300k, nạn nhân thanh toán nhận đồ vô giá trị. |
| **`R-RECOVER-001`**| Lừa "hỗ trợ thu hồi nợ/tiền treo" | "Văn phòng Luật sư", "An ninh mạng" | SMS / Fanpage | Cam kết lấy lại tiền lừa đảo đã mất với tỷ lệ 100%, yêu cầu nộp trước "phí pháp lý". |
| **`R-CHARITY-001`**| Kêu gọi từ thiện cứu trợ bão lũ giả | Quỹ thiện nguyện / Mặt trận Tổ quốc | SMS / Mạng xã hội | Sử dụng số tài khoản cá nhân có tên gần giống quỹ cứu trợ để trục lợi thời điểm thiên tai. |
| **`R-LOAN-TRAP-001`**| Bẫy chuyển nhầm tiền ép vay nặng lãi | Nhóm tín dụng đen | Chuyển khoản ngân hàng | Chuyển nhầm tiền vào tài khoản nạn nhân rồi đòi nợ với lãi suất cắt cổ, đe dọa khủng bố. |
| **`R-RECRUIT-001`**| Tuyển dụng việc làm Remote lương cao | Tập đoàn quốc tế / Sàn TMĐT | SMS quảng cáo tuyển dụng | Tuyển làm việc tại nhà thu nhập 1-2tr/ngày, bắt làm nhiệm vụ nạp tiền nâng cấp cấp bậc. |
| **`R-SCH-001`** | Giả mạo trường học nộp học phí | Phòng Tài chính / Nhà trường | SMS thông báo trường | Gửi thông báo nộp học phí gấp qua STK cá nhân giả mạo để chiếm đoạt tiền phụ huynh. |
| **`R-BHXH-001`** | Lừa trợ cấp BHXH / BHYT giả | Bảo hiểm Xã hội Việt Nam | SMS mạo danh cơ quan | Báo có khoản trợ cấp thai sản/thất nghiệp cần lĩnh qua link web giả mạo lấy OTP. |

---

## 4. Các tài liệu & File Dữ liệu Đã Cập Nhật

Hệ thống tài liệu và dữ liệu đã được cập nhật trực tiếp tại chỗ theo đúng quy tắc ưu tiên:

1. **Catalog & Kiểm kê Baseline:**
   - [`docs/existing_36_scenarios_inventory.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/existing_36_scenarios_inventory.md): Kiểm kê 13 trường của 36 kịch bản gốc.
2. **Nguồn Tham chiếu & Chứng cứ:**
   - [`docs/scam_scenario_research_sources.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/scam_scenario_research_sources.md): 18 nguồn điều tra chính thống của Bộ Công an, EVN, Cục Viễn thông, BHXH...
3. **Danh mục Ứng viên Chi tiết:**
   - [`docs/new_scam_scenario_candidates.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/new_scam_scenario_candidates.md): 24 hồ sơ ứng viên với đầy đủ 16 thuộc tính.
4. **Báo cáo Chống trùng lặp (Deduplication):**
   - [`docs/scam_scenario_deduplication_report.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/scam_scenario_deduplication_report.md): 7 tiêu chí đánh giá, kết quả phân bổ (17 ADD, 3 VARIANT, 1 REFINE, 1 MERGE, 2 RESEARCH_MORE).
5. **Ma trận Bao phủ Đa chiều:**
   - [`docs/scam_scenario_coverage_matrix.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/scam_scenario_coverage_matrix.md): Phân tích 8 chiều (Victims, Targets, Channels, Psych Tactics, Stages, Geography, Technology, Source Tiers).
   - [`docs/MECE_Coverage_Matrix.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/MECE_Coverage_Matrix.md): Cập nhật Taxonomy từ 7 lên 13 phân nhóm toàn diện.
6. **Bộ Dữ liệu Rule Engine Mở rộng:**
   - [`data/scam_scenario_expansion_dataset.json`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/data/scam_scenario_expansion_dataset.json): 17 AST rules theo đúng format production kèm 68 mẫu synthetic SMS.
7. **Bổ sung Từ khóa & Tín hiệu Rủi ro:**
   - [`scam_keywords_patterns.csv`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/scam_keywords_patterns.csv): Bổ sung 52 từ khóa, teencode, biến thể ngắt âm, unaccented, và regex.
   - [`scam_risk_signals.csv`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/scam_risk_signals.csv): Bổ sung 19 tín hiệu rủi ro chuyên sâu.
   - [`docs/sms_examples_inventory.md`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/sms_examples_inventory.md): Bổ sung 17 mẫu SMS mở rộng chuyên sâu.

---

## 5. Đánh giá Rủi ro Nhận diện nhầm (False Positive) & Khoảng trống Kỹ thuật (Residual Gaps)

### 5.1. Kiểm soát False Positive (FP)
- **Từ khóa thông thường (Common words):** Các từ khóa mang tính hành chính như `điện lực`, `thuế`, `học phí`, `vé máy bay` được thiết kế đi kèm với các toán tử ngữ cảnh bắt buộc (ví dụ: `cutoff_threat`, `emergency_phone_action`, `apk_domain`, `fee_upfront`) thay vì khớp độc lập một từ đơn lẻ.
- **Tách biệt Brandname chính thức:** Không cảnh báo nếu SMS xuất phát từ các Brandname đã xác thực và không chứa link rút gọn khả nghi hoặc số điện thoại lạ thúc ép chuyển khoản khẩn cấp.

### 5.2. Khoảng trống Kỹ thuật Ngoài Phạm vi SMS (Residual Gaps)
1. **Lừa đảo bằng giọng nói thời gian thực (Real-time Deepfake Audio):** Kẻ gian gọi video giả mạo người thân gặp nạn bằng công nghệ deepfake. Kênh SMS chỉ là bước mào đầu dẫn dụ hoặc xác nhận giao dịch.
2. **Tên miền `.vn` mới đăng ký trong vòng 24 giờ:** Kẻ gian mua tên miền có đuôi `.vn` thật của các nhà đăng ký trong nước để giả mạo cổng thông tin hành chính công, dễ qua mặt các bộ lọc blacklist tĩnh nếu chưa được tích hợp Threat Intel thời gian thực.
3. **Mã hóa đầu cuối OTT (Zalo, Telegram, WhatsApp):** Cuộc trao đổi chi tiết sau bước mồi SMS thường diễn ra trên các app nhắn tin bí mật, đòi hỏi giải pháp mở rộng sang client-side scanner trên mobile thay vì chỉ lọc tại gateway SMS.

---

## 6. Kết luận & Khuyến nghị Triển khai

1. **Sẵn sàng Tích hợp (Production Ready):** Toàn bộ 17 rule trong [`data/scam_scenario_expansion_dataset.json`](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/data/scam_scenario_expansion_dataset.json) đã được chuẩn hóa AST 100%, sẵn sàng cho đội ngũ kỹ sư nạp vào Rule Engine mà không cần chỉnh sửa cú pháp.
2. **Khuyến nghị Kiểm thử Tự động:** Thực thi suite kiểm thử hồi quy đối chiếu tập 68 mẫu tin nhắn mở rộng để đo lường độ chính xác (Precision/Recall) trước khi deploy bản cập nhật chính thức lên môi trường production.
