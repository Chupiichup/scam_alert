# Ma Trận Đầy Đủ & Không Chồng Lặp (MECE Coverage Matrix)
## Đánh Giá Toàn Diện Hệ Thống Phát Hiện & Cảnh Báo Scam

> **Nguyên tắc MECE:** Phân loại theo các trục độc lập, tiêu chí phân định rõ ràng (Mutually Exclusive) và bao quát toàn bộ không gian vấn đề (Collectively Exhaustive). Tuyệt đối không gộp chung các trục phân tích khác bản chất.

---

## 1. Trục 1: MECE Theo Kịch Bản Tấn Công (Threat Scenarios Taxonomy)

* **Tiêu chí phân chia (Partition Rule):** Phân loại theo **Thủ đoạn tâm lý cốt lõi (Psychological Leverage)** và **Loại danh tính bị mạo danh (Claimed Identity)**.
* **Quy tắc giải quyết giao nhau:** Nếu một tin nhắn vừa giả danh vừa đòi OTP, danh tính giả mạo là `Category`, còn hành vi đòi OTP là `Technical Signal`.

| Mã Nhóm (Taxonomy) | Định nghĩa & Tiêu chí phân định | Thành phần hiện tại hỗ trợ | Trạng thái (Coverage) | Điểm chồng lặp (Overlap) | Khoảng trống (Gap) | Bằng chứng (Repo Evidence) | Hành động tiếp theo (Next Action) |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **`BANK_FINANCIAL_IMPERSONATION`** | Mạo danh Ngân hàng, Ví điện tử, Tổ chức tín dụng; dọa khóa tài khoản/thẻ, yêu cầu OTP/sinh trắc học. | `R-BNK-001`, `R-BNK-002`, `scam_url_domain_indicators.csv` | **100% Bao phủ** | Có thể trùng với `MALICIOUS_DOMAIN` nếu link là giả mạo. | Chưa bao quát trường hợp trạm BTS giả phát tán SMS không dấu lách toàn bộ từ khóa. | `test_rule_engine.js:L132-L133`, TC-BNK-001/002/005 | Duy trì, định kỳ cập nhật tên miền ngân hàng mới. |
| **`GOV_LEGAL_COERCION`** | Mạo danh Công an, CSGT, Tòa án, Viện kiểm sát; dọa phạt nguội, bắt tạm giam, thu hồi sổ đỏ đất đai. | `R-POL-001`, `R-POL-002`, `R-GOV-003`, `PAT_VN_POLICE_FINE_THREAT` | **100% Bao phủ** | Trùng với `APK_DOWNLOAD_LINK` khi đối tượng gửi link tải app giả mạo. | Kẻ lừa đảo không nhắn SMS mà gọi điện thoại trực tiếp dọa dẫm rồi kết bạn Zalo. | `test_rule_engine.js:L134, L140`, TC-POL-001/002/004, TC-GOV-005/006 | Mở rộng tính năng On-Device OCR chụp màn hình Zalo. |
| **`SOCIAL_RELATIONSHIP_HIJACK`** | Chiếm đoạt tài khoản người thân (Zalo, FB) hoặc mạo danh đổi số mới; viện cớ cấp cứu, tai nạn để mượn tiền gấp. | `R-REL-001`, `R-CONV-001` (Stateful Engine), `PAT_VN_RELATIVE_BORROW` | **85% Bao phủ** | Trùng với `URGENT_MONEY_TRANSFER` khi có kèm STK ngân hàng. | Deepfake âm thanh/hình ảnh khi người già gọi điện xác minh lại bằng Zalo. | `test_rule_engine.js:L135, L147-L215`, TC-REL-001/002 | Bắt buộc cảnh báo người dùng: *Gọi điện thoại thường (SIM), không gọi qua Zalo/FB*. |
| **`JOB_INVESTMENT_LURE`** | Bẫy việc nhẹ lương cao, cộng tác viên giật đơn Shopee/TikTok, quỹ đầu tư cam kết lợi nhuận khủng. | `R-JOB-001`, `PAT_VN_TASK_JOB_OFFER` | **90% Bao phủ** | Trùng với `REDIRECT_TO_CHAT` khi tin nhắn dẫn dụ vào nhóm Telegram. | Các tin nhắn tuyển dụng sử dụng từ ngữ biến thể không có chữ "CTV", "lương". | `test_rule_engine.js:L136`, TC-JOB-001/002 | Thêm toán tử ngữ nghĩa Semantic Embedding nhẹ trên máy. |
| **`RECOVERY_FEE_EXTORTION`** | Mạo danh Luật sư, Cục An ninh mạng cam kết lấy lại tiền đã mất, yêu cầu nộp phí thụ lý/giải ngân trước. | `R-RCV-001`, `PAT_VN_RECOVERY_FEE` | **95% Bao phủ** | Trùng với `GOV_IMPERSONATION` nếu kẻ lừa đảo mạo danh Cục An ninh mạng. | Chưa phát hiện nếu đối tượng tiếp cận qua mục bình luận (Comment) mạng xã hội. | `test_rule_engine.js:L137`, TC-RCV-001/002 | Khuyến cáo phòng ngừa thứ cấp cho nạn nhân từng bị lừa. |
| **`E_COMMERCE_LOGISTICS_SCAM`** | Giả mạo giao hàng trúng thưởng, bưu tá giao đơn hàng 0 đồng đòi chuyển khoản cọc. | **CHƯA CÓ RULE RIÊNG** (đang xếp vào UNKNOWN) | **30% (Thiếu sót)** | Dễ nhầm với tin nhắn thông báo giao hàng hợp pháp (`TC-JOB-003`). | Kẻ lừa đảo gửi SMS bưu tá giao hàng kèm link xác nhận đơn. | Chưa có `R-LOG-001` trong `scam_detection_rules.json`. | **CẦN BỔ SUNG RULE:** `R-LOG-001` (Giao hàng COD + link lạ + đòi chuyển khoản). |
| **`LOTTERY_GIFT_REWARD`** | Thông báo trúng thưởng xe máy, sổ tiết kiệm, yêu cầu chuyển phí vận chuyển / thuế trước. | **CHƯA CÓ RULE RIÊNG** (đang xếp vào UNKNOWN) | **40% (Thiếu sót)** | Dễ nhầm với tin quảng cáo khuyến mãi hợp pháp. | Tin nhắn dạng "Chuc mung thue bao trung thuong SH...". | Chưa có pattern riêng cho trúng thưởng viễn thông. | **CẦN BỔ SUNG PATTERN:** `PAT_VN_LOTTERY_REWARD`. |

---

## 2. Trục 2: MECE Theo Vòng Đời Tấn Công (Attack Lifecycle Taxonomy)

* **Tiêu chí phân chia:** Theo thời điểm tác động trong chuỗi hành vi của kẻ gian: $\text{Reconnaissance} \to \text{Contact} \to \text{Manipulation} \to \text{Action} \to \text{Exfiltration} \to \text{Secondary Victimization}$.

| Giai đoạn Vòng đời | Mục tiêu của kẻ gian | Khả năng can thiệp của App hiện tại | Trạng thái bảo vệ | Điểm mù (Blind Spot) | Đơn vị/Giải pháp phù hợp hơn |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. Tiếp cận (Contact)** | Gửi SMS, tin nhắn OTT hoặc gọi điện đến số người già. | Phân tích nội dung SMS/ảnh chụp màn hình khi tin nhắn xuất hiện. | **BẢO VỆ TỐT (SMS)** | Hoàn toàn không chặn được cuộc gọi thoại (Voice Call) hoặc tin nhắn OTT riêng tư nếu người dùng không chụp ảnh. | Nhà mạng viễn thông (Chặn BTS giả, lọc SMS rác ở tầng mạng). |
| **2. Thao túng tâm lý (Manipulation)** | Tạo sự hoảng sợ (khóa tài khoản, lệnh bắt) hoặc lòng tham (lợi nhuận). | Hiển thị cảnh báo giải thích rõ bản chất thủ đoạn: "Công an không gửi SMS". | **BẢO VỆ TỐT NHẤT** | Người dùng bị kẻ xấu gọi điện thúc ép song song khiến họ không kịp nhìn màn hình app. | Bản thân người dùng & Thiết kế UI tạo "Moment of Pause" gián đoạn cảm xúc. |
| **3. Dẫn kênh (Channel Shift)** | Kéo nạn nhân từ SMS sang Zalo, Telegram bí mật hoặc link web giả. | Bóc tách URL, kiểm tra đuôi APK, nhận diện domain độc hại NCSC. | **BẢO VỆ TỐT** | Kẻ gian đọc số điện thoại qua cuộc gọi bảo người già tự kết bạn Zalo. | Trình duyệt Web (Google Safe Browsing), Zalo (cảnh báo link lạ). |
| **4. Thu thập dữ liệu (Harvesting)** | Lừa người già nhập mật khẩu, mã OTP hoặc tải APK chiếm quyền trợ năng. | Cảnh báo đỏ toàn màn hình (HIGH + CRITICAL), kích hoạt Family Escalation. | **BẢO VỆ TRUNG BÌNH** | App hiện tại chưa có quyền can thiệp vào bàn phím hay chặn trình duyệt mở URL. | Hệ điều hành Android/iOS (Accessibility Lock, App Sandbox). |
| **5. Thực hiện giao dịch (Action)** | Nạn nhân ra ngân hàng hoặc mở App Mobile Banking chuyển tiền tiết kiệm. | Không thể can thiệp trực tiếp vào ứng dụng ngân hàng của người dùng. | **KHÔNG BẢO VỆ ĐƯỢC** | Khoảnh khắc người dùng bấm nút "Chuyển tiền" trong app ngân hàng. | **Ngân hàng & Sinh trắc học** (QĐ 2345/QĐ-NHNN, giới hạn hạn mức chuyển tiền). |
| **6. Khai thác tiếp diễn (Re-victimization)** | Giả danh luật sư/công an thu hồi vốn để lừa thêm lần 2. | Bắt bài kịch bản thu hồi vốn nhờ Rule `R-RCV-001`. | **BẢO VỆ TỐT** | Nạn nhân giấu gia đình vì xấu hổ, tự tìm kiếm trên Google/Facebook. | Mạng xã hội, Tổ chức bảo vệ cộng đồng, Tư vấn tâm lý gia đình. |

---

## 3. Trục 3: MECE Theo Nguồn Tín Hiệu Nhận Diện (Detection Signals Taxonomy)

* **Tiêu chí phân chia:** Theo tính chất vật lý và nguồn gốc của dữ liệu được thu nhận.

| Nhóm Tín Hiệu | Nguồn gốc dữ liệu | Tín hiệu cụ thể trong hệ thống | Độ độc lập | Nguy cơ đếm trùng (Correlation Risk) | Cơ chế triệt tiêu hiện tại |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **1. Lexical / Keyword** | Từ ngữ, cụm từ thô | `CONTAINS_ANY_KEYWORD` (OTP, Vietcombank, CSGT) | Thấp (phụ thuộc ngữ cảnh) | **Rất cao** (Cùng xuất hiện trong 1 câu lừa đảo) | Đã gom vào `GRP_CREDENTIAL_THEFT` / `GRP_IMPERSONATION`. |
| **2. Structural / Regex** | Cấu trúc câu, mẫu hành văn | `MATCHES_PATTERN`, `REGEX_DISTANCE` | Trung bình | **Cao** nếu pattern bắt cùng ý đồ với keyword | Áp dụng Decay 50% cho tín hiệu thứ 2 cùng nhóm. |
| **3. Threat Intel (URL/Domain)** | Danh sách đen đã xác thực | `scam_url_domain_indicators.csv`, NCSC Sync | **Rất cao** (Chứng cứ cứng) | **Thấp** (Domain độc hại là bằng chứng độc lập) | Tính điểm độc lập +45.0đ (`FAKE_BRAND_DOMAIN`). |
| **4. Identity / Sender** | Đầu số gửi, Brandname viễn thông | `scam_sender_indicators.csv` (Brandname vs Số rác) | **Rất cao** (Metadata ngoài nội dung) | **Thấp** | Tín hiệu `SUSPICIOUS_SENDER_FOR_AUTHORITY` (+30đ). |
| **5. Behavioral / Intent** | Hành vi tin nhắn thúc ép thực hiện | Đòi chuyển tiền (`URGENT_MONEY_TRANSFER_REQUEST`), Đòi OTP | Cao | **Trung bình** | Xếp vào nhóm `GRP_FINANCIAL_ACTION`. |
| **6. Contextual / Temporal** | Lịch sử tương tác đa ngày | `ConversationStore` (chuỗi 3 ngày, rolling score) | **Rất cao** (Trục thời gian) | **Thấp** | Tín hiệu `MULTI_DAY_CONVERSATION_TRAP` (+40đ). |
| **7. Negative Evidence** | Dấu hiệu an toàn chính hãng | `OFFICIAL_SECURITY_WARNING_PRESENT` | **Độc lập hoàn toàn** | Không | Chiết khấu âm trực tiếp: **-40.0 điểm** (`GRP_BENIGN_DISCOUNT`). |

---

## 4. Trục 4: MECE Theo Các Chế Độ Hỏng Hóc (Failure Modes Taxonomy)

* **Tiêu chí phân chia:** Theo nguồn gốc của lỗi: $\text{Thuật toán} \to \text{Dữ liệu} \to \text{Hệ thống/Kỹ thuật} \to \text{Con người/Xã hội}$.

| Chế độ hỏng (Failure Mode) | Định nghĩa cụ thể | Mức độ rủi ro | Khả năng phát hiện (Detectability) | Hậu quả thực tế đối với người già | Giải pháp kiểm soát hiện tại | Biện pháp giảm thiểu bổ sung (Mitigation) |
| :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **FM-1: False Negative (Bỏ sót)** | Tin nhắn lừa đảo tinh vi không khớp bất kỳ rule nào $\to$ Gán nhãn `LOW`. | **CRITICAL** | Khó phát hiện ngay lập tức | Nạn nhân tin tưởng tuyệt đối vào app $\to$ Mất tiền. | Kiểm tra URL lạ để gán nhãn `UNKNOWN` (không cho về LOW nếu có link lạ). | Bổ sung fallback: Cứ có URL không nằm trong Whitelist $\to$ Tối thiểu `UNKNOWN`. |
| **FM-2: False Positive (Báo nhầm)** | Tin nhắn biến động số dư / OTP thật của ngân hàng bị báo đỏ `HIGH`. | **HIGH** | Dễ phát hiện (Người dùng khiếu nại) | Nạn nhân hoang mang, mất niềm tin, tắt thông báo hoặc gỡ app. | Rule `R-SAFE-001` trừ 40 điểm cho khuyến cáo bảo mật chính thức. | Mở rộng Whitelist cho Brandname ngân hàng và cơ quan nhà nước đã xác thực. |
| **FM-3: Alert Fatigue (Mệt mỏi cảnh báo)** | Quá nhiều cảnh báo vàng/xám `UNKNOWN` cho tin nhắn thông thường. | **MEDIUM** | Đo qua tỷ lệ CTR và tỷ lệ bỏ qua cảnh báo | Người già hình thành phản xạ bấm "Bỏ qua" trong vô thức mà không đọc. | Chỉ hiện thông báo toàn màn hình cho mức `HIGH`; mức `UNKNOWN` chỉ hiển thị thẻ phụ. | Tối ưu ngưỡng điểm: Chỉ hiển thị thẻ cảnh báo khi Score $\ge 25$. |
| **FM-4: Adversarial Evasion** | Kẻ gian dùng ký tự lạ (homoglyph, icon, chèn link ẩn) để né Regex. | **HIGH** | Khó phát hiện nếu không có telemetry | Bộ lọc Regex bị vô hiệu hóa hoàn toàn. | Hàm `removeVietnameseTones()` bóc tách ký tự trắng và teencode. | Thêm bộ giải mã Unicode Normalization (NFKD) và phát hiện ký tự tương đồng Cyrillic. |
| **FM-5: System Disablement** | Ứng dụng Android bị hệ điều hành tắt chạy ngầm do tiết kiệm pin. | **HIGH** | Client không gửi được heartbeat | Tin nhắn đến nhưng app không quét, không hiện cảnh báo. | Chưa có cơ chế bảo đảm (hiện tại mới là Web Simulator). | Đăng ký dịch vụ Foreground Service trên Android với quyền ưu tiên pin (Battery Whitelist). |
| **FM-6: Social Engineering Bypass** | Kẻ gian gọi điện bảo nạn nhân: *"Đó là phần mềm lỗi, bác bấm bỏ qua đi"*. | **CRITICAL** | Không thể phát hiện qua code | Nạn nhân tự tay tắt cảnh báo và làm theo hướng dẫn của kẻ xấu. | Thiết kế cảnh báo đính kèm câu khẳng định: "Công an không bao giờ bảo bác tắt cảnh báo này". | **Cơ chế Escalation khẩn cấp:** Gửi SMS cho con cái bất chấp người già bấm nút "Bỏ qua". |
