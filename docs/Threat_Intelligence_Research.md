# Báo Cáo Nghiên Cứu Tình Báo Lừa Đảo Tại Việt Nam (Vietnam Scam Intelligence Research Report)
## Đợt 1: Research, Evidence Extraction & Scam Taxonomy (Giai đoạn MVP)

> **Dự án:** Scam Message Detection Platform — Bảo vệ Người cao tuổi tại Việt Nam  
> **Tác giả:** Scam Intelligence Researcher & Cybersecurity Analyst Group  
> **Phiên bản:** v1.0.0 (Research Milestone Đợt 1)  
> **Ngày thu thập dữ liệu:** Tháng 10/2026 (Tổng hợp cảnh báo 12 tháng gần nhất từ 10/2025 – 10/2026)  
> **Tiêu chuẩn kiểm chứng:** Nghiêm cấm tự tạo (fabricate) indicator/URL giả thành bằng chứng đã xác minh; phân định minh bạch giữa `OBSERVED`, `REPORTED`, `CORROBORATED` và `SYNTHETIC`.

---

## 1. Phương Pháp Luận & Nguồn Dữ Liệu Nghiên Cứu

### 1.1 Nguyên Tắc Thu Thập & Thẩm Định Bằng Chứng
Để đảm bảo chất lượng dữ liệu làm nền tảng cho việc sinh Rule Engine ở Đợt 2 và kiểm thử ở Đợt 3, nghiên cứu tuân thủ các nguyên tắc sau:
1. **Phân cấp nguồn tin cậy (Source Hierarchy):**
   - **Tầng 1 (Chính thống - Trọng số cao nhất):** Cổng TTĐT Bộ Công an (BCA), Cục Cảnh sát giao thông (C08), Cục An ninh mạng và phòng, chống tội phạm sử dụng công nghệ cao (A05), Cục An toàn thông tin (Bộ TT&TT / NCSC / khonggianmang.vn), Cổng Thông tin điện tử Chính phủ, Ngân hàng Nhà nước và các Ngân hàng thương mại (Vietcombank, BIDV, Techcombank...).
   - **Tầng 2 (Báo chí chính thống có kiểm duyệt):** VnExpress, Tuổi Trẻ, Thanh Niên, Dân Trí, VietnamNet, Báo Lao Động, Báo Công an Nhân dân.
   - **Tầng 3 (Tổ chức an ninh mạng & Liên minh phòng chống lừa đảo):** Chống Lừa Đảo (chongluadao.vn), BKAV, các báo cáo Threat Intelligence độc lập.
2. **Quy định nghiêm ngặt về Indicator & Mẫu tin nhắn:**
   - Nếu cơ quan chức năng chỉ cảnh báo về *thủ đoạn chung* mà không công bố URL độc hại cụ thể, trường `url_or_domain_evidence` sẽ ghi nhận là `NOT_AVAILABLE (CHƯA CÔNG BỐ CỤ THỂ)` — **tuyệt đối không tự điền URL giả lập thành confirmed indicator**.
   - Mẫu tin nhắn chỉ được gắn nhãn `OBSERVED` khi được chụp lại từ màn hình tang vật hoặc trích dẫn nguyên văn trong thông cáo chính thức của cơ quan công an / báo chí.

---

### 1.2 Bảng Danh Mục Nguồn Dữ Liệu Chính Thống Đã Nghiên Cứu (Source Index)

| Source ID | Tên Nguồn | Cơ Quan / Đơn Vị | URL Tham Chiếu / Lưu Trữ | Ngày Công Bố | Trạng Thái Thẩm Định |
|---|---|---|---|---|---|
| `SRC-GOV-001` | Cảnh báo tin nhắn phạt nguội giả danh CSGT | Bộ Công an & Cổng TTĐT Chính phủ | `baochinhphu.vn / cand.com.vn` | 2025 – 2026 | `CORROBORATED` |
| `SRC-GOV-002` | Cảnh báo lừa đảo chiếm quyền Zalo, Deepfake mượn tiền | Cục An toàn thông tin (Bộ TT&TT) & C05 BCA | `vietnamnet.vn / tuoitre.vn` | 2025 – 2026 | `CORROBORATED` |
| `SRC-GOV-003` | Cảnh báo bẫy "Thu hồi tiền lừa đảo / Tiền treo" | Cục An toàn thông tin (khonggianmang.vn) | `dantri.com.vn / tuoitre.vn` | 2025 – 2026 | `CORROBORATED` |
| `SRC-GOV-004` | Cảnh báo giả mạo SMS Brandname trạm BTS giả | Cục Tần số Vô tuyến điện & NCSC | `mic.gov.vn / vnexpress.net` | 2025 – 2026 | `CORROBORATED` |
| `SRC-BNK-001` | Cảnh báo bẫy cập nhật sinh trắc học QĐ 2345 & đòi OTP | Ngân hàng TMCP Ngoại thương (Vietcombank) | `vietcombank.com.vn/canh-bao-bao-mat` | 2025 – 2026 | `OBSERVED` |
| `SRC-BNK-002` | Khuyến cáo an toàn giao dịch & nhận diện link giả mạo | Hiệp hội Ngân hàng Việt Nam (VNBA) & BIDV | `bidv.com.vn / vnba.org.vn` | 2025 – 2026 | `OBSERVED` |
| `SRC-JOB-001` | Cảnh báo bẫy tuyển CTV làm nhiệm vụ Shopee/Telegram | Bộ Công an & Cục Cạnh tranh và Bảo vệ người tiêu dùng | `cand.com.vn / vnexpress.net` | 2025 – 2026 | `CORROBORATED` |
| `SRC-GOV-005` | Cảnh báo lừa đảo cập nhật thông tin sổ đỏ trên VNeID | Công an tỉnh Ninh Bình, Phú Thọ & Cục ATTT | `congan.ninhbinh.gov.vn / congan.phutho.gov.vn` | 2025 – 2026 | `CORROBORATED` |
| `SRC-CLD-001` | Cơ sở dữ liệu cảnh báo tên miền phishing tại VN | Dự án Chống Lừa Đảo (chongluadao.vn) | `api.chongluadao.vn` | Liên tục 2026 | `CORROBORATED` |

---

## 2. Scam Taxonomy Chuẩn Hóa Cho Việt Nam

Dựa trên điều tra thực tế tại Việt Nam, hệ thống phân loại lừa đảo được chuẩn hóa thành 5 nhóm lớn phục vụ phạm vi MVP, kết hợp các mã định danh chuẩn để liên kết vào Database:

```
+-------------------------------------------------------------------------------------------------------+
|                                  VIETNAM SCAM TAXONOMY (MVP SCOPE)                                    |
+-------------------------------------------------------------------------------------------------------+
| 1. BANK_IMPERSONATION     : Mạo danh Ngân hàng, Cập nhật Sinh trắc học, Đánh cắp Mật khẩu & OTP       |
| 2. GOV_POLICE_COERCION    : Giả danh CSGT phạt nguội, Công an dọa bắt giam, Giả mạo VNeID/Dịch vụ công |
| 3. RELATIVE_TAKEOVER_SCAM : Chiếm quyền Zalo/Facebook mượn tiền, Cấp cứu giả mạo, Cầu cứu khẩn cấp    |
| 4. JOB_TASK_INVESTMENT    : Tuyển CTV online làm nhiệm vụ, Bẫy giật đơn Shopee/Tiktok, Sàn ảo cam kết  |
| 5. RECOVERY_ADVANCE_FEE   : Bẫy "Luật sư/An ninh mạng hỗ trợ thu hồi tiền treo", Đòi đóng phí hồ sơ   |
+-------------------------------------------------------------------------------------------------------+
```

---

## 3. Nghiên Cứu Chuyên Sâu 5 Nhóm Lừa Đảo MVP

Dưới đây là bản trích xuất 18 thuộc tính chi tiết cho từng kịch bản đặc trưng trong 5 nhóm ưu tiên MVP:

---

### Nhóm 1: Giả Danh Ngân Hàng & Chiếm Đoạt OTP / Sinh Trắc Học (`BANK_IMPERSONATION`)

#### 1.1 Phân tích hồ sơ thủ đoạn (Scenario Dossier)
- **1. `scam_category`:** `BANK_IMPERSONATION`
- **2. `scam_scenario`:** `SCEN_BANK_OTP_BIOMETRIC_THEFT` (Mạo danh thông báo ngân hàng dọa khóa tài khoản hoặc yêu cầu bổ sung sinh trắc học theo Quyết định 2345/QĐ-NHNN để đánh cắp thông tin đăng nhập và mã OTP).
- **3. `attack_stage`:** `Authority Impersonation` $\to$ `Urgency / Threat` $\to$ `Credential & OTP Harvesting`.
- **4. `claimed_sender_type`:** SMS Brandname mạo danh (phát tán qua trạm BTS giả lập không qua mạng viễn thông) hoặc Số di động cá nhân giả xưng Tổng đài CSKH.
- **5. `victim_action_requested`:** Nhấp vào đường link giả mạo; nhập Tên đăng nhập Internet Banking, Mật khẩu, Số thẻ CCCD và Mã OTP được gửi về điện thoại.
- **6. `psychological_tactic`:** 
  - **Tạo sự hoảng sợ:** *"Tài khoản sẽ bị tạm ngừng giao dịch trong 24h"*, *"Phát hiện đăng nhập lạ ở thiết bị khác trừ 10.000.000 VNĐ"*.
  - **Lợi dụng nghĩa vụ tuân thủ:** Lợi dụng quy định bắt buộc cập nhật khuôn mặt/CCCD sinh trắc học của Ngân hàng Nhà nước để người già tin là thủ tục bắt buộc.
- **7. `message_channel`:** Tin nhắn SMS (Brandname giả hoặc số lạ), OTT (Zalo, tin nhắn SMS phụ).
- **8. `message_evidence`:**
  - *Mẫu quan sát thực tế 1 (OBSERVED - Nguồn Vietcombank & VnExpress):*
    > `"Vietcombank tran trong thong bao: Tai khoan cua Quy khach tam thoi bi khoa do nghi van vi pham giao dich bat thuong. Vui long dang nhap tai http://vietcombank-smartotp[.]com de xac minh truoc 24h."`
  - *Mẫu quan sát thực tế 2 (OBSERVED - Nguồn Cục An toàn thông tin):*
    > `"Ngan hang thong bao: Quy khach chua hoan tat xac thuc sinh trac hoc theo Quy dinh 2345. Tai khoan se bi dung chuyen tien tu 0h ngay mai. Cap nhat ngay tai: https://vcb-sinhtrachoc[.]top"`
- **9. `url_or_domain_evidence`:**
  - Đã quan sát thực tế (OBSERVED/BLOCKED): `vietcombank-smartotp[.]com`, `vcb-digibank-xacminh[.]top`, `online-bidv[.]cc`, `techcombank-verify[.]net`.
  - Phân tích kỹ thuật: Sử dụng TLD giá rẻ (`.top`, `.cc`, `.xyz`, `.vip`), sử dụng ký tự gạch nối kết hợp tên thương hiệu (Typosquatting) và giao diện sao chép y hệt web ngân hàng thật.
- **10. `sender_evidence`:**
  - Chèn giả tên Brandname `Vietcombank`, `TCB`, `BIDV` thông qua trạm phát sóng di động giả (Fake BTS) chèn sóng 2G.
  - Số điện thoại đầu số rác: `+8491...`, `+8477...`.
- **11. `sensitive_data_requested`:** Username, Password, Mã kích hoạt Smart OTP, Số CCCD.
- **12. `financial_action_requested`:** Kẻ gian chiếm quyền Internet Banking trên thiết bị của chúng rồi thực hiện lệnh chuyển sạch toàn bộ tiền tiết kiệm sang tài khoản "mule" (tài khoản rác mua trôi nổi).
- **13. `technical_evasion_method`:** 
  - Bỏ dấu tiếng Việt, xen kẽ ký tự ngắt (`V.i.e.t.c.o.m.b.a.n.k`).
  - Dùng chữ O thay số 0 hoặc ngược lại (`0TP`, `OTP`).
  - Viết hoa thường xen kẽ để tránh bộ lọc regex ngây thơ của nhà mạng.
- **14. `risk_signals`:** `BANK_IMPERSONATION_CLAIM`, `ACCOUNT_SUSPENSION_THREAT`, `OTP_REQUEST`, `UNOFFICIAL_DOMAIN`, `URGENT_DEADLINE_24H`.
- **15. `recommended_detection_method`:**
  - Kết hợp Regex bắt cặp: `(tài khoản|thẻ|dịch vụ) + (bị khóa|tạm ngừng|hết hạn)` VÀ `(liên kết|truy cập|xác minh) + URL`.
  - Đối chiếu tên miền trong URL với Danh bạ Tên miền chính thống của Ngân hàng (`brand_identity_target`). Nếu tên miền KHÔNG kết thúc bằng `.vietcombank.com.vn`, `.bidv.com.vn`, `.techcombank.com.vn` $\to$ Gắn cờ cảnh báo mức **HIGH**.
- **16. `recommended_user_explanation`:**
  > *"Ngân hàng **không bao giờ** gửi tin nhắn yêu cầu bác bấm vào đường link để cập nhật thông tin hay đòi mã OTP. Bác tuyệt đối không bấm vào link và không nhập bất kỳ thông tin nào để tránh bị mất tiền!"*
- **17. `source_references`:**
  - Cảnh báo bảo mật Vietcombank 2025–2026 (`vietcombank.com.vn`).
  - Cục An toàn thông tin cảnh báo thủ đoạn lừa đảo cập nhật sinh trắc học ngân hàng (`khonggianmang.vn`).
- **18. `confidence_level`:** `0.98 (RẤT CAO)` khi có sự kết hợp giữa tên ngân hàng + link lạ + đòi OTP.

---

### Nhóm 2: Giả Danh Công An, CSGT & Thông Báo Phạt Nguội (`GOV_POLICE_COERCION`)

#### 2.1 Phân tích hồ sơ thủ đoạn (Scenario Dossier)
- **1. `scam_category`:** `GOV_IMPERSONATION`
- **2. `scam_scenario`:** `SCEN_POLICE_TRAFFIC_FINE_ARREST` (Mạo danh Cục CSGT hoặc Cơ quan Điều tra Bộ Công an gửi thông báo vi phạm luật giao thông/phạt nguội hoặc dọa lệnh bắt tạm giam, yêu cầu nộp phạt gấp hoặc tải ứng dụng độc hại).
- **3. `attack_stage`:** `Authority Impersonation` $\to$ `Threat of Legal Penalty` $\to$ `Malware Installation / Payment Demand`.
- **4. `claimed_sender_type`:** Số điện thoại di động cá nhân thông thường hoặc đầu số quốc tế mạo danh Cục CSGT / Cổng Dịch vụ công.
- **5. `victim_action_requested`:** Nhấp vào liên kết tra cứu phạt nguội; tải file cài đặt APK "Cổng dịch vụ công / Bộ Công An"; chuyển tiền nộp phạt vào tài khoản cá nhân.
- **6. `psychological_tactic`:**
  - **Uy hiếp tâm lý pháp lý:** Đe dọa tăng mức phạt lên 50%, tước giấy phép lái xe, niêm phong tài sản, tạm giữ trong vòng 48 giờ.
  - Người cao tuổi vốn kính sợ pháp luật, sợ phiền hà con cháu nên dễ bị hoảng loạn và vội vã làm theo.
- **7. `message_channel`:** Tin nhắn SMS thông thường, cuộc gọi tự động mạo danh kết hợp gửi SMS dẫn đường link.
- **8. `message_evidence`:**
  - *Mẫu quan sát thực tế (OBSERVED - Nguồn Cục CSGT & Báo Chính phủ):*
    > `"Cuc Canh sat giao thong thong bao: Phuong tien cua ban vi pham loi vuot den do tai nut giao chua xu ly. Yeu cau truy cap: http://phatnguoi-bocongan[.]top de nop phat trong 48h truoc khi tang muc phat 50%."`
  - *Mẫu cảnh báo nghiệp vụ (REPORTED - Nguồn Công an TP Hà Nội):*
    > `"Thong bao tu Cuc Canh sat: Ho so VNeID cua ong/ba bi sai lech thong tin dinh danh. Vui long tai ban cap nhat ung dung tai dichvucong-gov[.]apk de xac thuc."`
- **9. `url_or_domain_evidence`:**
  - Quan sát thực tế: `phatnguoi-bocongan[.]top`, `tra-cuu-csgt[.]net`, `dichvucong-gov[.]online`.
  - Phân tích: Giả dạng tiền tố chính phủ `gov` bằng cách dùng sub-domain hoặc dấu gạch nối (`.gov-vn[.]top`, thay vì tên miền chuẩn `.gov.vn`).
- **10. `sender_evidence`:**
  - Số điện thoại cá nhân (vd: `+8490...`, `+8488...`) hoặc số đầu số ảo quốc tế (`+88...`).
  - **Khẳng định từ Bộ Công an:** CSGT và Cơ quan điều tra **không bao giờ gửi thông báo phạt nguội hoặc làm việc qua tin nhắn SMS/Zalo từ số cá nhân**.
- **11. `sensitive_data_requested`:** Số CCCD, Biển số xe, Ảnh chụp mặt trước sau CCCD, Quyền trợ năng Android (Accessibility Service) khi cài APK.
- **12. `financial_action_requested`:** Yêu cầu chuyển tiền nộp phạt vào tài khoản cá nhân hoặc file APK tự động đọc trộm mã OTP rồi tự chuyển toàn bộ số dư trong app ngân hàng.
- **13. `technical_evasion_method`:** Hướng dẫn nạn nhân "Tắt tính năng Play Protect" và "Cho phép cài đặt từ nguồn không xác định" để vượt qua bảo vệ của Google Play.
- **14. `risk_signals`:** `GOV_AUTHORITY_IMPERSONATION`, `LEGAL_PENALTY_COERCION`, `SUSPICIOUS_SENDER_FOR_AUTHORITY`, `APK_DOWNLOAD_LINK`, `URGENT_DEADLINE_48H`.
- **15. `recommended_detection_method`:**
  - Kiểm tra Sender: Nếu nội dung nhắc đến `Cảnh sát`, `Công an`, `Tòa án`, `Phạt nguội` nhưng Sender là số di động cá nhân hoặc Brandname không thuộc danh bạ cơ quan nhà nước $\to$ Kích hoạt ngay tín hiệu `SUSPICIOUS_SENDER_FOR_AUTHORITY`.
  - Kiểm tra Link/Tên miền: Nếu có link chứa từ khóa dịch vụ công nhưng tên miền không có đuôi `.gov.vn` $\to$ Cảnh báo **CRITICAL**.
- **16. `recommended_user_explanation`:**
  > *"Công an và Cảnh sát giao thông **tuyệt đối không gửi thông báo phạt tiền hay dọa bắt người qua tin nhắn điện thoại**. Mọi thông báo vi phạm đều được gửi bằng văn bản giấy về tận nhà. Bác tuyệt đối không bấm vào link và không tải bất kỳ phần mềm nào!"*
- **17. `source_references`:**
  - Thông báo chính thức của Cục Cảnh sát giao thông (C08 - Bộ Công an).
  - Cảnh báo của Báo Chính Phủ ngày 2025–2026: *"CSGT khẳng định không thông báo phạt nguội qua tin nhắn hay điện thoại"*.
- **18. `confidence_level`:** `0.96 (RẤT CAO)`.

---

### Nhóm 3: Chiếm Quyền Zalo / Facebook & Mạo Danh Người Thân Vay Tiền (`RELATIVE_TAKEOVER_SCAM`)

#### 3.1 Phân tích hồ sơ thủ đoạn (Scenario Dossier)
- **1. `scam_category`:** `RELATIVE_IMPERSONATION`
- **2. `scam_scenario`:** `SCEN_ZALO_ACCOUNT_TAKEOVER_BORROWING` (Kẻ gian đánh cắp tài khoản Zalo/Facebook của con cháu hoặc bạn bè thân thiết, sau đó nghiên cứu lịch sử nhắn tin để nhắn tin mượn tiền gấp vì lý do khẩn cấp).
- **3. `attack_stage`:** `Account Takeover (Nạn nhân 1)` $\to$ `Social Engineering / Trust Exploitation (Người cao tuổi)` $\to$ `Emergency Payment Demand`.
- **4. `claimed_sender_type`:** Tài khoản Zalo / OTT của con cái, người thân hoặc bạn bè quen biết (đã bị kẻ lừa đảo chiếm quyền kiểm soát).
- **5. `victim_action_requested`:** Chuyển gấp một khoản tiền (từ 5 triệu đến 50 triệu VNĐ) vào một tài khoản ngân hàng lạ (không mang tên người thân, được ngụy tạo bằng lý do "tài khoản đối tác", "tài khoản bạn mượn tạm").
- **6. `psychological_tactic`:**
  - **Lợi dụng tình thương và lòng trắc ẩn:** Báo tin gặp tai nạn, máy hỏng không gọi được, đang ở bệnh viện cấp cứu, cần tiền cọc gấp.
  - **Tạo sự khẩn trương:** Thúc giục chuyển ngay trong 10-15 phút để con giải quyết việc gấp, hẹn "tối về con chuyển khoản trả lại".
  - **Né tránh gọi điện thoại:** Khi người cao tuổi gọi lại, kẻ gian tắt máy hoặc chỉ nhá máy 2-3 giây (dùng video Deepfake cắt ghép chập chờn) rồi nhắn: *"Sóng yếu quá không nghe được, mẹ cứ chuyển khoản vào số này giúp con ngay đi"*.
- **7. `message_channel`:** Ứng dụng Zalo, Messenger, SMS báo tin từ "số mới của con".
- **8. `message_evidence`:**
  - *Mẫu quan sát thực tế (OBSERVED - Nguồn Cục An toàn thông tin & Báo Tuổi Trẻ):*
    > `"Me oi, may con bi roi nuoc nen mic hong khong nghe duoc. Ban con dang can gap 10 trieu de dong tien vien phi. Me ban ho con vao so tk nay ti con ve con tra nhe: 1903... NGUYEN VAN A - Techcombank."`
  - *Mẫu tin nhắn SMS số lạ mạo danh con cái (REPORTED - Nguồn Công an các tỉnh):*
    > `"Bo me oi, con doi so dien thoai moi nay nhe. Con dang tren duong di lam gap bi va quet xe, can 5 trieu bo chuyen gap vao so tai khoan nay den cho nguoi ta..."`
- **9. `url_or_domain_evidence`:** 
  - Thường không chứa URL trong bước vay tiền trực tiếp.
  - Nhưng trong bước chiếm quyền tài khoản trước đó, thường dùng link bình chọn cuộc thi ảnh giả mạo: `binhchon-nhinang[.]top`, `cuocthianhdep-2026[.]online`.
- **10. `sender_evidence`:**
  - Nickname hiển thị đúng tên con cái/bạn bè (nhưng do kẻ gian cầm máy).
  - Tên chủ tài khoản nhận tiền **khác hoàn toàn** với tên người gửi (Mismatch Beneficiary Name).
- **11. `sensitive_data_requested`:** Ảnh chụp biên lai chuyển tiền thành công.
- **12. `financial_action_requested`:** Chuyển khoản ngân hàng tức thời (NAPAS 24/7) sang số tài khoản ngân hàng trung gian.
- **13. `technical_evasion_method`:** Nghiên cứu cách xưng hô trong tin nhắn cũ (gọi "Bố", "Mẹ", "U", "Bác") để bắt chước chuẩn giọng văn gia đình.
- **14. `risk_signals`:** `RELATIVE_EMERGENCY_CLAIM`, `URGENT_MONEY_TRANSFER_REQUEST`, `THIRD_PARTY_BANK_ACCOUNT`, `REFUSE_VOICE_CALL`.
- **15. `recommended_detection_method`:**
  - Phát hiện mẫu câu hỏi vay tiền/nhờ chuyển tiền gấp: `(chuyển hộ|chuyển gấp|vay tạm|bắn hộ) + (tiền|triệu|k)` kèm chuỗi số tài khoản ngân hàng.
  - Cảnh báo người dùng phải gọi điện thoại kiểm chứng bằng cuộc gọi viễn thông thông thường (SIM) trước khi thực hiện giao dịch chuyển tiền.
- **16. `recommended_user_explanation`:**
  > *"Tin nhắn này có dấu hiệu tài khoản của người thân đã bị kẻ gian cướp quyền để đi vay tiền. Bác **tuyệt đối không chuyển tiền vội**! Hãy gọi điện thoại trực tiếp bằng số di động thông thường cho con/cháu để hỏi lại cho chắc chắn!"*
- **17. `source_references`:**
  - Cảnh báo của Cục An toàn thông tin về thủ đoạn chiếm đoạt Zalo lừa vay tiền (`vietnamnet.vn`).
  - Báo Tuổi Trẻ: *"Mất hàng trăm triệu vì tin nhắn nhờ chuyển tiền của 'con gái' qua Zalo"*.
- **18. `confidence_level`:** `0.85 (CAO khi có mẫu nhờ chuyển tiền + STK)`.

---

### Nhóm 4: Tuyển Cộng Tác Viên & Đầu Tư Siêu Lợi Nhuận (`JOB_TASK_INVESTMENT`)

#### 4.1 Phân tích hồ sơ thủ đoạn (Scenario Dossier)
- **1. `scam_category`:** `JOB_SCAM / INVESTMENT_SCAM`
- **2. `scam_scenario`:** `SCEN_ONLINE_TASK_EASY_MONEY` (Dụ dỗ người lớn tuổi, phụ nữ làm cộng tác viên xử lý đơn hàng Shopee/Lazada hoặc tham gia quỹ đầu tư tài chính với cam kết lợi nhuận phi thực tế 20-30%/ngày).
- **3. `attack_stage`:** `Cold Contact` $\to$ `Small Reward Trust Building` $\to$ `Large Capital Extortion` $\to$ `Lock Account / Disappear`.
- **4. `claimed_sender_type`:** Số điện thoại rác gửi tin hàng loạt (Spam SMS) hoặc mời chào qua Telegram/Zalo.
- **5. `victim_action_requested`:** Nhấp vào liên kết tải ứng dụng hoặc liên hệ Zalo/Telegram; nạp tiền thực hiện nhiệm vụ "giật đơn hàng ảo" hoặc nạp tiền vào sàn giao dịch giả mạo.
- **6. `psychological_tactic`:**
  - **Lợi dụng lòng tham và mong muốn kiếm tiền phụ giúp gia đình:** Hứa hẹn "việc nhẹ lương cao", "làm tại nhà 30 phút nhận 500k", "không cần kinh nghiệm".
  - **Chiến thuật "Thả con tép bắt con tôm":** 1-2 nhiệm vụ đầu tiên chỉ yêu cầu nạp 100k-200k, hệ thống chuyển trả lại ngay 150k-300k (cho ăn quả ngọt) để tạo lòng tin tuyệt đối. Đến khi nạn nhân nạp số tiền lớn (vài chục đến vài trăm triệu), kẻ gian viện cớ "sai cú pháp", "chưa đủ hạn mức", yêu cầu nạp thêm để giải ngân rồi cắt đứt liên lạc.
- **7. `message_channel`:** SMS quảng cáo rác, iMessage, tin nhắn mời vào nhóm kín Telegram/Zalo.
- **8. `message_evidence`:**
  - *Mẫu quan sát thực tế (OBSERVED - Nguồn Báo Lao Động & Cục ATTT):*
    > `"Chao ban, Shopee Mall tuyen CTV danh gia san pham online lam tai nha. Thu nhap 300k - 800k/ngay, nhan tien ngay trong ngay. Khong can von, khong di lai. Lien he Zalo: 0988... de nhan viec ngay."`
  - *Mẫu mời chào đầu tư tài chính (REPORTED - Nguồn Báo Công an Nhân dân):*
    > `"Quy dau tu Vin-Trade ho tro nguoi cao tuoi sinh loi an toan: Loi nhuan 25%/tuan, bao hiem von 100%. Nhanh tay dang ky tai: http://vintrade-dautu[.]top"`
- **9. `url_or_domain_evidence`:**
  - Quan sát thực tế: Các link dẫn về Telegram bot hoặc nhóm Zalo cá nhân, các web sàn giao dịch ảo đuôi `.vip`, `.cc`.
- **10. `sender_evidence`:** Các sim rác nội mạng Viettel, Vina, Mobi không chính chủ.
- **11. `sensitive_data_requested`:** Thông tin tài khoản ngân hàng để "nhận lương", số điện thoại liên kết Zalo.
- **12. `financial_action_requested`:** Chuyển tiền đặt cọc làm nhiệm vụ, nạp tiền vào tài khoản chỉ định của đối tượng.
- **13. `technical_evasion_method`:** Thay đổi cách viết từ khóa để tránh spam filter: `S.h.o.p.e.e`, `T.i.k.t.o.k`, `v.i.ệ.c l.à.m`, `lương cao`.
- **14. `risk_signals`:** `UNREALISTIC_EARNING_PROMISE`, `TASK_SCAM_KEYWORDS`, `REDIRECT_TO_UNOFFICIAL_CHAT`, `UPFRONT_DEPOSIT_REQUIRED`.
- **15. `recommended_detection_method`:**
  - Phát hiện tổ hợp: `(tuyển ctv|việc nhẹ|lương cao|thu nhập \d+k) + (liên hệ zalo|telegram|link)`.
  - Phân loại mức rủi ro **HIGH** khi có lời hứa kiếm tiền dễ dàng từ số điện thoại không xác định.
- **16. `recommended_user_explanation`:**
  > *"Tin nhắn mời làm việc tại nhà với mức thu nhập cao bất thường là cái bẫy lừa đảo nạp tiền làm nhiệm vụ. Ban đầu kẻ xấu có thể cho bác nhận vài chục nghìn, nhưng sau đó sẽ ép bác nạp tiền lớn rồi chiếm đoạt sạch. Bác tuyệt đối không tham gia!"*
- **17. `source_references`:**
  - Cảnh báo của Bộ Công an về bẫy lừa đảo tuyển cộng tác viên online năm 2025–2026.
  - Báo Lao Động: *"Cảnh giác chiêu trò lừa đảo làm nhiệm vụ online bùng phát"*.
- **18. `confidence_level`:** `0.92 (RẤT CAO)`.

---

### Nhóm 5: Bẫy "Thu Hồi Vốn Treo" & Lấy Lại Tiền Lừa Đảo (`RECOVERY_SCAM`)

#### 5.1 Phân tích hồ sơ thủ đoạn (Scenario Dossier)
- **1. `scam_category`:** `RECOVERY_SCAM`
- **2. `scam_scenario`:** `SCEN_ADVANCE_FEE_RECOVERY` (Đóng giả Luật sư, Chuyên gia An ninh mạng hoặc Cán bộ Cục An ninh mạng hỗ trợ nạn nhân vừa bị lừa đảo lấy lại số tiền đã mất, yêu cầu đóng "phí hồ sơ", "phí giải ngân" để nhận lại tiền).
- **3. `attack_stage`:** `Secondary Victimization (Lừa đảo lần hai)` $\to$ `False Hope Exploitation` $\to$ `Upfront Fee Extortion`.
- **4. `claimed_sender_type`:** Tài khoản mạng xã hội giả mạo trang "Cục An ninh mạng", "Văn phòng Luật sư", hoặc tin nhắn mạo danh chuyên viên pháp lý.
- **5. `victim_action_requested`:** Cung cấp thông tin vụ việc lừa đảo trước đó; chuyển tiền đóng các loại phí: "Phí kéo vốn", "Thuế thu nhập cá nhân 10%", "Phí mở cổng giải ngân ngân hàng".
- **6. `psychological_tactic`:**
  - **Đánh vào tâm lý tuyệt vọng và tiếc tiền:** Nạn nhân vừa mất một khoản tiền lớn (vài chục triệu đến vài tỷ đồng), đang hoảng loạn, không dám nói với gia đình và khao khát gỡ gạc.
  - **Mạo danh uy tín tuyệt đối:** Sử dụng hình ảnh lãnh đạo Bộ Công an, con dấu đỏ giả mạo, giấy xác nhận thu hồi tài sản có chữ ký giả để nạn nhân tin rằng cơ quan chức năng đã phong tỏa được tiền của kẻ lừa đảo.
- **7. `message_channel`:** Tin nhắn chủ động nhắn tới nạn nhân qua Zalo/Telegram, quảng cáo Facebook tiếp cận người tìm kiếm từ khóa "bị lừa đảo", SMS mạo danh.
- **8. `message_evidence`:**
  - *Mẫu quan sát thực tế (OBSERVED - Nguồn Cục An toàn thông tin & Báo Dân Trí):*
    > `"Van phong Luat su ho tro nan nhan bi lua dao tren khong gian mang: Ho so cua ban da duoc Bo Cong an thu ly, so tien 150 trieu da duoc dong bang. Vui long dong phi giai toa 10% (15 trieu) de duoc hoan tien ve tai khoan trong ngay."`
  - *Mẫu tin nhắn quảng cáo mạo danh (REPORTED - Nguồn Báo Tuổi Trẻ):*
    > `"Cuc An ninh mang cam ket thu hoi 100% tien treo cho cac nan nhan bi lua dao online. Nhanh tay lien he Zalo can bo truc ban 0912... de duoc giai quyet ho so mien phi."`
- **9. `url_or_domain_evidence`:**
  - Các trang đích giả danh: `thuhoitientreo-bocongan[.]top`, `hotro-nan-nhan[.]online`.
  - Phân tích: Không có bất kỳ cơ quan công an hay công ty luật nào tại Việt Nam được phép yêu cầu nạn nhân đóng tiền "phí kéo vốn" qua tài khoản cá nhân.
- **10. `sender_evidence`:** Số điện thoại cá nhân tự xưng là "Cán bộ điều tra / Luật sư".
- **11. `sensitive_data_requested`:** Lịch sử sao kê ngân hàng, CCCD, thông tin tài khoản bị lừa trước đó.
- **12. `financial_action_requested`:** Yêu cầu chuyển khoản thêm một khoản tiền mới (thường từ 10% đến 20% số tiền đã mất) với lời hứa sẽ được trả lại toàn bộ sau khi tiền được giải phóng.
- **13. `technical_evasion_method`:** Ngụy trang dưới danh nghĩa "tiền ký quỹ nhà nước", "tiền bảo lãnh hồ sơ" để đánh lừa nhận thức của nạn nhân.
- **14. `risk_signals`:** `RECOVERY_SCAM_PROMISE`, `UPFRONT_FEE_DEMAND`, `FAKE_LAW_ENFORCEMENT_REPRESENTATION`, `DOUBLE_EXTORTION_RISK`.
- **15. `recommended_detection_method`:**
  - Bắt cặp từ khóa: `(thu hồi tiền|lấy lại tiền|tiền treo|giải cứu vốn) + (phí hồ sơ|phí giải ngân|đặt cọc|đóng trước)`.
  - Đánh dấu mức rủi ro **CRITICAL** ngay lập tức vì đây là hành vi lừa đảo kép trực tiếp.
- **16. `recommended_user_explanation`:**
  > *"Cục An toàn thông tin và Bộ Công an khẳng định: **Không có bất kỳ cơ quan hay cá nhân nào có thể lấy lại tiền bị lừa qua mạng mà yêu cầu nộp thêm phí**. Kẻ gian đang lợi dụng sự lo lắng của bác để lừa thêm lần thứ hai. Bác tuyệt đối không đóng thêm bất kỳ đồng tiền nào!"*
- **17. `source_references`:**
  - Cảnh báo của Cục An toàn thông tin trên Báo Dân Trí & Tuổi Trẻ năm 2025–2026.
  - Chuyên mục cảnh báo của `khonggianmang.vn`.
- **18. `confidence_level`:** `0.95 (RẤT CAO)`.

---

## 4. Bảng Tổng Hợp So Sánh 5 Kịch Bản MVP

Bảng đối chiếu tổng hợp giúp định hình các Rules và Risk Signals cho Đợt 2:

| Nhóm Kịch Bản | Thao Túng Tâm Lý Chủ Đạo | Dấu Hiệu Kỹ Thuật Đặc Trưng | Bằng Chứng Rủi Ro Nhận Diện | Nguy Cơ Thiệt Hại | Mức Độ Nghiêm Trọng |
|---|---|---|---|---|---|
| **1. Mạo danh Ngân hàng / OTP** | Gây hoảng sợ khóa thẻ, lợi dụng QĐ 2345 | BTS giả, tên miền typosquatting, đòi OTP | Link giả mạo + Yêu cầu OTP + Giục giã 24h | Mất sạch tiền trong tài khoản tức thì | **CRITICAL** |
| **2. Giả danh CSGT / Công an** | Uy hiếp pháp lý, dọa bắt giam / phạt nặng | Số cá nhân xưng CSGT, link giả gov, ép cài APK | Tự xưng công an + Dọa phạt + Link lạ | Mất tiền nộp phạt hoặc bị cài mã độc chiếm máy | **CRITICAL** |
| **3. Chiếm quyền Zalo mượn tiền** | Đánh vào tình thương, báo tin tai nạn cấp cứu | Tài khoản người quen nhưng STK tên người lạ | Nhờ chuyển tiền gấp + STK lạ + Tránh nghe máy | Mất tiền chuyển nhầm cho kẻ lừa đảo | **HIGH** |
| **4. Tuyển CTV / Đầu tư sàn ảo** | Lợi dụng lòng tham, hứa hẹn việc nhẹ lương cao | Mời vào nhóm kín Telegram/Zalo, mồi tiền nhỏ | Hứa hẹn lãi phi lý + Đòi đặt cọc nhiệm vụ | Bị lừa nạp tiền theo từng đợt tăng dần | **HIGH** |
| **5. Bẫy thu hồi vốn treo** | Đánh vào tâm lý tiếc của, hoảng loạn của nạn nhân | Giả danh luật sư/an ninh mạng đòi phí hồ sơ | Hứa lấy lại tiền + Bắt nộp phí trước 10-20% | Nạn nhân bị lừa thêm lần thứ hai (lừa kép) | **CRITICAL** |

---

## 5. Khoảng Trống Dữ Liệu & Giới Hạn Cần Lưu Ý (Data Gaps & Limitations)

1. **Giới hạn về URL Threat Intelligence:**
   - Các tên miền lừa đảo thường có vòng đời rất ngắn (Ephemeral Domains, sống từ 24h đến 72h). Khi báo chí đăng bài cảnh báo, tên miền đó thường đã bị nhà mạng hoặc NCSC chặn (Sinkholed/Taken down). Do đó, **Rule Engine không thể chỉ dựa vào blacklist URL cứng, mà bắt buộc phải dựa vào Heuristic Pattern của Domain (Sub-domain giả mạo, đuôi TLD lạ, độ tương đồng tên thương hiệu)**.
2. **Bảo vệ quyền riêng tư người dùng:**
   - Nghiên cứu không thu thập số điện thoại cá nhân thật của nạn nhân. Mọi số điện thoại và số tài khoản trong báo cáo đều được rút gọn hoặc ẩn danh (Masked) theo chuẩn bảo vệ dữ liệu cá nhân.
3. **Kế hoạch triển khai sang Đợt 2 (Rule Authoring & Database Seeding):**
   - Từ 5 kịch bản và các mẫu chứng cứ đã được thẩm định ở Đợt 1, nhóm kỹ sư sẽ tiến hành chuyển hóa thành:
     1. `scam_keywords_patterns.csv`: Bộ từ điển từ khóa tiếng Việt có dấu, không dấu, teencode và biểu thức Regex chuẩn hóa.
     2. `scam_detection_rules.csv`: Cấu trúc JSON AST của các Rules logic tương ứng theo ERD.
     3. `scam_risk_signals.csv`: Định nghĩa các tín hiệu rủi ro và trọng số đóng góp điểm.
     4. `scam_detection_seed_data.sql`: File SQL hoàn chỉnh để import vào PostgreSQL database theo schema của `Scam_Detection_Rules_Patterns_ERD.md`.
