# Scam Message Detection
## Product Requirement Specification (PRS / PRD) — Phiên bản 2.4 (Toàn Diện & Mở Rộng)

> **Thông tin tài liệu:**  
> - **Phiên bản:** v2.4 (Production Platform, Threat Intel & On-Device OCR Integrated)  
> - **Cập nhật:** Tháng 10/2026 — Senior Product Manager & Security Solution Architect  
> - **Tài liệu liên quan:**  
>   - [ERD: Thiết kế Cơ sở dữ liệu Chuẩn hóa](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/ERD.md) (PostgreSQL Schema, Unified Hub & Trusted Contacts)  
>   - [Báo cáo Nghiên cứu Tình báo Lừa đảo tại Việt Nam](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/Threat_Intelligence_Research.md) (Dẫn chứng Bộ Công an, AIS, VNCERT/CC)  
>   - [Báo cáo Kiểm thử & Hiệu chuẩn Rule Engine](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/Test_Report.md) (Kiểm chuẩn 24 kịch bản lừa đảo & hợp pháp, Precision 100%)  
>   - [Bản đồ Dự án & Hướng dẫn Vận hành](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/WALKTHROUGH.md) (Bản đồ thư mục, 7 bước phân tích & bảng tra cứu nhanh)  
>   - [Sổ tay Giải thích Kiến trúc Rule Engine AST Toàn diện](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/Rule_Engine_Architecture_Guide.md) (Cẩm nang chi tiết cho PM/BA)  

---

# 1. Goal

## 1.1 Product Goal
Tự động phát hiện các tin nhắn có dấu hiệu lừa đảo và can thiệp cảnh báo người dùng kịp thời trước khi họ thực hiện các hành động có nguy cơ gây thiệt hại tài chính hoặc lộ lọt thông tin bảo mật.

> **Định vị sản phẩm:**  
> The product should help users pause, verify and make safer decisions when receiving potentially fraudulent messages, without taking away their autonomy.  
> Sản phẩm không được định vị là *"ứng dụng giám sát"* (surveillance tool) mà là một **"trusted safety companion" (người bạn đồng hành an toàn đáng tin cậy)** giúp người dùng dừng lại một nhịp để kiểm tra trước khi quyết định.

## 1.2 User Outcome
Sau khi kích hoạt tính năng, người dùng đạt được các kết quả cụ thể:
- **Nhận biết trực quan, không quá tải:** Biết rõ tình trạng tin nhắn qua mô hình trải nghiệm 3 mức đơn giản (**LOW**, **UNKNOWN**, **HIGH**), không bị rối bởi điểm số hay thuật toán phức tạp.
- **Thấu hiểu nguyên nhân:** Hiểu được *vì sao* hệ thống đánh giá tin nhắn là nguy hiểm thông qua các dấu hiệu trực quan, dễ hiểu bằng ngôn ngữ đời thường.
- **Có định hướng hành động (Actionable Guidance):** Biết chính xác bước tiếp theo nên làm gì tương ứng với từng cấp độ (tiếp tục bình thường, kiểm tra trước khi chuyển tiền, hay dừng lại tham vấn gia đình).
- **Tự động đồng hành:** Thiết bị sử dụng được chủ động bảo vệ và rà soát mỗi khi có tin nhắn mới, không cần người dùng phải thực hiện thao tác thủ công.
- **Tạo khoảng dừng an toàn (Moment of Pause):** Có công cụ để kiểm tra thêm (hỏi trợ lý AI, tham vấn gia đình) thay vì lập tức chuyển tiền dưới áp lực tâm lý.
- **Chủ động nhờ trợ giúp an toàn:** Dễ dàng kết nối với người thân đáng tin cậy khi có nguy cơ nghiêm trọng mà không mang tâm lý tự ti hay xấu hổ.

## 1.3 Core Product Principles

### 1. Backend complexity ≠ User complexity
Hệ thống backend có thể vận hành đa tầng phức tạp (Risk Score 0–100, Confidence, Signal Engine, Policy Engine, Machine Learning), nhưng giao diện người dùng phải tối giản, dễ hiểu và tập trung hoàn toàn vào quyết định hành động: **LOW**, **UNKNOWN**, **HIGH**.

### 2. Unknown ≠ Safe
Hệ thống không đánh đồng việc "chưa đủ cơ sở khẳng định lừa đảo" với "tin nhắn an toàn". Khi thiếu dữ liệu hoặc độ tin cậy thấp, hệ thống minh bạch gán nhãn **UNKNOWN** và khuyến cáo người dùng kiểm chứng trước khi thực hiện hành động rủi ro.

### 3. Warn based on actionability, not just score
Cảnh báo không chỉ là còi báo động hay con số vô cảm. Cảnh báo phải gắn liền với hành động khả thi: Bác nên làm gì ngay lúc này? (Dừng chuyển tiền, kiểm tra đường link, gọi người thân).

### 4. Pause before action
Giá trị cốt lõi của sản phẩm là tạo ra "Khoảng dừng an toàn" (Moment of Pause) giúp người dùng thoát khỏi trạng thái bị kẻ xấu thao túng tâm lý hoặc thúc ép thời gian.

### 5. Explain, don't just alarm
Không bao giờ chỉ đưa ra kết luận cụt lủn "Lừa đảo"; luôn giải thích thấu đáo bằng ngôn ngữ giản dị, tôn trọng, chỉ rõ các dấu hiệu cụ thể trong tin nhắn.

### 6. Preserve user autonomy (Protect without controlling)
Hệ thống đóng vai trò cố vấn cảnh báo rủi ro; tuyệt đối không tự ý khóa máy, không tự ý hủy giao dịch hợp pháp, không tước đoạt quyền tự chủ và phẩm giá của người dùng.

### 7. Escalate only when necessary and consented
Cơ chế kết nối người thân chỉ kích hoạt khi rủi ro ở mức nghiêm trọng nhất (**HIGH + Critical Internal**) và bắt buộc phải có sự đồng thuận (opt-in consent) từ người dùng. Không biến ứng dụng thành công cụ giám sát đời tư.

### 8. Hard Delete for Benign Privacy (Zero Residual Risk)
Tin nhắn ở mức an toàn (**`LOW`**) bắt buộc phải được **xóa vĩnh viễn (Hard Delete)** sau 30 ngày; không giữ lại dữ liệu cá nhân không cần thiết nhằm tuân thủ tuyệt đối Nghị định 13/2023/NĐ-CP và bảo vệ quyền riêng tư tuyệt đối cho người dùng.

---

# 2. Context

## 2.1 User Persona

### 2.1.1 Người lớn tuổi (55–75+ tuổi) — Primary User
- **Tài chính & Quyền tự quyết:** Sở hữu sổ tiết kiệm, lương hưu hoặc tài sản tích lũy cả đời; có toàn quyền quyết định chi tiêu và thực hiện các giao dịch chuyển khoản ngân hàng.
- **Hành vi công nghệ:** Sử dụng smartphone hàng ngày để đọc báo, gọi video với con cháu, dùng Zalo, Facebook, SMS và Mobile Banking ở mức độ cơ bản.
- **Rào cản thể chất & nhận thức:** Thị lực giảm sút (khó đọc chữ nhỏ hoặc soi kỹ URL giả mạo), tốc độ phản xạ và khả năng tập trung giảm khi bị đối tượng xấu dồn ép tâm lý.
- **Bối cảnh xã hội & tâm lý:**
  - Đã nghỉ hưu, vai trò xã hội thu hẹp, thường xuyên ở nhà một mình trong khi con cháu bận rộn đi làm/đi học.
  - Có nhu cầu giao lưu, mong muốn được quan tâm, lắng nghe.
  - Luôn muốn khẳng định bản thân vẫn minh mẫn, tự chủ, không muốn trở thành gánh nặng cho con cái.
  - Ngại hỏi con cháu vì sợ bị trách móc hay coi là già yếu.

### 2.1.2 Người dùng phổ thông (16–55 tuổi)
- TBD (Đối tượng mở rộng trong các giai đoạn sau).

## 2.2 Core Pain Points

### 1. Cô đơn & Thiếu kết nối
Người lớn tuổi thường thiếu người trò chuyện hàng ngày. Khi kẻ lừa đảo chủ động tiếp cận bằng sự ân cần, hỏi han lịch sự hoặc đóng vai chuyên viên hỗ trợ tận tình, nạn nhân dễ mở lòng và đặt niềm tin vào người lạ.

### 2. Nhu cầu tự chủ & Sợ mất thể diện
Tâm lý muốn chứng minh mình vẫn làm chủ cuộc sống khiến người cao tuổi có xu hướng tự giải quyết vấn đề. Khi nhận được tin nhắn đe dọa hoặc cơ hội đầu tư, họ thường giấu con cháu vì sợ bị can thiệp vào tài chính cá nhân.

### 3. Dễ bị thao túng tâm lý bởi quyền lực & tổ chức lớn
Người lớn tuổi có niềm tin tự nhiên và sự kính trọng đối với cơ quan công quyền (Công an, Tòa án, Viện Kiểm sát, Thuế, Bảo hiểm xã hội) hoặc các thương hiệu lớn (Ngân hàng quốc doanh, Tập đoàn viễn thông). Kẻ lừa đảo khai thác triệt để tâm lý này bằng cách tạo văn bản giả mạo, viện dẫn các điều luật hình sự để gây sợ hãi và thúc ép hành động.

### 4. Hạn chế về kỹ năng kiểm chứng số
Không phân biệt được Brandname SMS giả mạo (sử dụng trạm BTS giả), tên miền phishing tương tự (ví dụ: `vietcombank.com.vn-ib.top`), hay các tài liệu con dấu scan giả. Thiếu phản xạ cốt lõi trong kỷ nguyên số: **"Pause → Verify → Decide"**.

### 5. Khủng hoảng tâm lý sau khi bị lừa (Vòng xoáy Recovery Scam)
Sau khi nhận ra mình mất tiền, nạn nhân rơi vào trạng thái hoảng loạn, sợ hãi, xấu hổ, không dám nói với gia đình. Nắm thấu tâm lý muốn "chuộc lỗi" và gỡ lại tiền, kẻ lừa đảo tiếp tục đóng vai luật sư, chuyên gia an ninh mạng cam kết "thu hồi tiền treo", dẫn dụ nạn nhân chuyển thêm phí xác minh, khiến thiệt hại nhân lên gấp nhiều lần.

## 2.3 Problem Statement
> **"Older adults possess financial assets that make them prime targets for sophisticated scammers, yet they lack a non-judgmental, privacy-respecting safety companion that helps them verify suspicious messages and pause impulsive actions while preserving their dignity and independence."**

## 2.4 Opportunity: Xây dựng "Decision Safety Layer"
Sản phẩm không đơn thuần là một bộ lọc spam/block tin nhắn cơ học, mà là một **"Lớp an toàn quyết định" (Decision Safety Layer)** can thiệp vào khoảnh khắc vàng giữa lúc nhận tin và lúc hành động:

$$\text{Nhận tin nhắn} \xrightarrow{\quad} \mathbf{PAUSE} \xrightarrow{\quad} \mathbf{VERIFY} \xrightarrow{\quad} \mathbf{DECIDE} \xrightarrow{\quad} \text{Hành động an toàn}$$

## 2.5 Các Kịch Bản Lừa Đảo Trọng Điểm Tại Việt Nam (Core Scam Scenarios)
Căn cứ vào dữ liệu nghiên cứu thực tế từ Cục An toàn thông tin (Bộ TT&TT), Cục Cảnh sát hình sự (Bộ Công an - A05/C08), Hiệp hội An ninh mạng Quốc gia (NCA) và VNCERT/CC (chi tiết tại [Báo cáo Nghiên cứu Tình báo](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/docs/Threat_Intelligence_Research.md)), sản phẩm tập trung xử lý dứt điểm các kịch bản đe dọa chính đối với người dân và người lớn tuổi:

| Mã Kịch bản | Tên Thủ đoạn | Đặc trưng Kỹ thuật & Thao túng tâm lý | Dẫn chứng Cơ quan thẩm quyền |
|---|---|---|---|
| `SCEN_VN_VNEID_LAND_FRAUD` | **Mạo danh Công an/Địa chính: Cập nhật Sổ đỏ vào VNeID** | Đối tượng mạo danh cán bộ Công an phường/quận hoặc cán bộ Văn phòng Đăng ký Đất đai gọi điện, gửi tin nhắn thúc ép: *"Thông tin sổ đỏ nhà đất chưa đồng bộ trên VNeID, sẽ bị phạt hành chính hoặc thu hồi nếu không cập nhật trước 24h"*. Nạn nhân bị ép click link giả mạo cổng dịch vụ công (`dichvucong-vneid.gov-vn.cc`) để tải file mã độc APK chiếm quyền điều khiển điện thoại. | Công an tỉnh Ninh Bình, Công an tỉnh Phú Thọ & Cục An toàn thông tin (Bộ TT&TT) liên tục phát đi cảnh báo khẩn cấp toàn quốc. |
| `SCEN_BANK_IMPERSONATION_OTP` | **Mạo danh Ngân hàng / Đánh cắp OTP** | Kẻ xấu sử dụng trạm phát sóng di động giả mạo (Fake BTS) chèn Brandname ngân hàng (`Vietcombank`, `BIDV`...). Nội dung dọa: "tài khoản bị khóa", "đăng nhập bất thường tại thiết bị lạ", ép bấm vào URL giả mạo thương hiệu để khai thác OTP / mật khẩu. | Cục An toàn thông tin, Bộ Công an (A05) cảnh báo các vụ bắt giữ trạm BTS giả mạo tại Hà Nội, TP.HCM. |
| `SCEN_GOV_TRAFFIC_FINE` | **Mạo danh Công an / CSGT Phạt nguội** | Tin nhắn mạo danh Cục CSGT thông báo vi phạm giao thông (phạt nguội), đe dọa tước bằng lái, truy cứu trách nhiệm hình sự; ép truy cập link web lạ hoặc cài ứng dụng lạ để tra cứu biên bản vi phạm. | Cục Cảnh sát giao thông (C08 - Bộ Công an) khẳng định lực lượng CSGT không thông báo phạt nguội qua tin nhắn SMS hay mạng xã hội. |
| `SCEN_SOCIAL_TAKEOVER_LOAN` | **Chiếm quyền MXH / Vay tiền khẩn cấp (Hội thoại đa tin nhắn)** | Kẻ gian hack tài khoản Facebook/Zalo của con cháu, người quen; dẫn dắt qua nhiều tin nhắn hỏi thăm làm quen trước khi viện cớ "đang kẹt tiền đóng hàng/phẫu thuật gấp", yêu cầu chuyển tiền vào số tài khoản lạ. | Cảnh báo thường trực từ Công an các tỉnh/thành về thủ đoạn Deepfake và hack tài khoản OTT người thân kết hợp kỹ thuật dẫn dắt tâm lý. |
| `SCEN_JOB_OFFER_TELEGRAM` | **Tuyển dụng CTV Online / Bẫy Nhiệm vụ** | Nhắm vào người cao tuổi ở nhà rảnh rỗi muốn kiếm thêm thu nhập phụ giúp con cháu. Mồi nhử "đánh giá sản phẩm Shopee/TikTok", "nghe nhạc có tiền 500k-1tr/ngày", sau đó kéo nạn nhân vào nhóm Telegram/Zalo, yêu cầu nạp tiền "chạy nhiệm vụ hoàn vốn" và chiếm đoạt tiền nạp. | Cục An toàn thông tin (AIS) xếp đây là 1 trong 3 hình thức lừa đảo gây thiệt hại tài chính lớn nhất tại Việt Nam. |
| `SCEN_RECOVERY_SCAM` | **Lừa đảo Thu hồi vốn / Hỗ trợ tiền treo** | Đánh vào tâm lý hoảng loạn và sợ mất thể diện của nạn nhân vừa bị lừa tiền. Đối tượng mạo danh "Luật sư an ninh mạng", "Đội ngũ kỹ thuật Cục An ninh mạng", cam kết hỗ trợ "thu hồi tiền treo", yêu cầu đóng trước "phí mở cổng xác thực" hoặc "phí hồ sơ pháp lý". | Bộ Công an và VNCERT/CC liên tục phát cảnh báo: Tuyệt đối không có cơ quan hay luật sư nào có khả năng thu hồi tiền lừa đảo qua mạng bằng cách thu phí trước. |

---

# 3. Measurement Framework & Metrics

## 3.1 North Star Metric: Safe Decision Rate (SDR)
- **Định nghĩa:** Tỷ lệ phần trăm các tin nhắn mức độ rủi ro cao (**`HIGH`**, bao gồm cả các trường hợp có `internal_severity = CRITICAL`) mà người dùng **không** thực hiện hành vi nguy hiểm (không click link độc hại, không chuyển khoản) và chủ động thực hiện hành động an toàn (Bỏ qua, Chặn người gửi, Nhờ AI kiểm tra, Tham vấn người thân).
- **Công thức tính:**
  $$\text{SDR} = \frac{\text{Số lượng High Risk Messages có User Action an toàn}}{\text{Tổng số High Risk Messages được người dùng tiếp nhận}} \times 100\%$$
- **Mục tiêu đề xuất (Proposed Target):** $\ge 85\%$ trong vòng 6 tháng sau khi phát hành chính thức.

## 3.2 Detection & Model Performance Metrics
- **Detection Precision (High Risk):** Tỷ lệ tin nhắn bị hệ thống cảnh báo `HIGH` thực sự là lừa đảo (Mục tiêu sản phẩm: $\ge 95\%$; Kết quả kiểm thử thực nghiệm: **$100\%$** trên 24 test cases).
- **Detection Recall (High Risk):** Tỷ lệ tin nhắn lừa đảo thực tế được hệ thống gắn nhãn `HIGH` (Mục tiêu sản phẩm: $\ge 95\%$; Kết quả kiểm thử thực nghiệm: **$100\%$** không bỏ sót kịch bản nguy hiểm nào).
- **False Positive Rate (FPR):** Tỷ lệ tin nhắn hợp pháp (OTP ngân hàng chính thức, thông báo CSGT, tin nhắn người thân) bị cảnh báo nhầm thành `HIGH` (Mục tiêu: $\le 0.5\%$; Kết quả: **$0.0\%$**).
- **False Negative Rate (FNR):** Tỷ lệ bỏ sót tin nhắn lừa đảo nguy hiểm xuống mức `LOW` (Mục tiêu: $\le 1.0\%$; Kết quả: **$0.0\%$**).
- **Detection Latency:**
  - *Local Rule Engine Triage:* $\le 5\text{ms}$ trên thiết bị client (WASM Regex & AST Engine).
  - *End-to-End Latency:* $\le 1.0$ giây từ lúc SMS đến khi hiển thị cảnh báo.

## 3.3 User Behavior & Engagement Metrics (3-Level UX)
- **Warning View Rate (HIGH):** $\%$ cảnh báo `HIGH` được người dùng dừng lại xem trên màn hình ($\text{Target} \ge 90\%$).
- **Explanation Comprehension Engagement:** $\%$ người dùng bấm vào xem lý do "Vì sao tin nhắn này đáng ngờ?" ($\text{Target} \ge 40\%$).
- **Verify with AI Usage:** $\%$ sự cố cảnh báo `HIGH` hoặc `UNKNOWN` mà người dùng đặt câu hỏi cho trợ lý AI ($\text{Target} \ge 25\%$).
- **UNKNOWN → Verification Rate:** $\%$ tin nhắn ở trạng thái `UNKNOWN` mà người dùng chủ động bấm kiểm chứng (hỏi AI, xem checklist an toàn) trước khi click link hoặc thực hiện giao dịch ($\text{Target} \ge 35\%$).
- **Critical Escalation Rate:** $\%$ sự kiện `HIGH + Critical Internal` kích hoạt thông báo tới người thân được người thân phản hồi trong vòng 30 phút ($\text{Target} \ge 70\%$).
- **Alert Fatigue Rate:** Tỷ lệ người dùng tắt thông báo hoặc gỡ app do bị làm phiền bởi cảnh báo không cần thiết ($\le 2\%$).
- **Action Distribution:** Tỷ lệ phân bổ giữa các hành động: `BLOCK_SENDER`, `MARK_AS_SAFE`, `CALL_FAMILY`, `DISMISS`.

## 3.4 Safety & Loss Prevention Metrics
- **Estimated Scam Loss Prevented:** Tổng giá trị tài chính ước tính ngăn chặn thành công (tính dựa trên số tiền đề cập trong tin nhắn lừa đảo bị cảnh báo `HIGH`).
- **Malicious Link Click Rate post-warning:** Tỷ lệ người dùng vẫn bấm vào link sau khi nhận cảnh báo đỏ `HIGH` (Proposed Target: $\le 2\%$).
- **Repeat Scam Vulnerability:** Tỷ lệ người dùng bị lừa tiếp lần 2 (đặc biệt là Recovery Scam) sau khi đã được bảo vệ trên hệ sinh thái (Proposed Target: giảm $80\%$ so với nhóm đối chứng).

## 3.5 Trust & UX Metrics
- **Warning Comprehension Score:** Điểm đánh giá mức độ dễ hiểu của cảnh báo qua khảo sát in-app định kỳ ($\ge 4.5/5.0$).
- **Net Promoter Score (NPS):** Đo lường trên cả 2 nhóm: Người dùng và Người thân/Người giám hộ ($\text{Target NPS} \ge 50$).

## 3.6 Privacy-Preserving Telemetry: Đo Lường Metrics Tách Rời Nội Dung (Content) Khỏi Sự Kiện (Events)
Để đảm bảo toàn bộ các chỉ số trên được thống kê **chính xác 100%** trong khi vẫn bảo vệ tuyệt đối bí mật đời tư (không đọc hay lưu trữ nội dung tin nhắn trên Cloud), hệ thống áp dụng cơ chế viễn trắc sự kiện ẩn danh:

```
[Tin nhắn SMS] ──▶ [Local Rule Engine (<5ms)] ──▶ [Hiện cảnh báo trên máy]
                            │                                  │
                            ▼                                  ▼
                 Event: MESSAGE_ANALYZED             Event: USER_ACTION_TAKEN
                 (risk_score, matched_rules)         (action: BLOCK, time: 8.5s)
                            │                                  │
                            └─────────────────┬────────────────┘
                                              ▼
                                 [Local SQLite Event Queue]
                                              │ (Batch Sync 15 phút/lần)
                                              ▼
                                 [Cloud Product Analytics DB]
                                  -> Tính toán SDR, FPR, Funnel
```

1. **Phân tách rạch ròi giữa Content và Event:**
   - Nội dung tin nhắn nằm lại 100% trong CSDL của điện thoại.
   - Gói tin sự kiện (`product_analytics_event`) gửi lên Cloud **chỉ chứa dữ liệu số học và mã định danh ẩn danh**: `anonymous_device_id`, `user_risk_level` (`HIGH`/`UNKNOWN`/`LOW`), `risk_score` (0–100), `internal_severity`, `matched_rule_codes` (mảng mã quy tắc), `action_type` (`BLOCK_SENDER`, `MARK_AS_SAFE`...), và `pause_duration_seconds`.
2. **Local Queueing & Batch Sync (Chống mất số liệu & Tiết kiệm pin):**
   - Sự kiện được lưu tạm vào hàng đợi SQLite trên thiết bị. Cứ 15 phút hoặc khi kết nối Wi-Fi/4G ổn định, client nén và gửi một gói batch lên Cloud Analytics Endpoint.
   - Đảm bảo **Zero Data Loss**: Nếu người dùng đi máy bay hoặc ở tầng hầm không có sóng, sự kiện vẫn được giữ nguyên và tự động đồng bộ bù khi có mạng.
3. **Công thức tính toán tự động trên Dashboard (BigQuery / BI Tool):**
   - $\text{SDR} = \frac{\text{COUNT}(\text{action\_type} \in [\text{'BLOCK\_SENDER'}, \text{'REPORT\_SCAM'}, \text{'CALL\_FAMILY'}])}{\text{COUNT}(\text{event\_name} = \text{'MESSAGE\_ANALYZED'} \text{ AND } \text{user\_risk\_level} = \text{'HIGH'})} \times 100\%$
   - $\text{FPR} = \frac{\text{COUNT}(\text{action\_type} = \text{'MARK\_AS\_SAFE'})}{\text{COUNT}(\text{event\_name} = \text{'MESSAGE\_ANALYZED'} \text{ AND } \text{user\_risk\_level} = \text{'HIGH'})} \times 100\%$

---

# 4. Detailed Requirements

## 4.1 Functional Requirements

### FR-01 — Message Ingestion Permission & Consent
- **Mô tả:** Hệ thống chỉ được phép thu thập và phân tích tin nhắn khi có sự cho phép rõ ràng từ người dùng.
- **Quy tắc:**
  - Giải thích mục đích bằng ngôn ngữ đơn giản trước khi mở System Permission dialog.
  - Phân tách quyền đọc SMS của OS (`READ_SMS`, `RECEIVE_SMS`) và sự đồng thuận xử lý dữ liệu (`Data Processing Consent`).
  - Cho phép người dùng bật/tắt tính năng bất kỳ lúc nào trong Cài đặt.
  - Lưu trữ lịch sử cấp/thu hồi quyền để phục vụ tuân thủ pháp lý.

### FR-02 — Real-time Message Detection
- **Mô tả:** Tự động lắng nghe và thu nhận tin nhắn mới đến thiết bị theo thời gian thực (Real-time Ingestion).
- **Quy tắc:**
  - Hoạt động ổn định ở chế độ chạy nền (Background service) trên Android mà không bị OS tắt đột ngột (tối ưu Battery Optimization).
  - Thu nhận: Số/Tên người gửi, thời gian nhận, loại kênh (SMS).
  - Khởi tạo quá trình xử lý ẩn danh ngay tại client trước khi truyền về server.

### FR-03 — Hybrid Message Analysis (Rule Engine + AI Engine)
- **Mô tả:** Đánh giá rủi ro nội dung bằng cơ chế lai đa tầng:
  - **Tầng 1 (Rule & Pattern Engine — Sub-50ms Fast Check):** Chạy cục bộ trên client/gateway bằng thuật toán đối sánh từ điển Aho-Corasick và Regex Token-Distance. Nhận diện ngay lập tức các mẫu lừa đảo đã biết, kiểm tra danh sách đen/trắng Brandname, kiểm tra tên miền độc hại/lookalike và định tuyến điểm rủi ro cơ sở. Đảm bảo bảo vệ offline 100% khi mất mạng.
  - **Tầng 2 (AI/ML Semantic Analysis — Cloud/Edge Fallback):** Khi tin nhắn không rơi vào các mẫu cứng của Rule Engine, mô hình NLP/LLM tiếng Việt phân tích ngữ nghĩa, nhận diện ý đồ đe dọa, hứa hẹn phi lý hoặc kỹ thuật thao túng tâm lý (Social Engineering).
- **Quy tắc:** Nếu kết nối mạng gián đoạn hoặc AI service quá tải, Rule Engine cục bộ đảm bảo đưa ra mức độ bảo vệ cơ sở với độ trễ $\le 50\text{ms}$.

### FR-03b — Dedicated Phone & URL Blacklists with Multi-Source Ingestion (Admin, Community, AI Crawler)
- **Mô tả:** Hệ thống phân tách độc lập hai danh mục quản lý danh sách đen: Danh sách đen Số điện thoại/Brandname (`blacklist_phone_number`) và Danh sách đen Đường link/Tên miền (`blacklist_url_domain`). Cả hai danh mục được thiết kế mở để liên tục tiếp nhận dữ liệu từ 3 nguồn cập nhật:
  1. **Nguồn 1: Quản trị viên & Chuyên gia SecOps (`ADMIN`):** Nhập trực tiếp các số điện thoại/tên miền đã được cơ quan chức năng hoặc ngân hàng xác minh (Trust level 100%, trạng thái `VERIFIED_SCAM`, kích hoạt chặn/cảnh báo ngay lập tức).
  2. **Nguồn 2: Cộng đồng người dùng báo cáo (`COMMUNITY`):** Cho phép người dùng bấm *"Báo cáo tin nhắn lừa đảo"* kèm nội dung/ảnh chụp. Áp dụng thuật toán gom nhóm và ngưỡng biểu quyết tự động:
     - Dưới 3 lượt báo cáo độc lập: Ghi nhận vết, xếp mức cảnh báo thận trọng `UNKNOWN`.
     - Từ 5 đến 9 lượt báo cáo độc lập: Tự động nâng mức cảnh báo `SUSPICIOUS`.
     - Từ 10 lượt báo cáo độc lập trở lên: Tự động đưa vào danh sách đen tạm thời (`COMMUNITY_FLAGGED`) và tạo cảnh báo ưu tiên cao cho Admin phê duyệt chính thức.
  3. **Nguồn 3: Trí tuệ nhân tạo cào dữ liệu tự động (`AI_CRAWLER`):** Bot AI tự động quét liên tục các nguồn tin tức chính thống, cổng cảnh báo Bộ Công An, Cục An toàn thông tin (NCSC / `khonggianmang.vn`), và các kênh cảnh báo uy tín. Sử dụng mô hình NLP trích xuất số điện thoại, link giả mạo kèm điểm tin cậy `ai_confidence_score`:
     - Nếu `ai_confidence_score >= 0.95`: Tự động đồng bộ vào Blacklist với nhãn `AUTO_AI_FLAGGED`.
     - Nếu `0.70 <= ai_confidence_score < 0.95`: Đưa vào hàng đợi Admin để duyệt nhanh 1-chạm (One-Click Approval).
- **Vòng đời & Hạn chế sai số (Lifecycle & Decay):**
  - Số điện thoại có cơ chế thời hạn hết lực (`expires_at`, mặc định 180 - 360 ngày) để phòng tránh việc chặn oan người dân khi nhà mạng thu hồi SIM rác và cấp lại cho người dùng mới.
  - Tên miền có cơ chế kiểm tra trạng thái sống/chết (DNS Resolution & WHOIS Expiration).

### FR-04 — Calibrated Scam Risk Signals (20 Tín Hiệu Rủi Ro Chuẩn Hóa)
- **Mô tả:** Trích xuất các dấu hiệu rủi ro nguyên tử (Atomic Risk Signals) được hiệu chuẩn trọng số thực nghiệm qua 20 bộ test cases tại Việt Nam:

| Mã Tín Hiệu | Nhóm Tín Hiệu | Trọng số ($w_i$) | Mô tả Tín Hiệu & Dấu hiệu Kích hoạt |
|---|---|:---:|---|
| `SIG_OTP_REQUEST` | FINANCIAL / CREDENTIAL | **25** | Yêu cầu cung cấp mã OTP, mã xác thực một lần, mật khẩu ngân hàng. |
| `SIG_BANK_ACCOUNT_HARVEST` | FINANCIAL | **20** | Khai thác thông tin tài khoản ngân hàng, số thẻ, mã CVV/CVC, tên đăng nhập. |
| `SIG_URGENT_ACTION` | LINGUISTIC | **15** | Thúc ép thời gian khẩn cấp ("ngay lập tức", "trước 12h", "hạn chót hôm nay"). |
| `SIG_SUSPICIOUS_URL` | TECHNICAL | **20** | Chứa liên kết URL rút gọn (`tinyurl`, `bit.ly`), tên miền lạ hoặc IP trực tiếp. |
| `SIG_IMPERSONATION_GOV` | IMPERSONATION | **25** | Mạo danh Công an, CSGT, Viện kiểm sát, Tòa án, Thuế, cơ quan VNeID. |
| `SIG_IMPERSONATION_BANK` | IMPERSONATION | **20** | Mạo danh ngân hàng hoặc tổ chức tín dụng (Vietcombank, BIDV, MB...). |
| `SIG_LEGAL_THREAT` | PSYCHOLOGICAL | **20** | Đe dọa pháp lý, khởi tố hình sự, bắt tạm giam, phong tỏa tài khoản, phạt nguội. |
| `SIG_UNOFFICIAL_SENDER` | SENDER | **15** | Số gửi là số di động cá nhân (+84...) nhưng nội dung xưng danh cơ quan/tổ chức. |
| `SIG_MONEY_TRANSFER` | FINANCIAL | **20** | Yêu cầu chuyển tiền, nạp tiền vào số tài khoản hoặc ví điện tử chỉ định. |
| `SIG_RECOVERY_PROMISE` | FRAUD_SCENARIO | **30** | Hứa hẹn hỗ trợ lấy lại tiền bị lừa, thu hồi tiền treo, luật sư an ninh mạng. |
| `SIG_UPFRONT_FEE` | FINANCIAL | **25** | Yêu cầu nộp phí trước (phí bảo lãnh, phí hồ sơ, phí mở cổng xác thực). |
| `SIG_JOB_OFFER` | FRAUD_SCENARIO | **15** | Mời chào làm cộng tác viên online, xem video/nghe nhạc/đánh giá sản phẩm. |
| `SIG_FINANCIAL_INVESTMENT` | FINANCIAL | **20** | Dụ dỗ nạp tiền tham gia sàn đầu tư tài chính, giao dịch chứng khoán, tiền ảo. |
| `SIG_UNREALISTIC_COMMISSION`| FINANCIAL | **20** | Hứa hẹn hoa hồng phi lý, việc nhẹ lương cao ("kiếm 500k-2tr/ngày sau 30 phút"). |
| `SIG_TELEGRAM_MIGRATION` | BEHAVIORAL | **15** | Hướng dẫn kết bạn Zalo/Telegram kín để nhận nhiệm vụ hoặc tài liệu mật. |
| `SIG_IMPERSONATION_RELATIVE`| IMPERSONATION | **20** | Giả mạo con cháu, người thân, bạn bè nhắn tin hỏi thăm rồi vay mượn. |
| `SIG_URGENT_BORROW` | FINANCIAL | **20** | Viện cớ đang cấp cứu, phẫu thuật gấp hoặc cần chuyển tiền cọc gấp để vay. |
| `SIG_BANK_CHANGE_REASON` | BEHAVIORAL | **15** | Biện minh tài khoản chính chủ bị lỗi/hỏng thẻ nên phải chuyển vào tài khoản lạ. |
| `SIG_APK_DOWNLOAD` | TECHNICAL | **30** | Dụ dỗ bấm link tải file ứng dụng `.apk` cài ngoài Google Play. |
| `SIG_HOMOGLYPH_BRAND` | TECHNICAL | **25** | Tên miền typo/homoglyph mạo danh thương hiệu (ví dụ: `vietcombank-ib.top`). |

- **Khả năng mở rộng:** Danh mục tín hiệu được quản lý động tại backend qua bảng `risk_signal_definition` (chi tiết tại [Rules & Patterns ERD](file:///d:/Me%20mine/PM/UXCamp/Scam%20alert/scam_alert_check_link_4/Scam_Detection_Rules_Patterns_ERD.md)).

### FR-05 — Scam Category & Scenario Classification
- **Mô tả:** Phân loại tin nhắn vào 6 kịch bản trọng điểm tại Việt Nam và các danh mục chuẩn hóa:
  - `SCEN_BANK_IMPERSONATION_OTP` (Mạo danh Ngân hàng / Đánh cắp OTP)
  - `SCEN_GOV_TRAFFIC_FINE` (Mạo danh Công an / CSGT / Phạt nguội)
  - `SCEN_VNEID_LAND_UPDATE_FRAUD` (Mạo danh Công an / Địa chính cập nhật Sổ đỏ trên VNeID)
  - `SCEN_SOCIAL_TAKEOVER_LOAN` (Chiếm quyền Zalo/FB / Vay tiền gấp)
  - `SCEN_JOB_OFFER_TELEGRAM` (Bẫy tuyển CTV / Nhiệm vụ Telegram hoàn vốn)
  - `SCEN_RECOVERY_SCAM` (Lừa đảo thu hồi vốn / Hỗ trợ tiền treo)
  - `OTHER_SCAM` (Các hình thức lừa đảo khác)

### FR-06 — Two-Tier Risk Classification & Calibrated Scoring Logic

#### A. Internal Risk Engine (Backend & Analytics)
Hệ thống backend duy trì đầy đủ các thông số chi tiết phục vụ mô hình máy học, luật chính sách và kiểm thử hồi quy:
- **Risk Score ($S$):** Thang điểm liên tục `0 – 100`, tính toán theo công thức kết hợp đa tín hiệu kèm hệ số tương tác (Synergy Multiplier):
  $$S = \min\left(100,\; \left(\sum_{i=1}^{n} w_i \times \text{confidence}_i\right) \times M_{\text{synergy}}\right)$$
  - Trong đó $M_{\text{synergy}} = 1.20$ nếu tin nhắn chứa đồng thời $\ge 3$ tín hiệu rủi ro khác nhau.
- **Detection Confidence:** Mức độ tin cậy của thuật toán (`HIGH`, `MEDIUM`, `LOW`).
- **Internal Severity:** Mức độ nghiêm trọng nội bộ (`NORMAL`, `HIGH`, `CRITICAL`).
- **Scam Signals:** Danh sách mã tín hiệu phát hiện được kèm `evidence_snippet`.

Bảng ánh xạ kỹ thuật nội bộ (Internal Reference):
| Internal Score | Internal Level | Mục đích nội bộ |
|:---:|:---:|---|
| 0 – 39 | LOW | Baseline an toàn, tin nhắn bình thường hoặc quảng cáo hợp pháp |
| 40 – 69 | MEDIUM | Tin nhắn có yếu tố đáng ngờ nhưng chưa đủ bằng chứng kết luận |
| 70 – 84 | HIGH | Dấu hiệu lừa đảo rõ ràng |
| 85 – 100 | CRITICAL | Kịch bản nguy hiểm nghiêm trọng (mạo danh công an, đòi OTP, mã độc APK, recovery scam) |

#### B. User-Facing Risk Level (Trải nghiệm người dùng)
Người dùng **tuyệt đối không** nhìn thấy thang điểm 0–100 hay điểm số kỹ thuật. Hệ thống chỉ hiển thị 3 trạng thái định hướng hành động:

| User Level | System Interpretation | User Action | Notification Policy |
|---|---|---|---|
| **🟢 LOW** | No significant risk detected | Có thể tiếp tục bình thường | Không gửi thông báo làm phiền (Silent) |
| **⚪ UNKNOWN** | Insufficient evidence / low confidence ($40 \le S < 70$) | **Verify before action** (Kiểm chứng trước khi hành động) | Hiển thị nhẹ nhàng khi mở tin nhắn / trước hành động có rủi ro |
| **🔴 HIGH** | Significant scam indicators ($S \ge 70$) | **PAUSE → VERIFY → DECIDE** | Push & In-app warning nổi bật |
| **🔴 HIGH + Critical Internal** *(Sub-state nội bộ)* | Severe / high-confidence threat ($S \ge 85$) | **DO NOT PROCEED** + Cân nhắc nhờ người thân hỗ trợ | Cảnh báo toàn màn hình mạnh mẽ + Family Alert (nếu đã consent) |

#### C. Quy tắc phân loại đa biến (Multi-Factor Classification Logic)
```text
// Logic ánh xạ rủi ro đã được hiệu chuẩn qua 20 test cases:
FUNCTION DetermineUserRisk(risk_score, confidence, detected_signals, category):
    // 1. Kiểm tra trường hợp bất định / thiếu cơ sở (UNKNOWN)
    IF confidence == "LOW" OR (risk_score >= 40 AND risk_score < 70 AND NOT HasCriticalSignal(detected_signals)):
        RETURN { 
            user_level: "UNKNOWN", 
            internal_severity: "NORMAL" 
        }

    // 2. Nguy cơ tối khẩn (HIGH + Critical Internal)
    IF (risk_score >= 85 AND confidence == "HIGH") 
       OR HasCriticalSignal(detected_signals, ["SIG_OTP_REQUEST", "SIG_APK_DOWNLOAD", "SIG_RECOVERY_PROMISE", "SIG_IMPERSONATION_GOV"]):
        RETURN { 
            user_level: "HIGH", 
            internal_severity: "CRITICAL" 
        }

    // 3. Nguy cơ cao thông thường (HIGH)
    IF risk_score >= 70:
        RETURN { 
            user_level: "HIGH", 
            internal_severity: "HIGH" 
        }

    // 4. Mặc định là an toàn cơ bản (LOW)
    RETURN { 
        user_level: "LOW", 
        internal_severity: "NORMAL" 
    }
```

**Các tình huống thực tế minh họa:**
- **Case A (Risk Score 25, Confidence High, không có tín hiệu nguy hiểm):**  
  $\to$ **User Level: `LOW`**. Người dùng không bị làm phiền.
- **Case B (Risk Score 45, Confidence Low, tin nhắn lạ có link rút gọn chưa rõ nguồn gốc):**  
  $\to$ **User Level: `UNKNOWN`**. Khuyên người dùng kiểm tra trước khi bấm link.
- **Case C (Risk Score 72, Confidence High, có tín hiệu thúc ép + hứa hẹn trúng thưởng):**  
  $\to$ **User Level: `HIGH` (Internal Severity: `HIGH`)**. Cảnh báo đỏ, yêu cầu dừng lại xác minh.
- **Case D (Risk Score 92, Confidence High, mạo danh Công an dọa bắt + ép chuyển tiền):**  
  $\to$ **User Level: `HIGH` (Internal Severity: `CRITICAL`)**. Cảnh báo đỏ mức độ cao nhất, đề xuất kết nối người thân khẩn cấp.

### FR-07 — Plain-Language Risk Explanation
- **Mô tả:** Bắt buộc phải có phần giải thích nguyên nhân bằng ngôn ngữ đời thường, tôn trọng, không tạo cảm giác người dùng già yếu hay phán xét.
- **Ví dụ hiển thị:**
  - *"Tin nhắn này có 3 dấu hiệu nguy hiểm:"*
    - *"1. Bắt Bác phải chuyển trước 5 triệu tiền phí."*
    - *"2. Thúc ép Bác phải làm gấp trước 12h trưa nay."*
    - *"3. Số gửi là số di động cá nhân nhưng lại xưng là Cơ quan Ngân hàng."*

### FR-08 — Contextual User Warning Interface (Thiết kế theo 3 mức trải nghiệm)

#### 1. Giao diện mức 🟢 LOW
- **Nguyên tắc:** Hoàn toàn không gây phiền (Non-intrusive).
- **Hành vi:** Không gửi Push Notification. Nếu người dùng chủ động mở chi tiết tin nhắn trong ứng dụng bảo vệ, hiển thị nhãn phụ:  
  *🟢 Mức độ rủi ro thấp: Chưa phát hiện dấu hiệu đáng ngờ.*  
  *(Tuyệt đối không dùng từ ngữ cam kết tuyệt đối như "Tin nhắn này chắc chắn an toàn 100%" để tránh tạo tâm lý chủ quan).*

#### 2. Giao diện mức ⚪ UNKNOWN
- **Nguyên tắc:** Truyền đạt sự bất định (Uncertainty) và khuyến nghị kiểm chứng; không gây hoang mang nhưng không được hiểu là an toàn.
- **Hành vi:**
  - Không gửi Push Notification hàng loạt.
  - Hiển thị thông báo nhẹ (Inline banner) khi người dùng mở tin nhắn hoặc chuẩn bị bấm vào liên kết trong tin nhắn:  
    *⚪ Chưa thể xác định độ an toàn*  
    *Hệ thống chưa có đủ thông tin để khẳng định tin nhắn này có an toàn hay không. Nếu tin nhắn yêu cầu chuyển tiền, cung cấp OTP hoặc tải file, Bác hãy kiểm tra kỹ trước khi thực hiện.*
  - **CTAs:**
    - `[Kiểm tra với Trợ lý AI]`
    - `[Xem các dấu hiệu cần chú ý]`
    - `[Tôi vẫn muốn tiếp tục]`

#### 3. Giao diện mức 🔴 HIGH
- **Nguyên tắc:** Tạo khoảng dừng an toàn (**Pause → Verify → Decide**), ngăn chặn hành vi bốc đồng.
- **Hành vi:**
  - Bắn Push Notification ưu tiên cao và hiển thị In-app Warning nổi bật.
  - Cỡ chữ lớn ($\ge 18\text{pt}$), màu sắc nhận diện đỏ/cam cảnh báo rõ nét.
  - Thông điệp chính:  
    *🔴 Nguy cơ lừa đảo cao*  
    *Tin nhắn này có nhiều dấu hiệu thường xuất hiện trong các vụ lừa đảo. Khoan thực hiện giao dịch, hãy kiểm tra trước!*
  - Liệt kê: Danh mục lừa đảo + Các tín hiệu rủi ro chính + Khuyến nghị hành động.
  - **CTAs:**
    - `[📞 Gọi điện thoại cho con ngay: 0912.334.455]` (Nổi bật hàng đầu, 1 chạm)
    - `[🔊 Nghe lại lời cảnh báo bằng giọng nói]` (Web Speech API)
    - `[Báo cáo lừa đảo & Chặn số]`
    - `(Bác vẫn muốn bỏ qua cảnh báo?)`

#### 4. Giao diện mức 🔴 HIGH + Critical Internal (Tối Ưu Cho Người Cao Tuổi)
- **Nguyên tắc:** Cảnh báo bằng đa giác quan (Hình ảnh + Âm thanh giọng nói tiếng Việt); kích hoạt trực giác an toàn cho người già.
- **Hành vi:**
  - Vẫn hiển thị nhãn **`🚨 CẢNH BÁO: RỦI RO CỰC KỲ CAO`**.
  - **Tích hợp Web Speech API (Text-to-Speech):** Tự động đọc to lời dặn bằng tiếng Việt với giọng điệu ân cần, tốc độ chậm rãi (`rate = 0.9`):  
    > *"Bác chú ý! Đây là tin nhắn lừa đảo nguy hiểm. Bác tuyệt đối không bấm vào đường link và không chuyển tiền. Cháu đã gửi thông báo đến điện thoại con của bác rồi. Bác hãy bấm nút màu đỏ trên màn hình để gọi cho con ngay nhé!"*
  - Kèm nút bấm điều khiển âm thanh: **"🔊 Nghe Lại Lời Cảnh Báo Bằng Giọng Nói"** và **"🔇 Tắt Đọc"**.
  - **Nút Bấm 1 Chạm "Gọi Điện Thoại Cho Con Ngay":**  
    - Liên kết trực tiếp: `href="tel:+84912334455"`.
    - Thiết kế nổi bật: Nền đỏ viền sáng, hiệu ứng nhịp thở thu hút (`pulseAlertGlow`), biểu tượng điện thoại rung lắc nhẹ (`wigglePhone`).
    - Cỡ chữ to, rõ ràng: *"Số điện thoại con: 0912.334.455 (Bác bấm vào đây để gọi hỏi con ngay!)"*.

### FR-09 — Tối Ưu Hóa Trải Nghiệm & Tôn Trọng Quyền Tự Quyết
- **Nguyên tắc cốt lõi:** Bảo vệ mà không tước đoạt quyền tự chủ của người cao tuổi.
- **Quyết định thiết kế quan trọng:** **KHÔNG BỔ SUNG cơ chế "Moment of Pause Friction" (không ẩn hoặc làm mờ nút copy mã OTP/STK trong 30 giây)** nhằm tránh gây ức chế, hoang mang hoặc làm rối trí người lớn tuổi.
- Thay vào đó, hệ thống tập trung tạo sự chú ý tự nhiên thông qua **giọng đọc Web Speech API thân thiện** và **nút gọi điện thoại cho con cái 1 chạm** để người cao tuổi chủ động xin ý kiến người thân trước khi thao tác.

### Ver 2 - FR-10 — Verify with AI (Conversational Safety Assistant)
- **Mô tả:** Cung cấp giao diện hỏi đáp dạng hội thoại để người dùng trò chuyện tự nhiên với Trợ lý An toàn (hỗ trợ cho cả tin nhắn `HIGH` và `UNKNOWN`):
  - Gợi ý sẵn các câu hỏi nhanh:
    - *"Tại sao tin này lại đáng ngờ hả cháu?"*
    - *"Có đúng công an nhắn tin triệu tập qua SMS không?"*
    - *"Bác có nên chuyển 5 triệu để nhận thưởng không?"*
  - Trả lời bằng giọng điệu kính cẩn, chân thành, giải thích cụ thể kịch bản lừa đảo mà không dùng thuật ngữ kỹ thuật khó hiểu.

### FR-11 — Safety Event Management
- **Mô tả:** Mỗi lần phát hiện rủi ro `HIGH` (bao gồm cả trường hợp có `internal_severity = CRITICAL`), hệ thống tạo một thực thể `Safety Event`.
- **Nội dung:** Lưu trữ trạng thái sự cố (`OPEN`, `ALERTED`, `ESCALATED`, `RESOLVED`, `FALSE_ALARM`), danh mục lừa đảo, các tín hiệu phát hiện, `user_risk_level`, `internal_severity` và liên kết tới các hành động can thiệp.

### FR-12 — User Action Recording & Feedback Loop
- **Mô tả:** Ghi nhận đầy đủ tương tác của người dùng đối với cảnh báo:
  - `IGNORE`: Không phản hồi.
  - `DISMISS`: Đóng cảnh báo.
  - `VIEW_DETAILS`: Đọc giải thích chi tiết.
  - `MARK_AS_SAFE`: Đánh dấu tin nhắn an toàn (phản hồi dương tính giả).
  - `REPORT_SCAM`: Xác nhận lừa đảo và gửi thêm thông tin.
  - `BLOCK_SENDER`: Yêu cầu chặn liên lạc.
  - Ver 2 - `CALLED_GUARDIAN`: Thực hiện cuộc gọi cho con cái từ nút bấm 1 chạm trên màn hình cảnh báo.
- **Mục đích:** Cung cấp dữ liệu kiểm toán và làm tập nhãn (Ground Truth) cải tiến mô hình.

### Ver 2 - FR-13 — Privacy-Preserving Family Escalation (Push Notification 0 VNĐ)
- **Điều kiện kích hoạt duy nhất:** Chỉ áp dụng cho các sự kiện **`HIGH + Critical Internal`** (nguy cơ lừa đảo đặc biệt nghiêm trọng) VÀ người dùng **đã chủ động đồng ý (opt-in consent)** trong cài đặt.
- **Kênh thông báo & Chi phí:** Sử dụng cổng **Push Notification (Google FCM / Apple APNS) với chi phí 0 VNĐ** gửi trực tiếp vào ứng dụng của con cái/người bảo trợ. (Kênh SMS Brandname được để lại làm giải pháp dự phòng cho tương lai).
- **Quy tắc bảo vệ quyền riêng tư:**
  - Người thân **tuyệt đối không** được nhận toàn văn tin nhắn gốc của người cao tuổi.
  - Người thân chỉ nhận **Bản tóm tắt nguy cơ chuẩn hóa (Sanitized Push Alert)**:  
    *🚨 [SCAMSHIELD KHẨN CẤP] Kính gửi Nguyễn Hoàng Nam (Con trai): Hệ thống vừa phát hiện và chặn một tin nhắn lừa đảo nguy hiểm gửi tới Bác Nguyễn Văn A từ +84908123456. Vui lòng gọi điện thoại trực tiếp cho Bác ngay để dặn dò không bấm link và không chuyển tiền!*

### FR-14 — Adaptive Protection against Recovery Scams
- **Mô tả:** Nếu hồ sơ người dùng từng ghi nhận sự cố bị lừa đảo trong quá khứ:
  - Hệ thống tự động nâng độ nhạy đối với các tin nhắn chứa từ khóa: *"thu hồi tiền treo"*, *"hỗ trợ lấy lại tiền"*, *"luật sư an ninh mạng"*, *"phí hồ sơ giải ngân"*.
  - Tự động gán nhãn **`HIGH`** với `internal_severity = CRITICAL` và hiển thị cảnh báo chuyên biệt:  
    *Cảnh báo lừa đảo lần 2: Tuyệt đối không có cơ quan hay dịch vụ nào có thể thu hồi tiền bị lừa bằng cách yêu cầu đóng thêm phí.*

### FR-15 — Historical Re-analysis & Immutable Versioning
- **Mô tả:** Khi cập nhật Rule Engine mới hoặc nâng cấp mô hình AI, hệ thống có khả năng phân tích lại các tin nhắn cũ.
- **Quy tắc:**
  - Kết quả phân tích mới được lưu thành bản ghi bổ sung (`append-only`), không ghi đè bản ghi cũ.
  - Lưu trữ đầy đủ cả `user_risk_level`, `risk_score`, `internal_severity` và phiên bản mô hình để phục vụ đánh giá hồi quy (đã tinh giản loại bỏ `internal_risk_level`).

### FR-16 — Rule Governance & Four-Eyes Principle (Nguyên tắc 4 mắt)
- **Mô tả:** Mọi quy tắc và mẫu nhận diện (Rules & Patterns) trên Production phải tuân thủ quy trình kiểm soát chất lượng nghiêm ngặt (Maker-Checker):
  - **Quy trình phê duyệt bắt buộc:** Người tạo rule (SecOps / Fraud Analyst) chỉ có quyền soạn thảo ở trạng thái `DRAFT` hoặc đưa vào môi trường kiểm thử ngầm `STAGED` (Shadow Mode).
  - **Phê duyệt độc lập:** Bắt buộc phải có ít nhất 1 Fraud Lead hoặc Security Architect kiểm tra độ an toàn logic, kiểm thử hồi quy (Regression Test) chống False Positive trước khi bấm duyệt (`APPROVED`) và phát hành (`ACTIVE`).
  - **Lưu vết kiểm toán:** Ghi lại đầy đủ `created_by`, `reviewed_by`, `approved_by`, `published_at` và `change_reason` trong cơ sở dữ liệu.

### FR-17 — Automated Retention Purge & Permanent Hard Delete
- **Mô tả:** Triệt tiêu hoàn toàn rủi ro rò rỉ dữ liệu cá nhân theo Nghị định 13/2023/NĐ-CP:
  - **Kiến trúc Zero Raw Storage:** Hệ thống tuyệt đối không lưu trữ nội dung thô `raw_content_encrypted` trên Cloud Server. Mọi suy luận diễn ra tại máy.
  - **Tin nhắn mức 🟢 LOW (an toàn):** Hệ thống kích hoạt Cronjob tự động thực hiện **Xóa vĩnh viễn (Hard Delete)** bản làm sạch `redacted_content` sau đúng **30 ngày** kể từ thời điểm nhận tin (`retention_until = received_at + 30 days`).
  - **Tin nhắn mức 🔴 HIGH (sự kiện an toàn / báo cáo lừa đảo):** Lưu trữ tối đa **90 ngày** phục vụ gom mẫu chiến dịch và huấn luyện mô hình AI tập trung; sau 90 ngày cũng tự động purge.
  - **Xóa theo yêu cầu:** Khi người dùng thu hồi quyền hoặc yêu cầu xóa tài khoản, toàn bộ dữ liệu tin nhắn của thiết bị được hard delete ngay lập tức trong vòng $\le 24$ giờ.

### FR-18 — Privacy-Preserving Telemetry & Batch Event Synchronization
- **Mô tả:** Phân tách rạch ròi giữa nội dung tin nhắn và dữ liệu viễn trắc sản phẩm nhằm phục vụ đo lường chỉ số (SDR, FPR, Funnel):
  - **Zero Content Leak:** Tuyệt đối không gửi nội dung tin nhắn hoặc thông tin định danh cá nhân (PII) trong các gói tin viễn trắc sự kiện.
  - **Local Event Queue:** Mỗi khi phân tích tin nhắn hoặc người dùng tương tác cảnh báo, một sự kiện ẩn danh (`MESSAGE_ANALYZED`, `WARNING_SHOWN`, `USER_ACTION_TAKEN`) được ghi nhận vào SQLite hàng đợi nội bộ trên máy.
  - **Batch Synchronization:** Định kỳ 15 phút một lần hoặc khi có kết nối mạng ổn định, client nén các sự kiện và gửi theo lô về Cloud Analytics Database (`product_analytics_event`).
  - **Offline Resilience:** Nếu mất mạng, các sự kiện vẫn được bảo toàn trong hàng đợi thiết bị và tự động đồng bộ bù khi có kết nối trở lại, đảm bảo Zero Data Loss cho dữ liệu phân tích sản phẩm.

### FR-19 — Local-First Backbone & Cloud-Assisted K-Anonymity Threat Lookup (2% Unknowns)
- **Mô tả:** Kết hợp tối ưu giữa tốc độ siêu nhanh của On-Device Rule Engine và độ nhạy Zero-day của Cloud Threat Intel:
  - **Local-First (98% tin nhắn):** Xử lý tức thì < 5ms ngay tại RAM thiết bị thông qua AST Rule Engine và bộ lọc Bloom Filter cục bộ. Tin nhắn `LOW` và `HIGH` rõ ràng được giải quyết 100% không cần gọi mạng.
  - **K-Anonymity Cloud Lookup (2% link lạ / UNKNOWN):** Khi gặp tên miền hoặc liên kết rút gọn chưa từng xuất hiện trong bộ nhớ máy, ứng dụng áp dụng chuẩn **K-Anonymity (tương tự Google Safe Browsing)**:
    - Client băm URL thành SHA-256 và **chỉ gửi 4 bytes đầu (8 ký tự hex)** lên máy chủ.
    - Máy chủ tra cứu bảng `cloud_hash_prefix_index` và trả về danh sách các full hash khớp tiền tố.
    - Client tiến hành so khớp mã băm đầy đủ ngay trong RAM thiết bị.
    - **Cam kết riêng tư:** Máy chủ tuyệt đối không biết người dùng đang bấm vào trang web cụ thể nào.

### FR-20 — Apple iOS IdentityLookup Architecture Compatibility Spec
- **Mô tả:** Đảm bảo hệ thống vận hành hoàn hảo trên hệ sinh thái Apple iOS mà không vi phạm chính sách quyền riêng tư khắt khe của App Store:
  - **Sandbox Extension:** Đóng gói AST Rule Engine vào `ILMessageFilterExtension`.
  - **Quy trình phân loại 3 tầng:**
    - `ILMessageFilterAction.none` (Cho phép hiển thị bình thường khi `LOW`).
    - `ILMessageFilterAction.promotion` (Lọc vào tab Tin nhắn quảng cáo khi `UNKNOWN`).
    - `ILMessageFilterAction.junk` (Tự động đưa vào mục Tin nhắn rác khi `HIGH`, subAction = `.scam`).
  - **Offline-to-Online Handshake:** Khi ở chế độ OfflineAction, extension tự xử lý. Khi cần K-Anonymity, extension kích hoạt `networkAction` gửi 4-byte prefix lên endpoint chuyên dụng được đăng ký với Apple.

---

## 4.2 Non-Functional Requirements (NFR)

### Privacy & Data Protection (Zero Raw Storage Architecture)
- **Local-First Inference (Edge):** Toàn bộ quy trình quét phân tích diễn ra trực tiếp trên thiết bị của người dùng thông qua Rule Engine (< 5ms, 0% FPR). Tin nhắn thường nhật không bao giờ bị gửi lên Cloud Server.
- **Thu thập dữ liệu huấn luyện AI & Tình báo cộng đồng (One-Time Consent & Auto-Telemetry):**
  - **Tự động gửi mẫu khi phát hiện nguy cơ (Opt-In):** Người dùng chỉ cần cấp quyền 1 lần trong phần cài đặt/onboarding (`auto_telemetry_consent = true`). Khi thiết bị phát hiện tin nhắn có mức rủi ro **🔴 HIGH** hoặc **⚪ UNKNOWN**, ứng dụng tự động khử sạch PII (`redacted_content`), sinh mã băm SHA-256 (`content_hash`, `sender_hash`) và gửi ngầm về Cloud Threat Intel mà người dùng **không cần phải bấm nút báo cáo mỗi lần**, giảm thiểu gánh nặng thao tác cho người già và người dùng phổ thông.
  - **Duy trì nút báo cáo thủ công (Fallback):** Nếu người dùng không đồng ý cấp quyền tự động (`auto_telemetry_consent = false`), hệ thống sẽ không tự ý gửi bất kỳ tin nào. Thay vào đó, mỗi tin nhắn rủi ro sẽ có nút bấm *"Báo cáo tin nhắn lừa đảo"* để người dùng chủ động bấm gửi theo ý muốn.
  - **Tin nhắn 🟢 LOW (An toàn):** Tuyệt đối **KHÔNG** gửi telemetry lên Cloud trong mọi trường hợp, triệt tiêu 100% rủi ro lộ lọt tin nhắn riêng tư.
- **Tập dữ liệu AI chuẩn hóa:** Mô hình AI (PhoBERT / LLM) chỉ được huấn luyện trên `redacted_content`, đảm bảo AI học ngữ cảnh lừa đảo mà không bao giờ bị nhiễm dữ liệu cá nhân thật của người dùng.
- Tuân thủ đầy đủ Nghị định 13/2023/NĐ-CP và các quy định pháp luật về bảo vệ dữ liệu cá nhân.

### Performance & Latency (Calibrated Targets)
- **Local Triage Latency:** Rule Engine cục bộ hoàn tất kiểm tra trong vòng $\le 50\text{ms}$ (Thực tế kiểm thử: $15 - 35\text{ms}$).
- **End-to-End Warning Latency:** Cảnh báo hiển thị trên màn hình trong vòng $\le 1.5$ giây kể từ khi tin nhắn đến máy (trong điều kiện có mạng).
- **Client Battery Impact:** Dịch vụ nền tiêu thụ $\le 1.0\%$ tổng lượng pin thiết bị mỗi ngày.

### Reliability & Graceful Degradation
- Lỗi kết nối mạng hoặc lỗi server AI tuyệt đối không làm ứng dụng bị treo hoặc thoát đột ngột (Crash-free rate $\ge 99.9\%$).
- Khi mất kết nối internet, hệ thống tự động chuyển sang chế độ bảo vệ cơ sở (Offline Rule Engine) và đồng bộ phân tích chi tiết khi có mạng trở lại.

### Accessibility (Thiết kế cho người lớn tuổi)
- Hỗ trợ Dynamic Type, cỡ chữ tối thiểu ở màn hình cảnh báo là $18\text{pt}$, độ tương phản màu (Color Contrast Ratio) đạt chuẩn WCAG 2.1 AA ($\ge 4.5:1$).
- Nút bấm to, khoảng cách chạm (Touch target) tối thiểu $48 \times 48\text{dp}$ để người già tay run hoặc mắt kém không bấm trượt.
- Hỗ trợ đọc to nội dung cảnh báo bằng giọng nói (Text-to-Speech) bằng tiếng Việt tự nhiên.

---

# 5. User Types & Access Matrix

## 5.1 Primary User: Người dùng / Người cao tuổi (Protected User)
- **Mục tiêu:** Được bảo vệ an toàn khi dùng điện thoại, không bị lừa mất tiền, giữ được sự tự chủ và tôn nghiêm.
- **Nhu cầu:** Cảnh báo rõ ràng, dễ hiểu theo 3 mức (LOW, UNKNOWN, HIGH), có người hỗ trợ khi bối rối, không bị con cái kiểm soát quá đà.
- **Quyền hạn:** Toàn quyền bật/tắt tính năng, quyết định thêm/xóa người thân bảo trợ, quyết định hành động cuối cùng đối với tin nhắn.
- **Phạm vi hiển thị:** Xem tin nhắn của mình, xem chi tiết cảnh báo, xem lịch sử các lần được bảo vệ.

## Ver 2 - 5.2 Secondary User: Người thân tin cậy (Trusted Family Contact)
- **Mục tiêu:** Kịp thời biết khi bố mẹ gặp mối nguy hại nghiêm trọng để can thiệp ngăn chặn, an tâm khi ở xa.
- **Nhu cầu:** Chỉ nhận cảnh báo khi có sự cố nghiêm trọng (`HIGH + Critical Internal`), không bị spam, nắm được loại hình lừa đảo để gọi hỗ trợ bố mẹ kịp thời.
- **Quyền hạn:** Nhận thông báo đẩy/SMS khẩn cấp, bấm nút gọi nhanh cho bố mẹ từ thông báo, đánh dấu xác nhận đã xử lý sự cố.
- **Phạm vi hiển thị:** **Chỉ xem được bản tóm tắt nguy cơ chuẩn hóa** (Risk summary) và thông tin đối tượng nghi vấn. **Tuyệt đối không xem được nội dung tin nhắn riêng tư** của bố mẹ.

## 5.3 Internal User: Đội ngũ An toàn & Gian lận (Fraud & Safety Analysts)
- **Mục tiêu:** Giám sát các chiến dịch lừa đảo mới phát sinh, tối ưu hóa bộ quy tắc phát hiện, giảm thiểu báo nhầm.
- **Quyền hạn:** Cấu hình trọng số tín hiệu (`signal_catalog`), bổ sung từ khóa Rule Engine, điều tra các phản hồi `MARK_AS_SAFE` (False Positive).
- **Phạm vi hiển thị:** Truy cập đầy đủ dữ liệu nội bộ (`risk_score`, `confidence`, `internal_severity`, `detected_signals`), xem dữ liệu đã làm sạch PII (`redacted_content`), xem các chỉ số thống kê tổng hợp (Aggregated Analytics).

## Ver 2 - 5.4 Internal User: Đội ngũ AI/ML & Data Engineering
- **Mục tiêu:** Đo lường độ chính xác mô hình, huấn luyện mô hình NLP mới, kiểm thử hồi quy (Regression Testing).
- **Quyền hạn:** Truy cập tập dữ liệu kiểm thử ẩn danh, quản lý phiên bản mô hình trên Model Registry.
- **Phạm vi hiển thị:** Vector embeddings, phân bổ điểm rủi ro liên tục (0–100), ma trận nhầm lẫn (Confusion Matrix), không truy cập PII định danh.

---

# 6. Analytics & Event Tracking

## 6.1 Core Tracking Events

| Tên Event | Thời điểm kích hoạt | Ý nghĩa phân tích |
|---|---|---|
| `message_received` | Thiết bị phát hiện có tin nhắn mới đến | Đo lường lưu lượng tin nhắn đầu vào |
| `message_analysis_started` | Pipeline phân tích bắt đầu xử lý | Đo lường độ trễ hàng đợi |
| `message_analysis_completed`| Hoàn tất tính điểm và phân loại | Đo lường hiệu năng và phân bổ điểm số |
| `risk_detected` | Phân tích cho kết quả `user_risk_level = HIGH` hoặc `UNKNOWN` | Theo dõi tỷ lệ tin nhắn rủi ro trong quần thể |
| `safety_event_created` | Khởi tạo sự kiện an toàn cho `HIGH` (bao gồm `Critical Internal`) | Bắt đầu phễu can thiệp bảo vệ |
| `warning_shown` | Màn hình cảnh báo hiển thị trước mắt user | Đo lường tỷ lệ phân phối cảnh báo theo cấp độ |
| `warning_viewed` | User tương tác hoặc dừng lại xem cảnh báo | Đo lường tỷ lệ tiếp nhận cảnh báo |
| `verify_with_ai_clicked` | User bấm vào hỏi Trợ lý AI từ cảnh báo | Đo lường nhu cầu tương tác giải thích |
| `user_action_taken` | User chọn một hành động cụ thể | Ghi nhận phản ứng thực tế của người dùng |
| `family_alert_triggered` | Hệ thống gửi cảnh báo tới người thân (`HIGH + Critical Internal`) | Đo lường tỷ lệ kích hoạt leo thang gia đình |
| `family_alert_acknowledged`| Người thân bấm xác nhận đã nắm thông tin | Đo lường tốc độ phản hồi của gia đình |
| `analysis_failed` | Quá trình phân tích gặp sự cố kỹ thuật | Theo dõi độ ổn định hệ thống |

## 6.2 Event Properties
Mỗi sự kiện được đính kèm các thuộc tính chuẩn hóa, phân tách rõ ràng giữa trường dữ liệu User-facing và trường dữ liệu Kỹ thuật nội bộ:

### User-facing fields
- `user_risk_level`: `LOW`, `UNKNOWN`, `HIGH`.
- `scam_category`: Tên danh mục hiển thị cho người dùng.
- `displayed_signals_count`: Số lượng dấu hiệu được giải thích trên UI.

### Internal technical fields (Data & ML Analysis)
- `risk_score`: Điểm rủi ro liên tục (0.00 – 100.00).
- `confidence`: Độ tin cậy thuật toán (`HIGH`, `MEDIUM`, `LOW`).
- `internal_severity`: `NORMAL`, `HIGH`, `CRITICAL` (xác định mức độ phá hoại & điều phối leo thang gia đình).
- `detected_signals`: Mảng JSON các tín hiệu phát hiện định dạng rút gọn `[{"sig": "OTP_REQUEST", "pts": 40.00}]` (lưu trữ trực tiếp trong `scam_analysis`, có Backend Schema Validation).
- `ai_model_version`: Phiên bản AI model.
- `rule_set_version`: Phiên bản Rule Engine.
- `action_type`: `DISMISS`, `BLOCK_SENDER`, `MARK_AS_SAFE`, `CALL_FAMILY`, `VERIFY_AI`.
- `time_to_action_ms`: Thời gian từ lúc hiện cảnh báo đến khi user ra quyết định.

## 6.3 Decision Safety Funnel
Phễu phân tích hiệu quả bảo vệ từ đầu đến cuối:

$$\begin{aligned}
\text{1. Message Received} &\longrightarrow \text{2. Message Analyzed} \\
&\longrightarrow \text{3. High Risk Detected (User Level = HIGH)} \\
&\longrightarrow \text{4. Warning Shown on Device} \\
&\longrightarrow \text{5. Warning Viewed & Moment of Pause Engaged} \\
&\longrightarrow \text{6. Verified with AI / Family Contacted} \\
&\longrightarrow \mathbf{7.\; Safe\; Decision\; Reached\; (Blocked / Ignored / No Funds Sent)}
\end{aligned}$$

## 6.4 Key Business Questions mà Analytics phải trả lời
1. Có bao nhiêu tin nhắn được quét mỗi ngày, và tỷ lệ phân bổ `LOW` / `UNKNOWN` / `HIGH` là bao nhiêu?
2. Tỷ lệ người dùng thực hiện kiểm chứng đối với tin nhắn `UNKNOWN` (UNKNOWN $\to$ Verification Rate) là bao nhiêu?
3. Nhóm thủ đoạn lừa đảo nào đang bùng phát mạnh nhất trong các tin nhắn `HIGH` tuần qua?
4. Khi nhận cảnh báo `HIGH`, người cao tuổi dành trung bình bao nhiêu giây để đọc trước khi bấm nút?
5. Tỷ lệ người dùng bấm `Bỏ qua` (tiếp tục hành động mạo hiểm) là bao nhiêu, và lý do phổ biến là gì?
6. Tỷ lệ báo nhầm (False Positive) là bao nhiêu, tập trung vào các nhà mạng hay ngân hàng nào?
7. Người thân mất trung bình bao nhiêu phút để liên lạc lại với bố mẹ sau khi nhận được Family Alert?

---

# 7. Rollout Timeline & Phasing

```mermaid
gantt
    title Kế hoạch triển khai tính năng Scam Message Detection
    dateFormat  YYYY-MM
    section Discovery
    User & Scam Research       :done,    d1, 2026-01, 2026-02
    Privacy & Tech Feasibility  :done,    d2, 2026-02, 2026-03
    section Phase 1 (MVP)
    SMS Ingestion & Rule Engine :active,  p1_1, 2026-03, 2026-04
    3-Level UX & Warning Engine :active,  p1_2, 2026-04, 2026-05
    Pilot Testing (500 users)  :         p1_3, 2026-05, 2026-06
    section Phase 2 (Intelligence)
    AI/ML Semantic Engine      :         p2_1, 2026-06, 2026-07
    Explainability & Verify AI :         p2_2, 2026-07, 2026-08
    Recovery Scam Protection   :         p2_3, 2026-08, 2026-09
    section Phase 3 (Family Shield)
    Trusted Contact Setup      :         p3_1, 2026-09, 2026-10
    Privacy-First Escalation   :         p3_2, 2026-10, 2026-11
    Public Launch (All Users)  :         p3_3, 2026-11, 2026-12
    section Phase 4 (Multi-Channel)
    Call Transcript & OTT Apps :         p4_1, 2027-01, 2027-04
```

- **Phase 0 — Discovery:** Nghiên cứu hành vi người lớn tuổi, khảo sát các kịch bản lừa đảo thực tế tại Việt Nam, đánh giá tính khả thi về quyền Android SMS và rà soát pháp lý bảo vệ dữ liệu.
- **Phase 1 — MVP (Baseline Safety & 3-Level UX):** Triển khai thu nhận SMS, Rule Engine cục bộ, bộ phân loại rủi ro 3 mức (`LOW`, `UNKNOWN`, `HIGH`), cảnh báo `HIGH` kèm danh sách lý do trực quan, các nút hành động cơ bản (`Chặn`, `Bỏ qua`). Thử nghiệm kín trên 500 người dùng.
- **Phase 2 — Intelligence & Explainability:** Đưa mô hình AI/ML NLP vào suy luận ngữ nghĩa, tối ưu độ tin cậy (Confidence Engine), tích hợp tính năng "Hỏi trợ lý AI" và cơ chế bảo vệ đặc biệt trước Recovery Scam.
- **Phase 3 — Family Safety:** Hoàn thiện cơ chế ủy quyền người thân (`Trusted Contact`), điều phối cảnh báo gia đình cho các trường hợp `HIGH + Critical Internal` tôn trọng riêng tư và ra mắt diện rộng.
- **Phase 4 — Multi-channel Expansion:** Mở rộng quét tin nhắn OTT (Zalo, Messenger qua Notification Listener) và cảnh báo đường link trong cuộc gọi/tin nhắn thoại.

---

# 8. Dependencies & Integrations

| Hạng mục | Thành phần phụ thuộc | Loại | Mục đích & Đánh giá rủi ro |
|---|---|:---:|---|
| **Platform** | Android `READ_SMS` / `RECEIVE_SMS` | **Required** | Đọc nội dung tin nhắn. Rủi ro: Chính sách Google Play kiểm duyệt gắt gao với quyền SMS nhạy cảm; cần chuẩn bị video giải trình rõ tính năng an toàn. |
| | Android Battery Optimization Whitelist | **Required** | Giúp Background Service không bị hệ thống tắt khi máy ngủ. |
| | iOS SMS Filter Extension | *Optional* | iOS chặn quyền đọc SMS trực tiếp; phải xây dựng giải pháp Extension riêng biệt cho bản iPhone. |
| **AI / ML** | Vietnamese Fraud LLM / NLP Service | **Required** | Phân tích ngữ nghĩa tiếng Việt, trích xuất confidence và intent. Cần có fallback local rule engine khi server AI quá tải. |
| | Rule Engine Service | **Required** | Lọc nhanh các mẫu cố định và số điện thoại blacklist với độ trễ siêu thấp. |
| **Security** | Cloud KMS (Key Management Service) | **Required** | Quản lý khóa mã hóa phong bì (Envelope Encryption) cho nội dung tin nhắn nhạy cảm. |
| | PII Redaction Pipeline | **Required** | Tự động làm sạch số thẻ, OTP trước khi gửi tới AI service hoặc ghi log. |
| **Backend** | Ingestion & Risk Scoring Service | **Required** | Tiếp nhận dữ liệu, tính toán Risk Score + Confidence và phân loại sang User Risk Level. |
| | Push Notification Service (FCM/APNS)| **Required** | Phát thông báo khẩn cấp tới máy người già và máy con cái. |
| **External** | Phone/Brandname Reputation Registry | *Optional* | Tra cứu số điện thoại lừa đảo đã bị cộng đồng báo cáo (Cục An toàn thông tin / Chống Lừa Đảo). |
| | Malicious URL Scanner API | *Optional* | Kiểm tra nhanh độ an toàn của đường link rút gọn có trong nội dung. |

---

# 9. Requirement Prioritization & Acceptance Criteria

| ID | Tên Requirement | Mức ưu tiên | Thuộc MVP? | Acceptance Criteria (Given — When — Then) |
|---|---|:---:|:---:|---|
| **FR-01** | Message Permission | **P0** | **Có** | **Given:** Người dùng mở ứng dụng lần đầu.<br>**When:** Ứng dụng yêu cầu quyền SMS.<br>**Then:** Hiển thị màn hình giải thích mục đích bảo vệ trước; sau khi người dùng đồng ý mới mở System Dialog; lưu trạng thái đồng thuận vào hệ thống. |
| **FR-02** | Real-time Ingestion | **P0** | **Có** | **Given:** Thiết bị đã cấp quyền SMS.<br>**When:** Có tin nhắn SMS mới gửi đến máy.<br>**Then:** Background service bắt được sự kiện trong vòng $\le 500\text{ms}$, mã hóa nội dung và đẩy về pipeline phân tích. |
| **FR-03** | Rule Engine Analysis | **P0** | **Có** | **Given:** Tin nhắn mới được thu nhận.<br>**When:** Đi qua Rule Engine.<br>**Then:** Bóc tách các từ khóa nóng, kiểm tra link và số điện thoại trong vòng $\le 300\text{ms}$. |
| **FR-04** | Signal Extraction | **P0** | **Có** | **Given:** Tin nhắn chứa dấu hiệu đe dọa hoặc đòi tiền.<br>**When:** Hoàn tất phân tích.<br>**Then:** Trả về danh sách các `signal_code` kèm bằng chứng trích dẫn (`evidence_snippet`). |
| **FR-06.1** | **Risk Level: LOW** | **P0** | **Có** | **Given:** Tin nhắn không chứa dấu hiệu lừa đảo đáng kể.<br>**When:** Phân tích hoàn tất.<br>**Then:** Gán `user_risk_level = LOW`; không phát Push Notification làm phiền; không gửi cảnh báo gia đình; người dùng tiếp tục bình thường. |
| **FR-06.2** | **Risk Level: UNKNOWN** | **P0** | **Có** | **Given:** Hệ thống chưa đủ bằng chứng hoặc mô hình có độ tin cậy thấp (`confidence = LOW`).<br>**When:** Phân tích hoàn tất.<br>**Then:** Gán `user_risk_level = UNKNOWN`; không báo động đỏ; hiển thị khuyến nghị kiểm chứng nhẹ nhàng khi mở tin nhắn hoặc trước khi bấm link. |
| **FR-06.3** | **Risk Level: HIGH** | **P0** | **Có** | **Given:** Tin nhắn chứa nhiều dấu hiệu lừa đảo rõ ràng.<br>**When:** Phân tích hoàn tất.<br>**Then:** Gán `user_risk_level = HIGH`; hiển thị Push & In-app Warning nổi bật; nêu rõ lý do cảnh báo; tạo khoảng dừng an toàn (Pause → Verify → Decide). |
| **FR-06.4** | **Risk Level: HIGH + Critical Internal** | **P0** | **Có** | **Given:** Tin nhắn chứa các dấu hiệu cực kỳ nghiêm trọng (mạo danh công an, đòi OTP gấp, dụ cài APK) với độ tin cậy cao.<br>**When:** Phân tích hoàn tất.<br>**Then:** Gán `user_risk_level = HIGH` và `internal_severity = CRITICAL`; hiển thị cảnh báo mức cao nhất; kích hoạt Family Alert nếu người dùng đã opt-in. |
| **FR-07** | Risk Explanation | **P0** | **Có** | **Given:** Tin nhắn được đánh giá mức `HIGH`.<br>**When:** Cảnh báo hiển thị.<br>**Then:** Liệt kê từ $1 - 3$ lý do cụ thể bằng tiếng Việt đời thường, dễ hiểu, tránh thuật ngữ kỹ thuật. |
| **FR-08** | High-Risk Warning | **P0** | **Có** | **Given:** Một SMS được xếp mức `HIGH`.<br>**When:** Người dùng mở tin nhắn / mở điện thoại.<br>**Then:** Hiển thị giao diện cảnh báo nổi bật, chữ to $\ge 18\text{pt}$, có các nút hành động: Kiểm tra với AI, Báo người thân, Chặn số, Bỏ qua. |
| **FR-09** | Moment of Pause | **P0** | **Có** | **Given:** Cảnh báo nguy hiểm `HIGH` đang hiển thị.<br>**When:** Người dùng bấm bỏ qua.<br>**Then:** Xuất hiện bước xác nhận nhắc nhở bình tĩnh kiểm tra trước khi chuyển tiền; không block cưỡng bức. |
| **FR-10** | Verify with AI | **P1** | Không (Phase 2) | **Given:** Người dùng bấm nút "Hỏi trợ lý an toàn" từ tin nhắn `HIGH` hoặc `UNKNOWN`.<br>**When:** Người dùng hỏi câu hỏi tự nhiên.<br>**Then:** AI phản hồi bằng ngôn từ ân cần, giải thích cặn kẽ kịch bản lừa đảo trong vòng $\le 3$ giây. |
| **FR-11** | Safety Event Creation| **P0** | **Có** | **Given:** Một phiên phân tích đạt mức `HIGH`.<br>**When:** Hoàn thành phân loại.<br>**Then:** Tự động tạo bản ghi `safety_event` với trạng thái `OPEN` để quản lý vòng đời sự cố. |
| **FR-12** | User Action Tracking | **P0** | **Có** | **Given:** Người dùng tương tác với màn hình cảnh báo.<br>**When:** Bấm chọn một nút bất kỳ.<br>**Then:** Lưu lại hành động (`BLOCK_SENDER`, `MARK_AS_SAFE`...) vào bảng dữ liệu kiểm toán và cập nhật `safety_event`. |
| **FR-13** | Family Escalation | **P1** | Không (Phase 3) | **Given:** User đã opt-in bảo vệ gia đình và tin nhắn đạt mức `HIGH + Critical Internal`.<br>**When:** Sự kiện an toàn được kích hoạt.<br>**Then:** Gửi bản tóm tắt nguy cơ chuẩn hóa (không chứa tin nhắn gốc) tới máy người thân đã ủy quyền. |
| **FR-14** | Recovery Scam Guard | **P1** | Không (Phase 2) | **Given:** Người dùng từng có lịch sử bị lừa tiền.<br>**When:** Nhận tin nhắn hứa hẹn lấy lại tiền, đòi phí giải ngân.<br>**Then:** Tự động nâng mức cảnh báo lên `HIGH` (`internal_severity = CRITICAL`) và hiển thị cảnh báo chuyên biệt về lừa đảo bồi hoàn. |
| **FR-15** | Immutable Re-analysis| **P1** | Không (Phase 2) | **Given:** Một tin nhắn cũ được quét lại bởi mô hình AI mới.<br>**When:** Có kết quả rủi ro mới.<br>**Then:** Lưu bản ghi phân tích mới kèm phiên bản model; giữ nguyên bản ghi phân tích cũ để đối chiếu kiểm toán. |
| **FR-16** | Four-Eyes Rule Governance | **P0** | **Có** | **Given:** SecOps soạn thảo Rule/Pattern mới.<br>**When:** Đề xuất ban hành ra Production.<br>**Then:** Rule phải ở trạng thái `DRAFT`/`STAGED`; bắt buộc có Fraud Lead duyệt (`APPROVED`) mới được kích hoạt `ACTIVE`. |
| **FR-17** | Automated Hard Delete (30 Days) | **P0** | **Có** | **Given:** Tin nhắn được đánh giá mức `LOW`.<br>**When:** Quá thời hạn 30 ngày (`retention_until <= NOW()`).<br>**Then:** Cron job thực hiện Hard Delete vĩnh viễn bản ghi `redacted_content` khỏi cơ sở dữ liệu (hệ thống không lưu trữ `raw_content_encrypted`). |
| **FR-18** | Privacy-Preserving Telemetry | **P0** | **Có** | **Given:** Tin nhắn được phân tích hoặc người dùng tương tác cảnh báo.<br>**When:** Sự kiện phát sinh trên thiết bị.<br>**Then:** Ghi nhận event ẩn danh vào hàng đợi cục bộ; tự động đồng bộ theo lô về Cloud Analytics Database phục vụ đo lường SDR, FPR, Funnel mà không gửi kèm nội dung tin nhắn. |
| **FR-19** | Local-First & K-Anonymity Fallback | **P0** | **Có** | **Given:** Tin nhắn đến thiết bị.<br>**When:** Quét trên máy (98% On-Device). Với 2% trường hợp URL/nghi vấn, máy khách chỉ gửi 4-byte hash prefix (8 hex) lên Cloud.<br>**Then:** Tra cứu K-Anonymity bảo vệ riêng tư tuyệt đối, đối chiếu full SHA-256 trên RAM client; gửi telemetry ẩn danh khi rủi ro HIGH/UNKNOWN theo consent 1 lần. |
| **FR-20** | Streamlined Schema & iOS IdentityLookup | **P0** | **Có** | **Given:** Thiết bị chạy trên Android hoặc iOS.<br>**When:** Tương thích kiến trúc iOS `ILMessageFilterExtension` và cơ sở dữ liệu tinh gọn.<br>**Then:** Ánh xạ 3 trạng thái phân loại (`junk`, `promotion`, `allow`); bảng `device` được gộp vào `user`, bảng `scam_category` được chuyển hóa thành kiểu `scam_category_type` ENUM để tối ưu hiệu năng. |

---

# 10. Appendix & Illustrations

## 10.1 Chi tiết mô hình phân cấp rủi ro (Risk Level Architecture)

### Master Table: User-facing Experience
| User Level | System Interpretation | User Action | Notification Policy |
|:---:|---|---|---|
| **🟢 LOW** | No significant risk detected ($S < 40$) | Có thể tiếp tục bình thường | Không làm phiền (Silent) |
| **⚪ UNKNOWN** | Insufficient evidence / low confidence ($40 \le S < 70$) | **Verify before action** (Kiểm tra trước khi hành động) | Hiển thị nhẹ nhàng khi mở tin nhắn hoặc trước thao tác có rủi ro |
| **🔴 HIGH** | Significant scam indicators ($S \ge 70$) | **PAUSE → VERIFY → DECIDE** | Push & In-app warning nổi bật |
| **🔴 HIGH + Critical Internal** *(Policy State)* | Severe / high-confidence threat ($S \ge 85$ hoặc có critical signal) | **DO NOT PROCEED** + Cân nhắc nhờ người thân hỗ trợ | Cảnh báo toàn màn hình mạnh mẽ + Family Alert (nếu đã consent) |

*Ghi chú: `HIGH + Critical Internal` không phải là một user-facing level riêng biệt, mà là một trạng thái chính sách nội bộ (Internal Policy/Severity State) nằm bên trong mức HIGH để kích hoạt phản ứng khẩn cấp cao nhất.*

### Bảng đối chiếu giữa Tầng Kỹ thuật nội bộ và Trải nghiệm người dùng
| Internal Score (0–100) | Confidence | Signals & Threat Severity | User-Facing Level | Internal Severity |
|:---:|:---:|---|:---:|:---:|
| 0 – 39 | High / Medium | Không có tín hiệu đáng ngờ (Tin OTP ngân hàng chính thống, SMS gia đình) | **🟢 LOW** | NORMAL |
| Bất kỳ | **Low** | Thiếu bằng chứng kết luận, link lạ chưa phân tích xong | **⚪ UNKNOWN** | NORMAL |
| 40 – 69 | Medium / High | Có 1 vài dấu hiệu nhưng chưa đủ khẳng định lừa đảo nguy hiểm | **⚪ UNKNOWN** | NORMAL |
| 70 – 84 | High / Medium | Có nhiều tín hiệu lừa đảo rõ ràng | **🔴 HIGH** | HIGH |
| 85 – 100 | **High** | Kịch bản lừa đảo tối khẩn (Mạo danh công an, đòi OTP gấp, mã độc APK, Recovery scam) | **🔴 HIGH** | **CRITICAL** |

## 10.2 5 Kịch bản mẫu giả lập đã kiểm thử thành công (Tested Scam Scenarios)

### Mẫu 1: Mạo danh Cơ quan CSGT Phạt nguội (`SCEN_GOV_TRAFFIC_FINE`)
> *"Cuc Canh sat Giao thong C08 thong bao: Phuong tien bien so 29A-888.88 cua ong/ba vi pham chay qua toc do. Vui long truy cap https://cucgiaothong-phatnguoi.site/tra-cuu de nop phat truc tuyen truoc ngay 12/10/2026. Qua han se bi truy cuu trach nhiem hinh su va tam giu phuong tien."*
- **Tín hiệu kích hoạt:** `SIG_IMPERSONATION_GOV` (25), `SIG_SUSPICIOUS_URL` (20), `SIG_LEGAL_THREAT` (20), `SIG_URGENT_ACTION` (15).
- **Đánh giá nội bộ:** Điểm thô $80$, áp dụng Synergy Multiplier ($1.2\times$) $\to$ Risk Score: **$96.0$**, Confidence: **HIGH**.
- **Kết quả:** **User Level: `🔴 HIGH`** | **Internal Severity: `CRITICAL`**.

### Mẫu 2: Mạo danh Ngân hàng / Đánh cắp OTP (`SCEN_BANK_IMPERSONATION_OTP`)
> *"Vietcombank Digibank: Tai khoan cua Quy khach vua dang nhap tai thiet bi la tai Ha Noi luc 02:15. Neu khong phai ban, vui long nhan vao https://vietcombank-ib-xacthuc.top de huy uy nhiem va nhap ma OTP de xac minh ngay lap tuc."*
- **Tín hiệu kích hoạt:** `SIG_IMPERSONATION_BANK` (20), `SIG_HOMOGLYPH_BRAND` (25), `SIG_SUSPICIOUS_URL` (20), `SIG_OTP_REQUEST` (25), `SIG_URGENT_ACTION` (15).
- **Đánh giá nội bộ:** Risk Score: **$100.0$** (Cap max), Confidence: **HIGH**.
- **Kết quả:** **User Level: `🔴 HIGH`** | **Internal Severity: `CRITICAL`**.

### Mẫu 3: Chiếm quyền MXH / Vay tiền khẩn cấp (`SCEN_SOCIAL_TAKEOVER_LOAN`)
> *"Mẹ ơi con đang ở bệnh viện làm thủ tục cấp cứu gấp cho cháu nhưng thẻ ngân hàng của con bị khóa. Mẹ chuyển gấp 15 triệu vào STK 1903... tên Tran Van B rồi trưa con bảo chồng con chuyển khoản trả lại mẹ ngay nhé."*
- **Tín hiệu kích hoạt:** `SIG_IMPERSONATION_RELATIVE` (20), `SIG_URGENT_BORROW` (20), `SIG_BANK_CHANGE_REASON` (15), `SIG_MONEY_TRANSFER` (20).
- **Đánh giá nội bộ:** Điểm thô $75 \times 1.2 = 90.0$, Confidence: **HIGH**.
- **Kết quả:** **User Level: `🔴 HIGH`** | **Internal Severity: `CRITICAL`**.

### Mẫu 4: Tuyển CTV Online / Nhiệm vụ Telegram hoàn vốn (`SCEN_JOB_OFFER_TELEGRAM`)
> *"Tiktok Shop tuyen dung cong tac vien danh gia san pham tai nha cho nguoi lon tuoi. Chi can co dien thoai, luong ngay tu 500k - 2 trieu tra ve tai khoan sau 30 phut. Lien he Telegram @trolyshopee de nhan nhiem vu nạp tiền hoàn vốn."*
- **Tín hiệu kích hoạt:** `SIG_JOB_OFFER` (15), `SIG_UNREALISTIC_COMMISSION` (20), `SIG_TELEGRAM_MIGRATION` (15), `SIG_FINANCIAL_INVESTMENT` (20).
- **Đánh giá nội bộ:** Điểm $70 \times 1.2 = 84.0$, Confidence: **HIGH**.
- **Kết quả:** **User Level: `🔴 HIGH`** | **Internal Severity: `HIGH`**.

### Mẫu 5: Lừa đảo Thu hồi tiền lừa đảo (`SCEN_RECOVERY_SCAM`)
> *"Văn phòng Luật sư An ninh mạng & Thu hồi vốn: Chúng tôi đã tiếp nhận hồ sơ bị treo 200 triệu của Bác. Cổng thanh toán quốc tế đã phong tỏa số tiền này. Bác cần nộp 5 triệu phí pháp lý và mở cổng xác minh để nhận lại toàn bộ tiền về tài khoản ngân hàng."*
- **Tín hiệu kích hoạt:** `SIG_RECOVERY_PROMISE` (30), `SIG_UPFRONT_FEE` (25), `SIG_MONEY_TRANSFER` (20), `SIG_IMPERSONATION_GOV` (25).
- **Đánh giá nội bộ:** Điểm thô $100.0$, Critical Signal `SIG_RECOVERY_PROMISE`.
- **Kết quả:** **User Level: `🔴 HIGH`** | **Internal Severity: `CRITICAL`**.

### Mẫu 6: Tin nhắn Chưa đủ cơ sở kết luận (`UNKNOWN`)
> *"Chao anh/chi, don hang #9821 cua ban da ve kho. Vui long kiem tra tinh trang kien hang tai https://tinyurl.com/don-hang-9821."*
- **Tín hiệu kích hoạt:** `SIG_SUSPICIOUS_URL` (20), thiếu các tín hiệu đe dọa hoặc thúc ép tiền bạc.
- **Đánh giá nội bộ:** Risk Score $20.0$, tuy nhiên chứa liên kết rút gọn chưa phân giải được tên miền đích $\to$ Confidence: **LOW**.
- **Kết quả:** **User Level: `⚪ UNKNOWN`** | **Internal Severity: `NORMAL`**.

### Mẫu 7: Tin nhắn Hợp pháp / Bình thường (`LOW`)
> *"Vietcombank: Ma OTP cua Quy khach la 849201 de xac thuc giao dich thanh toan so tien 200,000 VND tai Shopee. Ma co hieu luc trong 3 phut. KHONG chia se OTP cho bat ky ai."*
- **Tín hiệu kích hoạt:** Brandname chuẩn `Vietcombank` (thuộc Whitelist), có cảnh báo bảo mật chính thống, không chứa liên kết URL mạo danh, không đe dọa.
- **Đánh giá nội bộ:** Risk Score: **$0.0$**, Confidence: **HIGH**.
- **Kết quả:** **User Level: `🟢 LOW`** | **Internal Severity: `NORMAL`** (Không gửi cảnh báo, tự động xóa vĩnh viễn sau 30 ngày).

## 10.3 Warning UX Mockups & Copywriting Guidelines

### UX Thông báo mức độ ⚪ UNKNOWN
```text
+-------------------------------------------------------+
| ⚪  CHƯA THỂ XÁC ĐỊNH ĐỘ AN TOÀN                      |
|                                                       |
| Hệ thống chưa có đủ thông tin để xác định tin nhắn này |
| có an toàn hay không.                                 |
|                                                       |
| Lời khuyên: Nếu tin nhắn yêu cầu chuyển tiền, cung    |
| cấp OTP hoặc bấm vào link, Bác hãy kiểm tra trước     |
| khi thực hiện.                                        |
|                                                       |
| [ 🤖 Hỏi Trợ lý An toàn ]  [ 🔍 Xem dấu hiệu cần chú ý ]|
|                                                       |
|             ( Tôi hiểu và muốn tiếp tục )             |
+-------------------------------------------------------+
```

### UX Cảnh báo mức độ 🔴 HIGH
```text
+-------------------------------------------------------+
| 🛑  KHOAN CHUYỂN TIỀN! NGUY CƠ LỪA ĐẢO CAO            |
|                                                       |
| Tin nhắn này có 3 dấu hiệu đáng ngờ rất rõ ràng:      |
|                                                       |
| • Giục giã phải làm gấp trước 17h hôm nay             |
| • Yêu cầu chuyển trước 3 triệu đồng tiền phí          |
| • Dùng số điện thoại cá nhân mạo danh công ty lớn     |
|                                                       |
| [ 🤖 Hỏi Trợ lý An toàn ]     [ 🚫 Chặn số người gửi ]|
|                                                       |
| [ 📞 Gọi hỏi ý kiến người thân ]                       |
|                                                       |
|               ( Bác vẫn muốn bỏ qua cảnh báo này? )   |
+-------------------------------------------------------+
```

### UX Cảnh báo mức độ 🔴 HIGH + Critical Internal
```text
+-------------------------------------------------------+
| 🚨  CẢNH BÁO NGUY HIỂM: NGUY CƠ LỪA ĐẢO RẤT CAO!      |
|                                                       |
| Phát hiện thủ đoạn mạo danh Cơ quan Nhà nước / Đòi OTP|
|                                                       |
| Bác tuyệt đối:                                        |
| ❌ KHÔNG chuyển tiền vào bất kỳ tài khoản nào          |
| ❌ KHÔNG cung cấp mật khẩu, mã OTP                     |
| ❌ KHÔNG tải hoặc cài đặt ứng dụng theo hướng dẫn     |
|                                                       |
| [ 📞 GỌI CHO CON GÁI (CHỊ LAN) ĐỂ ĐƯỢC HỖ TRỢ NGAY ]   |
|                                                       |
| [ 🤖 Kiểm tra chi tiết với AI ]    [ 🚫 Chặn số này ] |
|                                                       |
|               ( Bác tự chịu trách nhiệm và tiếp tục? )|
+-------------------------------------------------------+
```

## 10.4 Out of Scope (Những điều sản phẩm KHÔNG làm trong MVP)
1. **Không tự động khẳng định tin nhắn "SAFE tuyệt đối":** Không dùng các từ ngữ tạo cảm giác an toàn giả tạo (False sense of security). Mức thấp nhất là `LOW` ("Chưa phát hiện dấu hiệu đáng ngờ").
2. **Không tự động block cứng mọi tin nhắn HIGH:** Hệ thống không tự ý tước đoạt quyền tự chủ của người dùng nếu họ chủ động khẳng định đây là giao dịch hợp lệ của họ.
3. **Không tự động gửi cảnh báo gia đình cho mọi tin nhắn HIGH:** Family Alert chỉ được kích hoạt cho các trường hợp đặc biệt nghiêm trọng (`HIGH + Critical Internal`) và bắt buộc phải có sự đồng ý (opt-in consent) từ trước.
4. **Không để lộ điểm số thô (Raw Score) hay tỷ lệ phần trăm mô hình cho người dùng:** Người dùng không cần hiểu "72 điểm" hay "Confidence 86%" nghĩa là gì; họ chỉ cần biết rõ: LOW, UNKNOWN, HIGH và hành động tiếp theo nên làm.
5. **Không tự động can thiệp vào tài khoản ngân hàng:** Không tích hợp tính năng tự đóng băng thẻ hay tự hủy lệnh chuyển tiền của banking app.
6. **Không tự động xóa tin nhắn SMS gốc của máy:** Việc xóa dữ liệu phần cứng có thể gây mất chứng cứ pháp lý hoặc làm người dùng bối rối khi tìm lại tin nhắn.
7. **Không đọc lén hội thoại riêng tư:** Tuyệt đối không đọc danh bạ hay tin nhắn cá nhân để xây dựng tập profile quảng cáo.

## 10.5 Open Questions cần làm rõ trước khi chốt mã nguồn
1. **Quyền SMS trên Google Play Store:** Google có chính sách rất khắt khe đối với `RECEIVE_SMS`. Team Legal & Product cần hoàn tất hồ sơ chứng minh sản phẩm thuộc danh mục "Safety Companion" để được phê duyệt quyền trên Play Console.
2. **Chiến lược xử lý nền tảng iOS:** Do iOS không cho app bên thứ ba đọc SMS tự do, lộ trình trải nghiệm trên iPhone sẽ như thế nào? (Đề xuất: Người dùng chụp màn hình tin nhắn để app phân tích qua OCR hoặc chia sẻ link vào app).
3. **Ngưỡng kích hoạt UNKNOWN:** Cần bao nhiêu dữ liệu đánh giá thực tế từ Pilot để tinh chỉnh ranh giới giữa UNKNOWN và HIGH nhằm tránh làm người dùng bị hoang mang khi gặp tin nhắn UNKNOWN?
4. **Cơ chế chống bão thông báo (Alert Fatigue):** Nếu kẻ xấu gửi spam 10 tin nhắn dồn dập, thuật toán nhóm sự cố (Event Throttling) sẽ gom lại như thế nào để người lớn tuổi không bị hoảng loạn?
5. **Chính sách hỗ trợ khi người dùng vẫn bị lừa:** Khi người dùng đã bấm "Bỏ qua cảnh báo" và bị mất tiền, quy trình chăm sóc khách hàng và hỗ trợ tâm lý/pháp lý sau sự cố sẽ kết nối với các đối tác nào?

---

# 11. Core Product Principles Summary

Toàn bộ đội ngũ Thiết kế, Kỹ thuật, Trí tuệ nhân tạo và Vận hành cam kết tuân thủ 8 nguyên tắc phát triển sản phẩm bất di bất dịch:

1. **Backend complexity ≠ User-facing complexity:** Đưa sự phức tạp vào thuật toán máy học và chính sách rủi ro; mang đến trải nghiệm 3 mức đơn giản, dễ hành động cho người dùng.
2. **Unknown ≠ Safe:** Minh bạch về sự bất định; chưa thể kết luận không có nghĩa là an toàn.
3. **Warn based on actionability, not just score:** Mọi cảnh báo phải đi kèm chỉ dẫn hành động rõ ràng và khả thi.
4. **Pause before action:** Tạo khoảng dừng an toàn để người dùng bình tĩnh trước các thủ đoạn thao túng tâm lý.
5. **Explain, don't just alarm:** Không dán nhãn vô cảm; giải thích rõ nguyên nhân bằng ngôn ngữ đời thường, tôn trọng.
6. **Preserve user autonomy:** Bảo vệ nhưng không kiểm soát; luôn tôn trọng phẩm giá và quyền tự quyết của người cao tuổi.
7. **Escalate only when necessary and consented:** Chỉ kích hoạt cảnh báo người thân khi nguy cơ ở mức tối khẩn (`HIGH + Critical Internal`) và đã được người dùng ủy quyền.
8. **Design for recovery, not only prevention:** Thiết lập lá chắn thích ứng trước các kịch bản lừa đảo bồi hoàn (Recovery Scam) để ngăn chặn tổn thương tài chính tiếp diễn.
