# Chiến Lược Kiểm Chuẩn & Đánh Giá Toàn Diện (Detection Test Strategy)
## Phương Pháp Luận Kiểm Thử Thực Chất & Bộ Ma Trận Kiểm Chuẩn Toàn Diện

> **Nguyên tắc cốt lõi:** "Kiểm tra tính đúng đắn của logic, không chỉ kiểm tra code có chạy được hay không". Một bộ test suite đạt 100% trên tập dữ liệu đóng không đồng nghĩa với việc sản phẩm an toàn ngoài thực tế nếu thiếu các ca kiểm thử biên (Edge Cases), đối kháng (Adversarial) và phân rã tín hiệu tương quan.

---

## 1. Ma Trận Tình Huống Kiểm Chuẩn Toàn Diện (Comprehensive Test Matrix)

| Nhóm Kiểm Chuẩn | Tình huống thử nghiệm cụ thể | Dữ liệu đầu vào mô phỏng (Input SMS/Context) | Ground Truth thực tế | Evidence mong đợi | Xếp loại kỳ vọng | Hành động người dùng mong muốn | Tiêu chí chấp nhận (Acceptance Criteria) |
| :--- | :--- | :--- | :---: | :--- | :---: | :--- | :--- |
| **1. True Positive (Điển hình)** | Giả mạo Vietcombank dọa khóa thẻ đòi OTP | `"Vietcombank: Tai khoan bi khoa. Nhap OTP tai http://vcb-verify.top truoc 24h"` | `CONFIRMED_SCAM` | `OTP_REQUEST`, `FAKE_BRAND_DOMAIN`, `ACCOUNT_SUSPENSION` | **🔴 HIGH (100đ, CRITICAL)** | Dừng lại, không bấm link, không nhập OTP | Bắt trúng rule `R-BNK-001`, kích hoạt Family Escalation. |
| **2. True Positive (Thủ đoạn mới)** | Giả danh Công an/Địa chính ép cập nhật Sổ đỏ VNeID | `"Can bo dia chinh thong bao: So do dat dai cua ban tren VNeID sai lech. Tai https://dichvucong-gov.top/vneid.apk de dong bo"` | `CONFIRMED_SCAM` | `VNEID_LAND_UPDATE_SCAM`, `APK_DOWNLOAD_LINK`, `GOV_IMPERSONATION` | **🔴 HIGH (100đ, CRITICAL)** | Xóa tin nhắn, gọi Công an xã hỏi trực tiếp | Bắt trúng rule `R-GOV-003`, cảnh báo tuyệt đối không cài APK. |
| **3. True Negative (Khẩn cấp thật)** | Ngân hàng thật gửi biến động số dư lớn lúc nửa đêm | `"VCB: TK 0011002345678 -20,000,000 VND luc 23:45. Neu khong thuc hien, goi 1900545413. Khong cung cap ma OTP cho bat ky ai."` | `BENIGN` | `OFFICIAL_SECURITY_WARNING_PRESENT` | **🟢 LOW (0đ, NORMAL)** | Người dùng đọc bình thường, không bị cản trở | Rule `R-SAFE-001` trừ 40đ, triệt tiêu 100% cảnh báo giả. |
| **4. True Negative (Cơ quan thật)** | Công an phường mời người dân làm định danh mức 2 | `"UBND Phuong moi ba con den tru so Cong an phuong mang theo CCCD de tich hop dinh danh VNeID muc 2 tu ngay 15-20/10."` | `BENIGN` | Không có URL, không có đòi tiền/OTP, địa chỉ trụ sở thật | **🟢 LOW (0đ, NORMAL)** | Đến trụ sở công an làm thủ tục | Điểm rủi ro = 0 điểm, không gây hoang mang cho người dân. |
| **5. False Positive Guard** | Tin tuyển dụng nhân viên bán hàng thật từ công ty | `"Sieu thi Co.opmart tuyen nhan vien thu ngan lam viec tai quan 1, luong 7-9 trieu/thang. Nop ho so tai phong nhan su."` | `BENIGN` | Có từ "tuyển", "lương" nhưng KHÔNG có "làm nhiệm vụ", "nạp tiền", "Telegram" | **🟢 LOW (0đ, NORMAL)** | Tiếp tục đọc | Điểm rủi ro < 20 điểm, không bị phạt oan vì từ khóa "tuyển dụng". |
| **6. Unknown / Insufficient Evidence** | Người lạ nhắn mượn tiền nhưng không kèm STK | `"Anh oi cho em vay tam 500k chieu em gui lai nhe."` | `SUSPICIOUS` | Có từ khóa vay mượn nhưng thiếu STK, không có link độc hại | **⚪ UNKNOWN (25đ, NORMAL)** | Gọi điện thoại hỏi kỹ trước khi trả lời | Không vội vã báo lừa đảo, khuyến cáo kiểm chứng danh tính. |
| **7. Unknown (Link rút gọn)** | Người quen gửi tài liệu qua link rút gọn | `"Minh gui ban file tong hop bao cao nhe: https://tinyurl.com/tai-lieu-2026"` | `SUSPICIOUS` | Tên miền rút gọn che giấu đích đến | **⚪ UNKNOWN (30đ, NORMAL)** | Hỏi lại người gửi link dẫn tới đâu | Cảnh báo link rút gọn có thể chứa mã độc. |
| **8. Adversarial: Homoglyph & Ký tự ngắt** | Kẻ gian viết teencode lách luật | `"Canh bao: t.k bi k.h.o.a vui long nhap 0TP tai https://vcb-verify.top"` | `CONFIRMED_SCAM` | Bóc tách được `t.k`, `k.h.o.a`, `0tp` sau khi chuẩn hóa | **🔴 HIGH (100đ, CRITICAL)** | Chặn người gửi ngay lập tức | Hàm `removeVietnameseTones()` bóc tách thành công. |
| **9. Adversarial: Ký tự Cyrillic** | Dùng chữ 'а' tiếng Nga thay chữ 'a' tiếng Việt | `"Vietcombаnk thong bаo tаi khoаn bi khoа: nhap OTP tai http://vcb.top"` | `CONFIRMED_SCAM` | Unicode NFKD Normalization chuẩn hóa về Latin | **🔴 HIGH (100đ, CRITICAL)** | Cảnh báo giả mạo thương hiệu | Bắt trúng Regex sau khi giải mã Unicode tương đồng. |
| **10. Correlated Signals (Triệt tiêu điểm)** | Tin nhắn vừa đòi OTP (+40) vừa đòi mật khẩu (+35) | `"Yeu cau dang nhap mat khau va cung cap ma OTP tai http://link.top"` | `CONFIRMED_SCAM` | Hai tín hiệu cùng nhóm `GRP_CREDENTIAL_THEFT` | **Điểm nhóm: 57.5đ (Không bị cộng dồn thành 75đ)** | Không cung cấp thông tin | Thuật toán Decay 50% hoạt động chuẩn xác. |
| **11. Stateful: Chuỗi nuôi bẫy 3 ngày** | Day 1 mạo danh con $\to$ Day 2 hỏi thăm $\to$ Day 3 mượn tiền | D1: *"Mẹ ơi con đổi số này nhé"* $\to$ D2: *"Mẹ ăn cơm chưa"* $\to$ D3: *"Mẹ chuyển gấp 5tr vào STK lạ..."* | `CONFIRMED_SCAM` | Tích lũy chuỗi: `RELATIVE_EMERGENCY` + `MULTI_DAY_CONVERSATION_TRAP` | **Day 1: LOW $\to$ Day 2: LOW $\to$ Day 3: 🔴 HIGH (100đ)** | Gọi điện thoại thường cho con trai | Bắt trúng rule `R-CONV-001`, chặn đứng bẫy lừa dài ngày. |
| **12. Multi-channel Evasion** | Kẻ gian nhắn SMS: "Bác mở Zalo xem tin nhắn con gửi" | `"Bac oi mo Zalo xem tin nhan con gui ngay nhe, co viec gap lam"` | `SUSPICIOUS` | Dẫn kênh chuyển tiếp sang ứng dụng OTT | **⚪ UNKNOWN (30đ, NORMAL)** | Gọi điện xác nhận lại với người gửi | Khuyến cáo người già cẩn trọng với các tin nhắn giục mở Zalo. |
| **13. Offline / Mất mạng** | Điện thoại người già đang ở chế độ máy bay hoặc mất mạng | SMS Vietcombank lừa đảo đến khi không có Wi-Fi/4G | `CONFIRMED_SCAM` | Toàn bộ Regex, AST và Blacklist CSV chạy 100% trong RAM | **🔴 HIGH (100đ, HIGH)** | Vẫn hiển thị cảnh báo đỏ đầy đủ trên màn hình | Hoạt động bình thường mà không cần kết nối server. |
| **14. Parsing Error Resilience** | Tin nhắn chứa ký tự rác, emoji đặc biệt hoặc độ dài 2000 ký tự | `"[Emoji][Emoji]...!!!??? ### @@@ https://link.top ... (2000 chars)"` | `SUSPICIOUS` | Bộ parser Regex không bị crash hoặc timeout (> 50ms) | Phân tích thành công < 5ms | Không bị văng ứng dụng | Đảm bảo tính sẵn sàng cao (High Availability). |

---

## 2. Phương Pháp Luận Về Chỉ Số & Khử Nhiễu Dữ Liệu (Metrics & Validation Methodology)

### 2.1. Tại sao chỉ số "Accuracy tổng thể" là nguy hiểm và gây hiểu nhầm?
* Trong thực tế thế giới thực, tỷ lệ tin nhắn lừa đảo chỉ chiếm **khoảng 1% – 3%** tổng số tin nhắn người dùng nhận được (Class Imbalance nghiêm trọng: 98% tin nhắn là hợp pháp, quảng cáo hoặc người thân).
* Nếu một thuật toán "ngây thơ" luôn đoán mọi tin nhắn là **AN TOÀN (`LOW`)**, độ chính xác tổng thể (Accuracy) vẫn đạt tới **$98.0\%$**! Nhưng trên thực tế, hệ thống đó đã **thất bại hoàn toàn ($Recall = 0\%$)** vì để lọt 100% các vụ lừa đảo khiến người già mất tiền.
* **Quy chuẩn đo lường chuẩn:**
  1. **Precision (Độ tin cậy của cảnh báo đỏ):** $\frac{TP}{TP + FP} \ge 95\%$. Không được phép báo động giả làm người già hoang mang.
  2. **Recall (Độ bao phủ, chống bỏ sót):** $\frac{TP}{TP + FN} \ge 98\%$. Tuyệt đối không để lọt các vụ án lừa đảo mạo danh ngân hàng/công an.
  3. **Safe Decision Rate (SDR - Chỉ số North Star):** Đo lường tỷ lệ người dùng **thực sự dừng lại không chuyển tiền** sau khi nhìn thấy cảnh báo. Đây là thước đo giá trị đời thực cao nhất, vượt lên trên các chỉ số kỹ thuật thuần túy.

### 2.2. Chiến lược ngăn chặn rò rỉ dữ liệu (Leakage Prevention)
* **Nguyên tắc "Tách biệt Tuyệt đối giữa Xây dựng và Kiểm chuẩn":** 24 test cases dùng để kiểm thử độc lập **không bao giờ được dùng để hardcode tạo rule**.
* **Định kỳ bổ sung mẫu lừa đảo mới (Out-of-Distribution Data):** Mỗi tuần nạp tối thiểu 10 mẫu tin nhắn mới được ghi nhận từ cổng cảnh báo của Cục An toàn thông tin (`canhbao.khonggianmang.vn`) để thử thách khả năng thích ứng của hệ thống.
