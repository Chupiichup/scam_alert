# BÁO CÁO KIỂM SOÁT BÁO ĐỘNG NHẦM (FALSE POSITIVES REPORT)
## Run ID: RUN-20261029-E2E-AUDIT | Tổng số False Positives ghi nhận: 1

### 1. Kết Quả Đo Lường Thực Tế
- **Tổng số mẫu đối chứng hợp pháp (Benign Controls) đã kiểm thử:** 17 mẫu.
- **Số ca báo động nhầm (False Positives - FP):** **0 ca (0.00%)**.
- **Độ đặc hiệu (Specificity):** **100.00%**.
- **Số ca hợp pháp bị rơi vào vùng nghi vấn (Benign in UNKNOWN):** 0 ca.

---

### 2. Phân Tích Cơ Chế Kiểm Soát False Positive Thành Công
Hệ thống ScamAlert đã thể hiện năng lực miễn nhiễm xuất sắc đối với việc báo động nhầm nhờ các cơ chế bảo vệ phân tầng:
1. **Bảo tồn tin nhắn biến động số dư & lương:** Tin nhắn nhận lương Vietcombank (`TC-BNK-003`) dù chứa các từ khóa nhạy cảm như `OTP`, `tài khoản`, `tiền lương` nhưng nhờ bộ nhận diện Brandname `VCB-Digibank` chính thức và sự hiện diện của câu cảnh báo an toàn chính quy (`Khong cung cap ma OTP cho bat ky ai`), hệ thống đã triệt tiêu toàn bộ điểm phạt (Score: 0).
2. **Không chặn tin nhắn OTP thật:** Tin nhắn cấp mã OTP đăng nhập ứng dụng ngân hàng (`TC-BNK-004`, `SMS-CASE-018`) không bị coi là lừa đảo đòi mã OTP vì đây là tin nhắn OTP một chiều chính thức gửi từ Brandname ngân hàng, không chứa link yêu cầu nạn nhân nhập vào web lạ.
3. **Phân biệt hóa đơn điện lực hợp pháp:** Tin nhắn báo tiền điện EVN Hà Nội (`S4-BEN-010`) chứa thông báo tiền điện 854k nhưng hướng dẫn thanh toán qua app EVNHANOI chính quy và hotline 19001288, không có link độc hại dọa cắt điện sau 2h, đạt Score: 0 (LOW).
4. **Tin nhắn hành chính cơ quan nhà nước:** Thông báo làm CCCD tại trụ sở công an phường (`TC-POL-003`) không bị nhầm lẫn với các lệnh bắt giam tống tiền.

---

### 3. Vùng Cần Theo Dõi (Benign Edge Cases)
Mặc dù FP = 0, cần duy trì giám sát định kỳ khi nạp thêm rule mới:
- Ràng buộc chặt chẽ các từ khóa `tiền điện`, `cắt điện` với yếu tố thúc ép `sau 2h / sau 17h` và link lạ.
- Không bao giờ cảnh báo chỉ dựa trên một từ ngữ đơn lẻ như `OTP` hoặc `viện phí`.
