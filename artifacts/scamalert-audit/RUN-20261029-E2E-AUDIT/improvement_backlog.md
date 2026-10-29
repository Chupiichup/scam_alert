# DANH MỤC ĐỀ XUẤT CẢI TIẾN HỆ THỐNG (IMPROVEMENT BACKLOG)
## Trạng thái: Chỉ đề xuất — Tuyệt đối KHÔNG tự ý sửa đổi hệ thống

> Toàn bộ các đề xuất dưới đây được rút ra trực tiếp từ bằng chứng thực nghiệm 6 ca False Negatives trên production trong đợt kiểm thử `RUN-20261029-E2E-AUDIT`.

---

### Bảng Đề Xuất Ưu Tiên (Priority Backlog)

| Proposal ID | Vấn đề phát hiện | Bằng chứng thực nghiệm | Kịch bản bị ảnh hưởng | Đề xuất kỹ thuật | Lợi ích dự kiến | Rủi ro False Positive | Mức ưu tiên | Cần duyệt |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **PROP-001** | Bỏ sót lừa đảo con cấp cứu Chợ Rẫy chuyển tiền mổ gấp | `S3-EXP-004` (Score 0) | `R-MED-001` | Kích hoạt rule AST `R-MED-001` từ `scam_scenario_expansion_dataset.json` lên production. | Bắt 100% chiêu trò tống tiền viện phí con trẻ nguy cấp. | Rất thấp (ràng buộc tên BV + cấp cứu + chuyển tiền STK). | **P0 (Khẩn cấp)** | CẦN DUYỆT |
| **PROP-002** | Bỏ sót tống tiền bằng hình ảnh cắt ghép Deepfake | `S3-EXP-008` (Score 0) | `R-EXT-001` | Kích hoạt rule AST `R-EXT-001` với regex `clip nong\|clip nhay cam\|tong tien`. | Chặn đứng thủ đoạn bôi nhọ tống tiền công nghệ cao. | Rất thấp (từ khóa đặc thù đe dọa nhạy cảm). | **P0 (Khẩn cấp)** | CẦN DUYỆT |
| **PROP-003** | Bỏ sót bẫy chuyển nhầm tiền ép vay nặng lãi | `S3-EXP-014` (Score 0) | `R-LOAN-TRAP-001` | Bổ sung rule nhận diện tín hiệu `lo tay chuyen nham ... vao STK khac`. | Bảo vệ nạn nhân khỏi bẫy tín dụng đen siết nợ. | Thấp (chỉ bắt khi có yêu cầu chuyển sang STK khác). | **P1 (Cao)** | CẦN DUYỆT |
| **PROP-004** | Bỏ sót giả mạo cứu trợ bão lũ UBMTTQ | `S3-EXP-009` (Score 0) | `R-CHARITY-001` | Kích hoạt rule `R-CHARITY-001` đối soát STK cá nhân xưng danh Ban cứu trợ bão lũ. | Chặn đứng hành vi trục lợi lòng hảo tâm nhân dân. | Rất thấp. | **P1 (Cao)** | CẦN DUYỆT |
| **PROP-005** | Bỏ sót domain Sacombank giả dạng `.com` | `S1-EMP-016` (Score 0) | `R-BNK-001` | Mở rộng danh sách Brand Mismatch cho Sacombank với domain dạng `vn-sacombank.com`. | Bắt trúng 100% các biến thể lừa đảo ngân hàng Sacombank. | Không có. | **P1 (Cao)** | CẦN DUYỆT |
| **PROP-006** | Mở rộng kiểm thử OCR ảnh mờ/lóa camera | 63 ảnh thực tế | Input Modality: IMAGE | Tích hợp bộ lọc làm nét ảnh (contrast/thresholding) trước khi đưa vào Tesseract WASM. | Tăng tỷ lệ bóc tách chữ từ ảnh chụp camera góc nghiêng. | Không có. | **P2 (Trung bình)**| CẦN DUYỆT |
