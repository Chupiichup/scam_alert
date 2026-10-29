# HƯỚNG DẪN TÁI LẬP KIỂM THỬ ĐỘC LẬP (REPRODUCTION GUIDE)
## Nền tảng: ScamAlert Vietnam | Audit Run: RUN-20261029-E2E-AUDIT

### 1. Yêu cầu Môi trường
- **Node.js:** Phiên bản 18.x trở lên.
- **Hệ điều hành:** Hỗ trợ Windows, macOS, Linux.
- **Kết nối mạng:** Kết nối Internet trực tiếp tới endpoint `https://scamalert-delta.vercel.app`.

---

### 2. Các Bước Thực Thi Tái Lập (Step-by-Step)

#### Bước 1: Mở Terminal tại thư mục gốc repository
```bash
cd "d:/Me mine/PM/UXCamp/Scam alert/scam_alert_check_link_4"
```

#### Bước 2: Chạy bộ kiểm thử E2E trực tiếp lên môi trường Vercel Live
```bash
node scripts/build_and_run_full_audit.js
```

#### Bước 3: Kiểm tra kết quả thực thi
Toàn bộ log chi tiết và bảng số liệu sẽ được tự động ghi lại tại:
`artifacts/scamalert-audit/RUN-20261029-E2E-AUDIT/`

---

### 3. Cách Đọc và Đối Chiếu Output
- **HTTP 200 & Score >= 75 (`HIGH`):** Hệ thống cảnh báo lừa đảo thành công.
- **HTTP 200 & Score < 25 (`LOW`):** Hệ thống đánh giá tin nhắn an toàn.
- **HTTP 200 & Score 25-74 (`UNKNOWN`):** Hệ thống nghi vấn, yêu cầu xác minh.
- **Đối chiếu Ground Truth:** Kiểm tra cột `eval_category` trong `execution_results.csv` (`TP`, `TN`, `FN`, `FP`).
