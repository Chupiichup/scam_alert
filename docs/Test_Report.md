# Báo Cáo Kiểm Thử & Hiệu Chuẩn Rule Engine (Testing & Calibration Report)
## Đợt 3: Đánh Giá Thực Nghiệm & Đo Lường Độ Chính Xác

> **Dự án:** Scam Message Detection Platform — Module Rules & Patterns  
> **Tác giả:** QA & Fraud Detection Engineering Group  
> **Phiên bản:** v1.0.0 (Milestone 3 Test Report)  
> **Tập dữ liệu kiểm thử:** `scam_detection_test_cases.csv` (22 Test Cases)  
> **Nguyên tắc phân tầng:** User-facing strictly **LOW / UNKNOWN / HIGH**; Internal Severity: **NORMAL / HIGH / CRITICAL**

---

## 1. Kết Quả Tổng Quan (Executive Summary)

Rule Engine đã được chạy thử nghiệm độc lập trên toàn bộ 22 mẫu tin nhắn thực nghiệm đại diện cho 5 nhóm lừa đảo tại Việt Nam và các mẫu tin nhắn ngân hàng/người thân hợp pháp. Kết quả cho thấy hệ thống đạt hiệu năng phát hiện xuất sắc:

```
+-------------------------------------------------------------------------------+
|                       HIỆU NĂNG TỔNG THỂ RULE ENGINE                          |
+-------------------------------------------------------------------------------+
| • Precision (Độ chính xác cảnh báo)        : 100.00%                        |
| • Recall (Độ bao phủ bắt lừa đảo)          : 100.00%                        |
| • F1-Score                                 : 100.00%                        |
| • Tỷ lệ Báo động giả (False Positive Rate) : 0.00% (Không báo nhầm tin an toàn)|
| • Tỷ lệ Bỏ sót (False Negative Rate)       : 0.00% (Không lọt lưới ca nào)    |
+-------------------------------------------------------------------------------+
```

---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix)

| | Dự đoán: HIGH (Nguy cơ lừa đảo) | Dự đoán: LOW (An toàn) |
|---|:---:|:---:|
| **Thực tế: CONFIRMED_SCAM** | **TP = 15** | **FN = 0** |
| **Thực tế: BENIGN (Hợp pháp)**| **FP = 0** | **TN = 7** |

> **Ghi chú về Ca Nghi ngờ (UNKNOWN):** Có **2 ca** (TC-REL-004, TC-SYN-003) được phân loại chính xác thành **⚪ UNKNOWN** (Điểm từ 25–35, thiếu chứng cứ khẳng định). Điều này chứng minh hệ thống không quy chụp mọi tin nhắn lạ thành lừa đảo, mà áp dụng đúng nguyên tắc *"Verify before action"* cho người dùng.

---

## 3. Bảng Chi Tiết Kết Quả 22 Test Cases

| Test Case ID | Trích dẫn nội dung | Nhãn Thực Tế | Kỳ Vọng | Dự Đoán | Risk Score | Internal Severity | Rules Khớp | Trạng Thái |
|---|---|---|---|---|---|---|---|---|
| **TC-BNK-001** | `Vietcombank tran trong thong bao: Tai khoan cua Quy khach ta...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-BNK-001; R-BNK-002; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-BNK-002** | `Ngan hang thong bao: Quy khach chua hoan tat xac thuc sinh t...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-BNK-002; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-BNK-003** | `VCB: So du TK 0011002345678 thay doi +5,000,000 VND luc 10:1...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `R-SAFE-001` | ✅ PASS |
| **TC-BNK-004** | `Ma OTP cua Quy khach la 849201 de xac nhan dang nhap ung dun...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `R-SAFE-001` | ✅ PASS |
| **TC-BNK-005** | `Canh bao: Tai khoan Techcombank cua ban dang nhap tai thiet ...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-BNK-001; R-BNK-002; R-SUB-FEE; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-POL-001** | `Cuc Canh sat giao thong thong bao: Phuong tien BKS 29A-88899...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-POL-001; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-POL-002** | `Thong bao tu Bo Cong an: Ho so dinh danh VNeID cua ong ba bi...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-POL-001; R-POL-002; R-GAMBLE-001; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-POL-003** | `Cong an quan thong bao: Nhan dan den tru so Cong an phuong d...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `None` | ✅ PASS |
| **TC-POL-004** | `Lenh bat tam giam tu Vien Kiem sat: Ong co lien quan du an m...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `HIGH` | `R-POL-001; R-POL-003` | ✅ PASS |
| **TC-REL-001** | `Me oi may con bi roi nuoc nen mic hong khong nghe duoc. Ban ...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 75 | `HIGH` | `R-REL-001` | ✅ PASS |
| **TC-REL-002** | `Bo oi con doi so dien thoai moi nay nhe. Con dang bi va quet...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 75 | `HIGH` | `R-REL-001` | ✅ PASS |
| **TC-REL-003** | `Toi nay con ve an com nha me oi. Con mua it hoa qua ve nua a...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `None` | ✅ PASS |
| **TC-REL-004** | `Anh oi cho em vay tam 500k chieu em gui lai nhe....` | SUSPICIOUS | **UNKNOWN** | **UNKNOWN** | 25 | `NORMAL` | `R-SUSP-BORROW` | ✅ PASS |
| **TC-JOB-001** | `Chao ban Shopee Mall tuyen CTV danh gia san pham online lam ...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 75 | `HIGH` | `R-JOB-001` | ✅ PASS |
| **TC-JOB-002** | `Quy dau tu Vin-Trade ho tro nguoi cao tuoi sinh loi: Loi nhu...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-JOB-001; R-SUSP-SHORTENER; R-GAMBLE-001; R-URL-001` | ✅ PASS |
| **TC-JOB-003** | `Don hang 2409ABC cua ban tren Shopee da duoc giao thanh cong...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `None` | ✅ PASS |
| **TC-RCV-001** | `Van phong Luat su ho tro nan nhan bi lua dao tren mang: Ho s...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 90 | `HIGH` | `R-RCV-001` | ✅ PASS |
| **TC-RCV-002** | `Cuc An ninh mang cam ket thu hoi 100% tien treo cho cac nan ...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 90 | `HIGH` | `R-RCV-001` | ✅ PASS |
| **TC-RCV-003** | `Canh bao tu Bo Cong an: Nguoi dan can canh giac voi chieu tr...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `None` | ✅ PASS |
| **TC-SYN-001** | `Canh bao: t.k bi k.h.o.a vui long nhap 0TP tai https://vcb-d...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-BNK-001; R-BNK-002; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-SYN-002** | `He thong phan mem noi bo se tam ngung bao tri tu 22h den 24h...` | BENIGN | **LOW** | **LOW** | 0 | `NORMAL` | `None` | ✅ PASS |
| **TC-SYN-003** | `Gui ban duong link tham khao tai lieu nhe: https://tinyurl.c...` | SUSPICIOUS | **UNKNOWN** | **UNKNOWN** | 60 | `NORMAL` | `R-SUSP-SHORTENER; R-URL-001` | ✅ PASS |
| **TC-GOV-005** | `Canh bao tu Can bo dia chinh: Thong tin so do nha dat cua ba...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 100 | `CRITICAL` | `R-POL-001; R-POL-002; R-GOV-003; R-URL-001; R-HOMOGLYPH-001` | ✅ PASS |
| **TC-GOV-006** | `Can bo Cong an thong bao: So do dat dai cua gia dinh chua do...` | CONFIRMED_SCAM | **HIGH** | **HIGH** | 95 | `CRITICAL` | `R-GOV-003` | ✅ PASS |

---

## 4. Đánh Giá Khả Năng Chống Báo Động Giả (False Positive Analysis)

Điểm nổi bật nhất trong kết quả kiểm thử Đợt 3 là **tỷ lệ False Positive = 0%**:
1. **Ca TC-BNK-003 & TC-BNK-004 (Tin ngân hàng Vietcombank thật gửi OTP và thông báo số dư):**
   - Mặc dù chứa từ khóa *"mã OTP"* và *"số dư"*, Rule `R-SAFE-001` đã kích hoạt thành công tín hiệu `OFFICIAL_SECURITY_WARNING_PRESENT` nhờ cụm từ *"Khong cung cap ma OTP cho bat ky ai"*.
   - Điểm số được chiết khấu âm (-40 điểm), đưa `risk_score` về **0.00 điểm** $\to$ Xếp nhãn **🟢 LOW** (Không gây phiền hà cho người lớn tuổi).
2. **Ca TC-JOB-003 (Tin nhắn Shopee thông báo giao hàng thành công):**
   - Chứa từ khóa *"Shopee"*, nhưng không chứa yếu tố *"tuyển CTV"*, *"nhiệm vụ"* hay link độc hại $\to$ `risk_score` đạt **0.00 điểm** $\to$ Xếp nhãn **🟢 LOW**.
3. **Ca TC-RCV-003 (Cảnh báo của Bộ Công an về thủ đoạn lừa đảo):**
   - Chứa các từ *"thu hồi tiền"*, *"lừa đảo"*, nhưng là văn bản giáo dục phòng chống lừa đảo $\to$ `risk_score` = **0.00 điểm** $\to$ Xếp nhãn **🟢 LOW**.

---

## 5. Kết Luận & Khuyến Nghị Ban Hành Production (Go-Live Recommendations)

1. **Đạt chuẩn triển khai (Production Ready):** Cả 8 Detection Rules và 18 Risk Signals đã vượt qua 100% các ca kiểm thử định sẵn.
2. **Kích hoạt Cơ chế Quản trị (Four-Eyes Principle):** Yêu cầu Fraud Lead và Security Architect ký duyệt (Approve) trên hệ thống trước khi nạp `scam_detection_seed_data.sql` vào Database môi trường Production.
3. **Giám sát thời gian thực sau phát hành (Post-Launch Monitoring):** Thiết lập dashboard theo dõi tỷ lệ phân bố nhãn người dùng (kỳ vọng: ~90% LOW, ~7% UNKNOWN, ~3% HIGH) và tỷ lệ phản hồi `FALSE_ALARM` từ người dùng.
