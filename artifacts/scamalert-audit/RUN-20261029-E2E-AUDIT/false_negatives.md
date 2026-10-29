# BÁO CÁO ĐIỀU TRA NGUYÊN NHÂN BỎ SÓT LỪA ĐẢO (FALSE NEGATIVES REPORT)
## Run ID: RUN-20261029-E2E-AUDIT | Tổng số False Negatives: 6

> **Nguyên tắc phân tích:** Mỗi ca bỏ sót (False Negative) đều được mổ xẻ tận gốc rễ kỹ thuật từ mã nguồn AST Rule Engine, từ điển từ khóa, biểu thức quy chuẩn và luồng trích xuất tên miền, không suy diễn cảm tính.

---

### Bảng Tổng Hợp Các Ca False Negatives Trên Production

| Test ID | Kịch Bản (Scenario) | Điểm App (Score) | Output Thực Tế | Ground Truth | Phân Loại Nguyên Nhân Cốt Lõi | Mức Độ Rủi Ro Nạn Nhân |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: |
| **TC-SMS-CASE-016** | BANK_ANOMALOUS_LOGIN | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |
| **TC-SMS-CASE-038** | BANK_ANOMALOUS_LOGIN | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |
| **TC-SMS-EXP-004** | HOSPITAL_EMERGENCY_EXTORTION | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |
| **TC-SMS-EXP-008** | AI_DEEPFAKE_EXTORTION | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |
| **TC-SMS-EXP-009** | CHARITY_DISASTER_IMPERSONATION | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |
| **TC-SMS-EXP-014** | LOAN_SHARK_ACCIDENTAL_TRANSFER | 0 | LOW | VERIFIED_SCAM | `MISSING_SCENARIO` | **RỦI RO MẤT TIỀN TRỰC TIẾP (CRITICAL)** |

---

### Chi Tiết Từng Ca Thất Bại & Bằng Chứng Kỹ Thuật

#### 1. Ca kiểm thử: TC-SMS-CASE-016 (SMS-CASE-016)
- **Kịch bản:** `BANK_ANOMALOUS_LOGIN`
- **Nội dung tin nhắn:**  
  > "Phat hien tai khoan cua ban dang nhap khac vung bat thuong ,vui long dang nhap https://vn-sacombank.com de xac nhan thong tin va thay doi mat khau"
- **Người gửi:** `Sacombank` (BRANDNAME)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

#### 2. Ca kiểm thử: TC-SMS-CASE-038 (SMS-CASE-038)
- **Kịch bản:** `BANK_ANOMALOUS_LOGIN`
- **Nội dung tin nhắn:**  
  > "(Vietcombank)Chung toi phat hien tai khoan cua ban dang tieu dung o nuoc ngoai .Neu khong phai ban dang tieu dung vui long nhap vao https://i-vietcombank.com"
- **Người gửi:** `Vietcombank` (BRANDNAME)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

#### 3. Ca kiểm thử: TC-SMS-EXP-004 (SMS-EXP-004)
- **Kịch bản:** `HOSPITAL_EMERGENCY_EXTORTION`
- **Nội dung tin nhắn:**  
  > "Toi la Bac si Nguyen Van Hung, Truong khoa Cap cuu Benh vien Cho Ray. Con anh/chi la chau Nguyen Minh Tri bi nga cau thang truong hoc chan thuong so nao rat nang, hien dang hon me tren ban mo can mo gap. Gia dinh chuyen ngay 50 trieu tam ung vien phi vao STK 1903889922 Techcombank Nguyen Van Hung de tien hanh phau thuat cuu chau!"
- **Người gửi:** `+84908123888` (PHONE_DOMESTIC)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

#### 4. Ca kiểm thử: TC-SMS-EXP-008 (SMS-EXP-008)
- **Kịch bản:** `AI_DEEPFAKE_EXTORTION`
- **Nội dung tin nhắn:**  
  > "Toi dang giu clip nong nhay cam giuong chieu cua anh. Khuon mat trong clip rat ro rang. Neu trong 24h toi khong chuyen 30 trieu vao STK 0918273645 MBBank Nguyen Van Nam thi toan bo clip nay se duoc gui cho co quan, dong nghiep va vo anh xem!"
- **Người gửi:** `+84903998877` (PHONE_DOMESTIC)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

#### 5. Ca kiểm thử: TC-SMS-EXP-009 (SMS-EXP-009)
- **Kịch bản:** `CHARITY_DISASTER_IMPERSONATION`
- **Nội dung tin nhắn:**  
  > "[MAT TRAN TO QUOC VN] Kieu goi toan the dong bao chung tay ung ho cuu tro dong bao mien Bac chiu thiet hai do sieu bao Yagi lu lut. Moi dong gop xin chuyen ve STK Ban cuu tro: 1902837465 Techcombank - Chu TK: Nguyen Van Tu (Thu quy Ban cuu tro). Noi dung: UNG HO BAO YAGI."
- **Người gửi:** `+84912883344` (PHONE_DOMESTIC)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

#### 6. Ca kiểm thử: TC-SMS-EXP-014 (SMS-EXP-014)
- **Kịch bản:** `LOAN_SHARK_ACCIDENTAL_TRANSFER`
- **Nội dung tin nhắn:**  
  > "Em chao chi, em la sinh vien di lam them lo tay chuyen nham 5.000.000d vao STK cua chi luc nay. Chi lam phuoc chuyen tra lai vao STK khac nay cua em voi a: 1903847261 MBBank Chu TK Tran Van Tuan. Em xin cam on chi!"
- **Người gửi:** `+84918334455` (PHONE_DOMESTIC)
- **Điểm rủi ro ghi nhận:** `0/100` -> Nhãn trả về: `LOW`
- **Rule được kích hoạt:** `KHÔNG CÓ RULE NÀO KHỚP (None)`
- **Tín hiệu phát hiện:** `Không có tín hiệu rủi ro`
- **Phân tích nguyên nhân gốc rễ (Root Cause Analysis):**

