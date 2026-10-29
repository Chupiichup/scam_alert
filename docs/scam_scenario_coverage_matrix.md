# 🌐 MA TRẬN BAO PHỦ ĐA CHIỀU KỊCH BẢN LỪA ĐẢO (SCAM SCENARIO COVERAGE MATRIX)
> **Dự án:** Scam Message Detection Platform (ScamShield Vietnam)  
> **Phương pháp phân tích:** Ma trận bao phủ 8 chiều độc lập đánh giá sự chuyển biến về độ bao phủ từ hệ thống 36 kịch bản gốc sang hệ thống mở rộng toàn diện.

---

## 1. Ma Trận Đa Chiều: Trước vs Sau Mở Rộng

| Trục Phân Tích (Dimension) | Phân Khúc / Chiều Kích (Segments) | Trạng Thái Ban Đầu (36 Kịch Bản Hiện Có) | Trạng Thái Sau Mở Rộng (Bổ Sung 17 Kịch Bản Mới + 4 Biến Thể) | Mức Độ Gia Tăng Độ Bao Phủ (Coverage Delta) | Kịch Bản Tiêu Biểu Bổ Sung |
|---|---|---|---|:---:|---|
| **1. Danh tính bị mạo danh (Impersonated Entity)** | - Ngân hàng, Cổng thanh toán | `R-BNK-001`, `R-BNK-002`, `R-SUB-FEE` | Mở rộng biến thể nâng hạn mức thẻ tín dụng (`CAND-021`), nhận tiền kiều hối (`CAND-016`) | +25% | `R-REMIT-001`, `R-BNK-002` (Refined) |
| | - Cơ quan Công quyền (Công an, Tòa án, Thuế) | `R-POL-001`, `R-POL-002`, `R-POL-003`, `R-GOV-003`, `R-TAX-001` | Mở rộng Cục Đăng kiểm ô tô (`CAND-012`), Bảo hiểm Xã hội / Y tế (`CAND-003`, `CAND-017`) | +60% | `R-VR-001`, `R-BHXH-001`, `R-BHYT-001` |
| | - Tiện ích thiết yếu (Điện lực, Viễn thông) | `R-TEL-SPOOF-001` (chỉ khuyến mãi data) | Mạo danh Điện lực EVN dọa cắt điện (`CAND-001`), Cục Viễn thông khóa SIM theo NĐ 49 (`CAND-002`) | **+200% (Từ 1 lên 3)** | `R-EVN-001`, `R-SIM-001` |
| | - Y tế, Cấp cứu, Bệnh viện | **0% (Chưa bao phủ)** | Bác sĩ Bệnh viện Chợ Rẫy/Việt Đức báo cấp cứu nguy kịch chuyển viện phí mổ gấp (`CAND-004`) | **+100% (Mới hoàn toàn)** | `R-MED-001` |
| | - Tài chính, Tín dụng tiêu dùng | **0% (Chưa bao phủ)** | Bẫy cho vay tiền duyệt siêu tốc lãi rẻ bắt đóng phí bảo hiểm khoản vay (`CAND-005`), Chuyển nhầm tiền siết nợ (`CAND-014`) | **+100% (Mới hoàn toàn)** | `R-LOAN-001`, `R-SHARK-001` |
| | - Du lịch, Vận tải, Hàng không | **0% (Chưa bao phủ)** | Vé máy bay Tết giá rẻ, hủy chuyến bồi thường Vietnam Airlines (`CAND-006`) | **+100% (Mới hoàn toàn)** | `R-AIR-001` |
| | - Xã hội, Từ thiện, Giáo dục | `R-EDU-001` (Học phí đại học) | Quỹ từ thiện bão lũ UBMTTQ (`CAND-009`), Cuộc thi ảnh thiếu nhi (`CAND-007`), Cọc phòng trọ (`CAND-010`), Xuất khẩu lao động (`CAND-015`) | **+400% (Từ 1 lên 5)** | `R-CHARITY-001`, `R-VOTE-001`, `R-RENT-001`, `R-EXP-001` |
| | - Thương mại điện tử, Logistics | `R-SHIP-001`, `R-DELIV-001` | Giao hàng COD 0 đồng hàng rác (`CAND-011`), CSKH Shopee hoàn tiền đơn hàng bị hủy (`CAND-013`) | +100% | `R-COD-001`, `R-REF-001` |
| **2. Mục tiêu chiếm đoạt (Attacker Objective)** | - Đánh cắp mã OTP & Tài khoản ngân hàng | `R-BNK-001`, `R-BNK-002`, `R-SUB-FEE` | Hoàn tiền đơn hàng (`CAND-013`), Nhận tiền kiều hối (`CAND-016`) | +30% | `R-REF-001`, `R-REMIT-001` |
| | - Chiếm quyền điều khiển thiết bị (Malware APK) | `R-POL-002`, `R-TAX-001`, `R-GOV-003` | Cài app Đăng kiểm xe (`CAND-012`), Cài app cập nhật BHYT (`CAND-017`) | +66% | `R-VR-001`, `R-BHYT-001` |
| | - Chiếm đoạt tài khoản mạng xã hội / OTT | `R-COPILOT-2384/2389` | Bình chọn cuộc thi ảnh thiếu nhi qua OAuth Phishing (`CAND-007`) | +100% | `R-VOTE-001` |
| | - Chiếm quyền số điện thoại (SIM Swap) | **0% (Chưa bao phủ)** | Cập nhật thông tin thuê bao NĐ 49 đánh cắp mã OTP viễn thông (`CAND-002`) | **+100% (Mới hoàn toàn)** | `R-SIM-001` |
| | - Chiếm đoạt tiền mặt trực tiếp (Chuyển khoản) | `R-REL-001`, `R-RCV-001` | Cấp cứu bệnh viện (`CAND-004`), Phí bảo hiểm vay (`CAND-005`), Cọc vé máy bay (`CAND-006`), Cọc phòng trọ (`CAND-010`), Từ thiện (`CAND-009`) | **+250%** | `R-MED-001`, `R-LOAN-001`, `R-AIR-001`, `R-RENT-001`, `R-CHARITY-001` |
| | - Tống tiền, đe dọa danh dự đời tư | `R-EXTORT-001` (Xét nghiệm ADN) | Tống tiền bằng hình ảnh/clip nhạy cảm AI Deepfake cắt ghép (`CAND-008`), Ép vay siết nợ chuyển nhầm (`CAND-014`) | **+200%** | `R-DEEP-001`, `R-SHARK-001` |
| | - Chiếm đoạt tiền mặt cước COD vật lý | **0% (Chưa bao phủ)** | Bưu kiện COD 0 đồng hàng rác thu tiền ship tại nhà (`CAND-011`) | **+100% (Mới hoàn toàn)** | `R-COD-001` |
| **3. Cơ chế thao túng (Psychological Leverage)** | - Sợ hãi pháp lý / Hình phạt | `R-POL-001`, `R-POL-003` | Cắt điện sinh hoạt (`CAND-001`), Khóa SIM 2 chiều (`CAND-002`), Khóa thẻ BHYT (`CAND-017`), Phạt đăng kiểm (`CAND-012`) | +100% | `R-EVN-001`, `R-SIM-001`, `R-BHYT-001`, `R-VR-001` |
| | - Tình cảm ruột thịt & Đe dọa tính mạng con | `R-REL-001` (Hỏng mic, mượn tiền) | Con cấp cứu nguy kịch chấn thương sọ não trên bàn mổ (`CAND-004`) | **+100% (Cấp độ cực hạn)** | `R-MED-001` |
| | - Lòng trắc ẩn & Tương thân tương ái | **0% (Chưa bao phủ)** | Kêu gọi cứu trợ lũ lụt bão Yagi (`CAND-009`), Nhờ bình chọn cho cháu thi ảnh (`CAND-007`) | **+100% (Mới hoàn toàn)** | `R-CHARITY-001`, `R-VOTE-001` |
| | - Khó khăn tài chính / Cần vay tiền | **0% (Chưa bao phủ)** | Duyệt vay siêu tốc không thế chấp 50tr-200tr (`CAND-005`), Đi làm thời vụ nước ngoài lương 45tr (`CAND-015`) | **+100% (Mới hoàn toàn)** | `R-LOAN-001`, `R-EXP-001` |
| | - Lòng tham lợi ích / Tiền thưởng / Quà tặng | `R-PRIZE-001`, `R-GAMBLE-001`, `R-JOB-001` | Hoàn tiền điện (`CAND-001`), Hoàn tiền Shopee (`CAND-013`), Nhận tiền kiều hối ngoại tệ (`CAND-016`), Bot AI Trading (`CAND-019`) | +80% | `R-REF-001`, `R-REMIT-001` |
| **4. Bối cảnh & Sự kiện kích hoạt (Context & Trigger)** | - Thời điểm cận Tết Nguyên Đán | `SMS-CASE-008` (Bia Sài Gòn quà Tết) | Mua vé máy bay Tết giá rẻ (`CAND-006`), Nhận tiền kiều hối bà con gửi về (`CAND-016`), Tiền thưởng Tết | +200% | `R-AIR-001`, `R-REMIT-001` |
| | - Sau thiên tai, bão lũ | **0% (Chưa bao phủ)** | Lũ lụt, cứu trợ đồng bào vùng thiên tai (`CAND-009`) | **+100% (Mới hoàn toàn)** | `R-CHARITY-001` |
| | - Đầu năm học mới / Mùa nhập học | `R-EDU-001` (Học phí HUIT) | Tìm thuê phòng trọ sinh viên nhập học (`CAND-010`) | +100% | `R-RENT-001` |
| | - Sinh hoạt thường nhật tại gia đình | `R-SUB-FEE` (Quảng cáo TikTok) | Cắt điện sinh hoạt (`CAND-001`), Khóa liên lạc điện thoại di động (`CAND-002`), Nhận bưu kiện COD giao tận nhà (`CAND-011`) | +150% | `R-EVN-001`, `R-SIM-001`, `R-COD-001` |
| **5. Giai đoạn tấn công (Attack Stage)** | - Tiếp cận ban đầu & Tạo lòng tin | `R-SUSP-APPROACH`, `R-CONV-001` | Nhờ vả bình chọn cuộc thi ảnh (`CAND-007`), Chuyển nhầm tiền tạo cớ làm quen (`CAND-014`) | +100% | `R-VOTE-001`, `R-SHARK-001` |
| | - Thúc ép khẩn cấp & Hành động | `R-POL-001`, `R-REL-001` | Cấp cứu viện phí trong 15 phút (`CAND-004`), Cắt điện sau 17h (`CAND-001`), Khóa SIM sau 2h (`CAND-002`) | +75% | `R-MED-001`, `R-EVN-001`, `R-SIM-001` |
| | - Chiếm quyền tài nguyên | `R-POL-002`, `R-BNK-001` | Chiếm quyền SIM (`CAND-002`), Chiếm tài khoản MXH (`CAND-007`), Cài app Đăng kiểm (`CAND-012`) | +100% | `R-SIM-001`, `R-VOTE-001`, `R-VR-001` |
| | - Chiếm đoạt tài sản & Tống tiền | `R-EXTORT-001` | Tống tiền clip Deepfake (`CAND-008`), Siết nợ vay chuyển nhầm (`CAND-014`) | +200% | `R-DEEP-001`, `R-SHARK-001` |
| | - Tấn công thứ cấp (Secondary) | `R-RCV-001` (Thu hồi vốn treo) | Giữ nguyên và củng cố rule `R-RCV-001` | Ổn định | `R-RCV-001` |
| **6. Khả năng nhận diện qua SMS (SMS Detectability)** | - Tin nhắn có liên kết URL | Đa số các rule hiện tại | Bao phủ thêm URL mạo danh EVN, Cục Viễn thông, BHXH, Đăng kiểm, Vé máy bay, Bình chọn ảnh | +50% | 12 rules mới có URL |
| | - Tin nhắn KHÔNG CÓ URL (Text-only / Hotline / STK) | `R-REL-001`, `R-SUSP-ORDER`, `R-SUSP-APPROACH` | Cấp cứu con (`CAND-004`), Quyên góp từ thiện (`CAND-009`), Cọc phòng trọ (`CAND-010`), Chuyển nhầm tiền siết nợ (`CAND-014`), Bưu kiện COD (`CAND-011`) | **+166% (Từ 3 lên 8)** | 5 rules mới không cần URL |
| | - Tin nhắn có đầu số đặc biệt / Dẫn kênh thoại | `R-TOLL-001` (1900) | Dẫn số hotline bàn bệnh viện, số cá nhân shipper | +50% | `R-MED-001`, `R-COD-001` |

---

## 2. Thống Kê Phân Bổ Theo Bằng Chứng Nghiên Cứu

Sau khi mở rộng, toàn bộ thư viện kịch bản của hệ thống được phân bổ dựa trên bằng chứng minh bạch:

```text
┌─────────────────────────────────────────────────────────────────┐
│     PHÂN BỔ BẰNG CHỨNG HỆ THỐNG SAU MỞ RỘNG (53 KỊCH BẢN)      │
├─────────────────────────────────────────────────────────────────┤
│ 🏛️ OFFICIAL (Cơ quan Chức năng: BCA, NCSC, EVN, BHXH, SBV):  60.4%│
│ 📰 REPUTABLE_MEDIA (Báo chí: VnExpress, Tuổi Trẻ, CAND, Dân Trí): 24.5%│
│ 🔬 RESEARCH_REPORT (Chống Lừa Đảo, GASA):                       9.4%│
│ 💡 MODEL_INFERENCE / PUBLIC_REPORT (Biến thể suy luận chuẩn hóa): 5.7%│
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Các Khoảng Trống Còn Tồn Tại & Giới Hạn Công Nghệ (Residual Gaps)

1. **Khoảng trống Cuộc gọi thoại Deepfake (Voice Clone):** Khi kẻ lừa đảo sử dụng cuộc gọi thoại giả giọng người thân nói chuyện trực tiếp, ứng dụng SMS không thể can thiệp nếu người dùng không chụp màn hình tin nhắn tóm tắt sau đó.
2. **Khoảng trống Tên miền mới mua dưới 24h có đuôi `.vn` chính chủ:** Một số đối tượng sử dụng CCCD đánh cắp để đăng ký tên miền `.vn` thật, chưa kịp đưa vào danh sách đen Threat Intel. Hệ thống phải dựa vào AST Regex để phát hiện ngữ cảnh thay vì tra cứu blacklist.
3. **Khoảng trống Tin nhắn mã hóa E2EE trên ứng dụng mạng xã hội:** Tin nhắn trò chuyện riêng tư trên Telegram/Signal có mã hóa đầu cuối, app chỉ có thể quét khi người dùng chủ động tải ảnh chụp màn hình lên OCR.
