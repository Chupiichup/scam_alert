# 🔍 BÁO CÁO ĐỐI SOÁT & KHỬ TRÙNG LẶP KỊCH BẢN (SCAM SCENARIO DEDUPLICATION REPORT)
> **Dự án:** Scam Message Detection Platform (ScamShield Vietnam)  
> **Nguyên tắc phân định:** Không gộp các kịch bản khác nhau chỉ vì cùng dùng chung một từ khóa; không tách các kịch bản chỉ vì thay tên tổ chức hoặc vài từ ngữ. Đánh giá dựa trên **7 tiêu chí cốt lõi** để đảm bảo tính độc lập và giá trị gia tăng thực tế.

---

## 1. Phương Pháp Luận & 7 Tiêu Chí Phân Định

Mỗi ứng viên trong danh sách 24 ứng viên được đối chiếu với toàn bộ 36 quy tắc hiện có qua 7 chiều:
1. **Bản chất hành vi lừa đảo (Core Fraud Mechanism):** Thủ đoạn phạm tội cốt lõi là gì?
2. **Mục tiêu cuối cùng (Ultimate Objective):** Tiền mặt, chiếm tài khoản ngân hàng, chiếm đoạt SIM hay chiếm quyền thiết bị?
3. **Chuỗi hành động (Attack Flow):** Các bước kẻ xấu thực hiện có tạo thành chuỗi mắt xích riêng biệt không?
4. **Cơ chế thao túng tâm lý (Psychological Leverage):** Đe dọa pháp lý, tình cảm ruột thịt, lòng trắc ẩn, lòng tham hay sự gián đoạn tiện ích?
5. **Hành động nạn nhân bị ép buộc (Victim Action):** Chuyển khoản, nhập OTP, tải APK, quét QR hay gọi tổng đài?
6. **Tín hiệu quan sát được trong SMS (Observable Indicators):** Từ khóa, cấu trúc câu, loại liên kết, đầu số gửi có đặc thù không?
7. **Khác biệt có ý nghĩa với độ bao phủ (Detection Impact):** Nếu không thêm quy tắc/biến thể này, hệ thống hiện tại có bỏ sót (`False Negative`) hoặc gán nhãn sai (`UNKNOWN` thay vì `HIGH`) không?

---

## 2. Bảng Tổng Hợp Phân Loại 24 Ứng Viên

| Nhóm Phân Loại | Số Lượng | Danh Sách Ứng Viên | Ý Nghĩa Nghiệp Vụ Đối Với Hệ Thống |
|---|:---:|---|---|
| **`ADD` (Kịch bản Mới Độc Lập)** | **17** | `CAND-001`, `CAND-002`, `CAND-003`, `CAND-004`, `CAND-005`, `CAND-006`, `CAND-007`, `CAND-008`, `CAND-009`, `CAND-010`, `CAND-011`, `CAND-012`, `CAND-013`, `CAND-014`, `CAND-015`, `CAND-016`, `CAND-017` | Bổ sung các cơ chế lừa đảo và đối tượng hoàn toàn mới mà 36 kịch bản hiện tại chưa có quy tắc chuyên biệt. |
| **`REFINE` (Tinh Chỉnh Quy Tắc Hiện Có)** | **1** | `CAND-021` | Mở rộng phạm vi bao phủ của `R-BNK-002` từ chỉ "dọa khóa thẻ" sang cả "hứa hẹn nâng hạn mức thẻ tín dụng". |
| **`VARIANT` (Biến Thể Có Giá Trị Gia Tăng)** | **3** | `CAND-018`, `CAND-019`, `CAND-022` | Bổ sung cách biểu đạt và phương thức dẫn kênh mới (Quét QR cào trúng thưởng, Bot AI trading, Dịch video AI) cho các quy tắc `R-PRIZE-001`, `R-JOB-001`. |
| **`MERGE` (Hợp Nhất Tránh Trùng Lặp)** | **1** | `CAND-023` | Hợp nhất 6 quy tắc Copilot thô (`R-COPILOT-1222/2389/2384/2375/2369/2212`) để tránh cộng dồn điểm ảo vô căn cứ. |
| **`RESEARCH_MORE` (Cần Nghiên Cứu Thêm)** | **2** | `CAND-020`, `CAND-024` | `CAND-020` (Thuốc đông y giả) thuộc vi phạm thương mại lừa dối tiêu dùng cần bộ từ điển riêng; `CAND-024` (Trạm BTS 5G) cần telemetry tầng sóng vô tuyến từ HĐH. |

---

## 3. Phân Tích Chi Tiết Từng Ứng Viên & Lý Do Phân Loại

### 3.1 Nhóm `ADD` — Kịch Bản Mới Độc Lập (17 Ứng viên)

#### 1. `CAND-001`: Mạo danh Điện lực (EVN) dọa cắt điện hoặc bẫy hoàn tiền điện
* **So sánh với hiện tại:** Hiện tại hệ thống chỉ có `R-SUB-FEE` (trừ phí dịch vụ TikTok) và `R-BNK-002` (khóa tài khoản). Không có quy tắc nào cho ngành Điện lực.
* **Khác biệt cốt lõi:** Lợi dụng **nhu cầu sinh hoạt thiết yếu (Điện)**. Nạn nhân sợ bị cắt điện sinh hoạt trong ngày nên rất dễ làm theo hướng dẫn.
* **Tín hiệu SMS:** Các cụm từ đặc trưng: `dien luc`, `cat dien`, `ngat dien sinh hoat`, `hoan tien dien tinh nham cong to`, `evn-cskh`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-EVN-001`).

#### 2. `CAND-002`: Mạo danh Cục Viễn thông khóa SIM sau 2h do chưa chuẩn hóa CCCD
* **So sánh với hiện tại:** Hiện tại chỉ có `R-TEL-SPOOF-001` (số cá nhân mạo danh nhà mạng tặng data 4G).
* **Khác biệt cốt lõi:** `R-TEL-SPOOF-001` đánh vào lòng tham khuyến mãi data; còn `CAND-002` đánh vào **nỗi sợ bị mất số liên lạc chính chủ theo quy định pháp luật (Nghị định 49)**. Mục tiêu của kẻ gian là chiếm quyền SIM (SIM Swap) để nhận mã OTP ngân hàng.
* **Tín hiệu SMS:** `chuan hoa thue bao`, `nghi dinh 49`, `khoa sim 2 chieu sau 2 gio`, `cuc vien thong`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-SIM-001`).

#### 3. `CAND-003`: Mạo danh BHXH nhận trợ cấp thai sản / ốm đau / thất nghiệp
* **So sánh với hiện tại:** `R-POL-001` có chứa từ khóa cũ "tro cap covid-19", nhưng đại dịch đã kết thúc từ lâu. Hiện nay thủ đoạn chuyển dịch sang trợ cấp thai sản, ốm đau, dưỡng sức sau sinh.
* **Khác biệt cốt lõi:** Bẫy chế độ chính sách an sinh xã hội hợp pháp thường xuyên của người lao động.
* **Tín hiệu SMS:** `tro cap thai san`, `tro cap om dau`, `che do duong suc`, `quy bhtn`, `m-bhxh`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-BHXH-001`).

#### 4. `CAND-004`: Mạo danh Bệnh viện / Bác sĩ báo con cấp cứu nguy kịch chuyển tiền gấp
* **So sánh với hiện tại:** `R-REL-001` bắt tin mạo danh con cháu nhờ mượn tiền (hỏng mic, va quẹt nhẹ).
* **Khác biệt cốt lõi:** Kẻ xấu không xưng là con cháu mà **mạo danh Bác sĩ bệnh viện lớn hoặc Giáo viên**, thông báo tình trạng **đe dọa tính mạng (chấn thương sọ não, đang trên bàn mổ)** ép chuyển 50-100 triệu trong 15 phút. Đây là kịch bản khủng bố tinh thần tàn nhẫn và gây thiệt hại tài sản cực lớn.
* **Tín hiệu SMS:** `con dang cap cuu`, `benh vien cho ray`, `chan thuong so nao`, `chuyen vien phi mo gap`, `bac si truc`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-MED-001`).

#### 5. `CAND-005`: Bẫy tín dụng đen duyệt vay siêu tốc không thế chấp đòi nộp phí bảo hiểm
* **So sánh với hiện tại:** Hiện tại chỉ có `R-JOB-001` (tuyển CTV làm nhiệm vụ) và `R-SUSP-BORROW` (hỏi vay mượn cá nhân). Hoàn toàn chưa có quy tắc nào bắt bẫy lừa cho vay tiền giải ngân online.
* **Khác biệt cốt lõi:** Nạn nhân là người đang gặp khó khăn tài chính cần vay tiền, bị lừa nộp trước 10-20% tiền "phí bảo hiểm khoản vay" hoặc "phí sửa sai số tài khoản ngân hàng".
* **Tín hiệu SMS:** `duyet vay 50tr - 200tr`, `giai ngan trong 15 phut`, `khong can the chap`, `phi bao hiem khoan vay`, `phi sua so tai khoan`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-LOAN-001`).

#### 6. `CAND-006`: Lừa đảo bán vé máy bay Tết giá rẻ / Bồi thường hoãn chuyến bay
* **So sánh với hiện tại:** Hệ thống chưa có kịch bản liên quan đến ngành hàng không và dịch vụ du lịch mùa cao điểm.
* **Khác biệt cốt lõi:** Lợi dụng bối cảnh khan hiếm vé máy bay dịp Tết hoặc sự cố trễ/hủy chuyến bay để lừa đặt cọc hoặc chiếm đoạt thông tin thẻ ngân hàng qua web bồi thường giả mạo.
* **Tín hiệu SMS:** `ve may bay tet`, `hoan ve may bay`, `chuyen bay bi huy`, `boi thuong chuyen bay`, `vietnamairlines-ticket`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-AIR-001`).

#### 7. `CAND-007`: Bẫy bình chọn cuộc thi ảnh thiếu nhi / tài năng nhí chiếm tài khoản
* **So sánh với hiện tại:** `R-SUSP-APPROACH` bắt tin làm quen; `R-JOB-001` bắt làm nhiệm vụ. Không có quy tắc nào nhận diện hành vi gửi link nhờ bình chọn thi ảnh.
* **Khác biệt cốt lõi:** Khai thác sự cả nể đối với trẻ em và người quen, dẫn dụ nạn nhân vào trang web bình chọn giả để chiếm đoạt tài khoản Facebook/Zalo thông qua OAuth Phishing.
* **Tín hiệu SMS:** `binh chon anh`, `thi sinh nhi`, `nu cuoi thien than`, `vote giup be`, `binhchon-nhi`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-VOTE-001`).

#### 8. `CAND-008`: Tống tiền bằng hình ảnh / video nhạy cảm Deepfake cắt ghép AI
* **So sánh với hiện tại:** `R-EXTORT-001` chỉ mới nhận diện đe dọa nặc danh xét nghiệm ADN.
* **Khác biệt cốt lõi:** Sử dụng công nghệ AI Deepfake cắt ghép khuôn mặt nạn nhân vào clip khiêu dâm rồi đe dọa phát tán cho gia đình, cơ quan nếu không nộp tiền chuộc.
* **Tín hiệu SMS:** `clip nhay cam`, `anh cat ghep`, `phat tan cho co quan va ban be`, `chuyen 30 trieu xoa clip`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-DEEP-001`).

#### 9. `CAND-009`: Mạo danh Quỹ từ thiện / Hội Chữ thập đỏ lừa đảo cứu trợ bão lũ
* **So sánh với hiện tại:** Hoàn toàn chưa có quy tắc nào bao phủ mảng từ thiện và cứu trợ xã hội.
* **Khác biệt cốt lõi:** Khai thác lòng trắc ẩn của người dân sau các đợt thiên tai, bão lũ lớn để kêu gọi quyên góp vào số tài khoản cá nhân lừa đảo.
* **Tín hiệu SMS:** `ung ho bao lu`, `cuu tro dong bao`, `mat tran to quoc`, `chu thap do`, `dong gop quy cuu tro`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-CHARITY-001`).

#### 10. `CAND-010`: Lừa đảo đặt cọc giữ phòng trọ sinh viên giá rẻ
* **So sánh với hiện tại:** `R-SUSP-ORDER` chỉ nhận diện đơn hàng mua sắm online.
* **Khác biệt cốt lõi:** Nhắm vào đối tượng sinh viên và người lao động ngoại tỉnh tìm thuê nhà trọ, sử dụng áp lực "nhiều người đang hỏi thuê" để giục chuyển cọc 1-2 triệu rồi chiếm đoạt.
* **Tín hiệu SMS:** `coc phong tro`, `giu phong tro`, `chuyen phong tro`, `hoan coc neu khong ung phong`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-RENT-001`).

#### 11. `CAND-011`: Bưu kiện COD 0 đồng lừa đảo (Brush scam / Giao hàng rác thu tiền ship)
* **So sánh với hiện tại:** `R-DELIV-001` bắt link cập nhật địa chỉ bưu điện; `R-SHIP-001` bắt shipper dọa giữ hàng đòi chuyển khoản.
* **Khác biệt cốt lõi:** Kẻ gian gửi **bưu phẩm vật lý rác** (hàng không đặt) đến nhà nạn nhân khi vắng nhà để lừa người thân nhận hộ trả tiền cước COD 80k-150k.
* **Tín hiệu SMS:** `don hang cod 0 dong`, `nhan ho don hang`, `thu phi cod`, `don hang khong dat`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-COD-001`).

#### 12. `CAND-012`: Mạo danh Cục Đăng kiểm gia hạn kiểm định trực tuyến
* **So sánh với hiện tại:** `R-POL-001` chỉ bắt phạt nguội giao thông của CSGT.
* **Khác biệt cốt lõi:** Mạo danh Cục Đăng kiểm Việt Nam thông báo hết hạn kiểm định an toàn kỹ thuật phương tiện cơ giới, dụ tải app giả để nộp phí gia hạn tem kiểm định.
* **Tín hiệu SMS:** `cuc dang kiem`, `kiem dinh xe co gioi`, `gia han dang kiem`, `app-dangkiem`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-VR-001`).

#### 13. `CAND-013`: Mạo danh CSKH Shopee/TikTok Shop hoàn tiền đơn hàng bị lỗi
* **So sánh với hiện tại:** `R-JOB-001` tuyển CTV giật đơn; `R-BNK-001` đòi OTP ngân hàng.
* **Khác biệt cốt lõi:** Mạo danh bộ phận chăm sóc khách hàng của sàn TMĐT thông báo hoàn lại tiền hàng bị hủy nhằm dụ nạn nhân bấm link nhập thông tin thẻ và OTP.
* **Tín hiệu SMS:** `hoan tien don hang`, `don hang bi huy`, `cskh shopee hoan tien`, `link nhan tien hoan`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-REF-001`).

#### 14. `CAND-014`: Cố tình chuyển nhầm tiền vào tài khoản rồi ép vay nặng lãi (Loan Shark Bait)
* **So sánh với hiện tại:** Hệ thống hiện chỉ xử lý tình huống nạn nhân chuyển tiền đi, chưa bao phủ trường hợp nạn nhân nhận được tiền trước.
* **Khác biệt cốt lõi:** Kẻ gian cố tình chuyển tiền vào tài khoản nạn nhân để gài bẫy, sau đó đe dọa đòi nợ với lãi suất cắt cổ kiểu tín dụng đen.
* **Tín hiệu SMS:** `chuyen nham tien`, `gui lai vao stk khac`, `tien vay tin dung den`, `doi no cat co`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-SHARK-001`).

#### 15. `CAND-015`: Bẫy xuất khẩu lao động thời vụ Hàn Quốc/Nhật Bản cam kết bao đậu
* **So sánh với hiện tại:** `R-JOB-001` chỉ bắt việc làm online tại nhà.
* **Khác biệt cốt lõi:** Bẫy việc làm quốc tế thời vụ (visa nông nghiệp E-8) nhắm vào người lao động nông thôn, yêu cầu đóng cọc làm thủ tục xuất cảnh 5-10 triệu đồng.
* **Tín hiệu SMS:** `xuat khau lao dong`, `lao dong thoi vu han quoc`, `visa e8`, `coc lam visa`, `luong 45tr khong can tieng`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-EXP-001`).

#### 16. `CAND-016`: Mạo danh nhận tiền kiều hối Western Union / MoneyGram
* **So sánh với hiện tại:** `R-BNK-001` bắt hành vi đòi OTP chung chung.
* **Khác biệt cốt lõi:** Đưa ra mồi nhử cụ thể là khoản tiền ngoại tệ từ bà con Việt kiều gửi về để kích thích nạn nhân đăng nhập quy đổi ngoại tệ.
* **Tín hiệu SMS:** `nhan tien kieu hoi`, `western union`, `chuyen tien tu nuoc ngoai`, `quy doi ngoai te sang vnd`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-REMIT-001`).

#### 17. `CAND-017`: Mạo danh cơ quan BHXH dọa cắt quyền lợi thẻ BHYT
* **So sánh với hiện tại:** `R-GOV-003` bắt cập nhật sổ đỏ đất đai.
* **Khác biệt cốt lõi:** Đe dọa gián đoạn quyền lợi khám chữa bệnh bảo hiểm y tế nếu không cập nhật lại thông tin cá nhân.
* **Tín hiệu SMS:** `the bhyt bi khoa`, `sai thong tin the bhyt`, `cat quyen loi kham chua benh`, `gia han the bhyt`.
* **Kết luận:** **`ADD`** (Cần tạo Rule `R-BHYT-001`).

---

### 3.2 Nhóm `REFINE` & `VARIANT` (4 Ứng viên)

* **`CAND-021` (REFINE):** Tinh chỉnh `R-BNK-002` để bổ sung nhánh từ khóa `nâng hạn mức thẻ tín dụng`, `kích hoạt thẻ tín dụng được duyệt` nhằm bao phủ chiều kích hứa hẹn lợi ích tài chính từ ngân hàng.
* **`CAND-018` (VARIANT):** Bổ sung biến thể phiếu cào trúng thưởng quét mã QR vào kịch bản trúng thưởng `R-PRIZE-001`.
* **`CAND-019` (VARIANT):** Bổ sung biến thể Bot AI Trading tự động khớp lệnh sinh lời 3%/ngày vào kịch bản đầu tư `R-JOB-001`.
* **`CAND-022` (VARIANT):** Bổ sung biến thể làm nhiệm vụ dịch phụ đề phim / gõ văn bản tại nhà vào `R-JOB-001`.

---

### 3.3 Nhóm `MERGE` & `RESEARCH_MORE` (3 Ứng viên)

* **`CAND-023` (MERGE):** Hợp nhất 6 quy tắc Copilot thô (`R-COPILOT-1222`, `R-COPILOT-2389`, `R-COPILOT-2384`, `R-COPILOT-2381`, `R-COPILOT-2375`, `R-COPILOT-2369`, `R-COPILOT-2212`) vì cả 6 quy tắc này đều dùng chung 1 logic thô `REGEX_DISTANCE(tien, gap, 35)`. Đề xuất giữ lại 1 quy tắc chuẩn hóa `R-COPILOT-SOCIAL` để tránh trùng lặp.
* **`CAND-020` (RESEARCH_MORE):** Thuốc đông y giả chữa dứt điểm bệnh là vi phạm thương mại lừa dối người tiêu dùng, cần nghiên cứu thêm từ điển dược phẩm chuyên biệt trước khi tích hợp.
* **`CAND-024` (RESEARCH_MORE):** Tấn công trạm BTS giả 5G SA ngắt mã hóa đòi hỏi dữ liệu đo tầng vô tuyến (RSRP, TAC, PCI) từ hệ điều hành điện thoại, hiện tại chưa thể phát hiện thuần túy bằng nội dung SMS.
