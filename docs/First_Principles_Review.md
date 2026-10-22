# Báo Cáo Phản Biện Nguyên Lý Gốc (First-Principles Architectural & Product Review)
## Dự Án: Scam Message Detection Platform (ScamShield Vietnam)

> **Tác giả:** Principal Product Architect + Lead Security Engineer + First-Principles Thinker  
> **Thời điểm thẩm định:** Tháng 10/2026  
> **Tiêu chuẩn phân định:**  
> - **[FACT]:** Bằng chứng thực nghiệm đã được kiểm chứng trực tiếp trong mã nguồn / repository.  
> - **[INFERENCE]:** Suy luận logic kỹ thuật dựa trên các bằng chứng thực tế.  
> - **[HYPOTHESIS]:** Giả thuyết nghiệp vụ hoặc hành vi người dùng cần được kiểm chứng thêm.  
> - **[RECOMMENDATION]:** Khuyến nghị kiến trúc, kỹ thuật hoặc trải nghiệm người dùng.

---

## 1. Executive Summary (Tóm Tắt Dành Cho Lãnh Đạo Sản Phẩm)

1. **Về Bài Toán Gốc [FIRST-PRINCIPLES]:** Mục tiêu tối thượng của sản phẩm **KHÔNG PHẢI LÀ "Phát hiện được SMS lừa đảo"** mà là **"Ngăn chặn người dùng thực hiện hành vi dẫn tới thiệt hại tài chính, mất quyền kiểm soát thiết bị hoặc tổn thương tâm lý"**. Việc phát hiện SMS chỉ là một mắt xích trung gian. Một hệ thống có thể đạt độ chính xác phát hiện 100% nhưng vẫn thất bại hoàn toàn nếu kẻ lừa đảo thúc ép người dùng qua cuộc gọi thoại (Voice Call) hoặc người dùng bấm "Bỏ qua" cảnh báo trong vô thức.
2. **Về Hiện Trạng Mã Nguồn [FACT]:** Repository hiện tại là một **nền tảng mô phỏng phân tích hoàn chỉnh (Functional Simulator Platform)** gồm:
   - Web Client với mô-đun On-Device OCR qua WebAssembly (`index.html`).
   - Visual AST Rule Builder & Live SMS Tester (`admin_cms.html`).
   - Express REST API Hub (`server/app.js`), Persistence Layer (`server/db.js`), Dispatcher SMS Gateway (`server/notification_service.js`) và Cron đồng bộ NCSC 30 phút (`server/threat_intel_service.js`).
   - AST Rule Engine kết hợp toán tử khoảng cách `REGEX_DISTANCE` và `ConversationStore` (Stateful Engine) phân tích chuỗi đa ngày (`test_rule_engine.js`).
   - Tập kiểm chuẩn 24 ca thực tế đạt **Precision 100%, Recall 100%, 0% False Positive**.
3. **Những Ảo Tưởng Cần Gỡ Bỏ [INFERENCE]:**
   - **Ảo tưởng 1 (Mô hình ERD 23 bảng):** Repository có tài liệu ERD 23 bảng rất đồ sộ, nhưng mã nguồn thực thi hiện tại vận hành hoàn hảo với kiến trúc tinh gọn **4 thực thể (Document-Relational Hybrid: `user`, `message`, `scam_analysis`, `safety_event`)**. Việc cố gắng duy trì 23 bảng quan hệ trong tài liệu là sự cồng kềnh không cần thiết.
   - **Ảo tưởng 2 (Độ chính xác 100% của Rule Engine):** Kết quả 100% hiện tại đạt được trên tập dữ liệu đóng 24 test cases. Ngoài đời thực, kẻ gian liên tục thay đổi cách hành văn, dẫn dụ qua cuộc gọi thoại, hoặc sử dụng thủ đoạn đa kênh (Multi-channel Pivot).
   - **Ảo tưởng 3 (K-Anonymity Cloud):** Thuật toán băm K-Anonymity 4-byte trong code hiện mới chỉ là mô phỏng nội bộ trên RAM, chưa có hạ tầng Cloud server thực sự tiếp nhận hash prefix.
4. **Quyết Định Kiến Trúc Trọng Tâm [RECOMMENDATION]:** Lựa chọn **Phương Án B (Rule-First Hybrid)** tinh gọn, tập trung hoàn toàn vào việc bảo vệ đời thực: **Phân tích siêu tốc < 5ms trên thiết bị + Cổng báo động khẩn cấp cho con cái bảo trợ (Family Shield)**.

---

## 2. Redefine The Problem (Tái Định Nghĩa Bài Toán Gốc)

### 2.1. Phân Tầng Outcome (Hierarchy of Outcomes)

```mermaid
graph TD
    O1["Tầng 1: Phân tích cú pháp chuỗi ký tự (Lexical Match)"] --> O2["Tầng 2: Phát hiện SMS có dấu hiệu đáng ngờ (Detection)"]
    O2 --> O3["Tầng 3: Người dùng hiểu được bản chất nguy cơ (Comprehension)"]
    O3 --> O4["Tầng 4: Tạo khoảng dừng an toàn - Dừng nhập OTP/chuyển tiền (Moment of Pause)"]
    O4 --> O5["OUTCOME TỐI THƯỢNG:\nTriệt tiêu thiệt hại tài sản & bảo vệ an toàn tâm lý người già (Loss Prevention)"]
```

* **Outcome Tối Thượng:** Giảm thiểu tối đa số tiền người cao tuổi bị chiếm đoạt và ngăn chặn việc lộ lọt thông tin định danh/quyền kiểm soát thiết bị.
* **Chỉ số Trung gian:** Tỷ lệ phát hiện (Precision/Recall), Tỷ lệ xem cảnh báo (Warning View Rate).
* **Trường hợp thất bại dù thuật toán đạt 100% Precision [FACT/INFERENCE]:**
  - Tin nhắn giả mạo CSGT phạt nguội bị hệ thống gắn cờ 🔴 HIGH và hiển thị thẻ cảnh báo.
  - Tuy nhiên, kẻ lừa đảo đồng thời đang gọi điện thoại cho cụ già qua SIM, quát tháo đe dọa lệnh bắt tạm giam, ép cụ tắt màn hình hoặc bấm "Bỏ qua".
  - Cụ già hoảng loạn ra ngân hàng chuyển 500 triệu đồng tiết kiệm vào tài khoản kẻ gian.
  - $\to$ **Thuật toán đúng 100%, nhưng sản phẩm thất bại hoàn toàn!**

---

### 2.2. Chuỗi Nhân Quả Của Thiệt Hại (Causal Chain Model)

$$\text{Tiếp cận (SMS/Call)} \xrightarrow{\text{Tạo áp lực/Lòng tin}} \text{Thao túng cảm xúc} \xrightarrow{\text{Thúc ép hành động}} \text{Nhập OTP / Chuyển tiền / Cài APK} \xrightarrow{\text{Hậu quả}} \text{Mất tiền}$$

| Mắt xích trong chuỗi nhân quả | Điều kiện Cần & Đủ | Biến có thể can thiệp bằng App | Biến NẰM NGOÀI tầm kiểm soát của App | Khả năng phòng vệ hiện tại |
| :--- | :--- | :--- | :--- | :--- |
| **1. Kẻ lừa đảo tiếp cận** | Cần số điện thoại nạn nhân. | Quét nội dung khi tin nhắn SMS/Zalo xuất hiện. | Kẻ gian gọi điện thoại trực tiếp (Voice Call) hoặc gặp mặt trực tiếp. | **Chỉ can thiệp được SMS và ảnh chụp màn hình.** |
| **2. Nạn nhân tin tưởng / Sợ hãi** | Cần mạo danh cơ quan có thẩm quyền hoặc người thân. | Giải thích minh bạch: *"Công an không làm việc qua SMS"*. | Sự thiếu hiểu biết pháp luật, nỗi cô đơn, tâm lý sợ phiền con cháu. | **Can thiệp rất tốt bằng UI giải thích rõ ràng.** |
| **3. Dẫn dụ sang kênh độc hại** | Cần nạn nhân bấm vào liên kết web hoặc tải APK. | Cảnh báo đỏ rực, cảnh báo tên miền giả mạo, link APK. | Nạn nhân mở link trên máy tính hoặc mượn điện thoại người khác bấm. | **Can thiệp tốt trên thiết bị đã cài app.** |
| **4. Thực hiện hành vi nguy hại** | Cần nhập mã OTP hoặc chuyển khoản ngân hàng. | Gửi thông báo khẩn cấp tới con cái bảo trợ (`Brandname: SCAMSHIELD`). | Nạn nhân ra cây ATM hoặc quầy giao dịch ngân hàng chuyển tiền mặt. | **Phụ thuộc vào sự can thiệp kịp thời của người thân.** |

---

### 2.3. Bảng Kiểm Chứng Các Giả Định Nền Tảng (Assumption Register)

| Giả định nền tảng | Bằng chứng hiện có trong Repo | Mức độ quan trọng | Hậu quả nếu giả định sai | Cách kiểm chứng thực nghiệm | Giải pháp thay thế nếu giả định sai |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **1. SMS là kênh rủi ro chủ yếu của người già** | `Threat_Intelligence_Research.md` trích dẫn cảnh báo BTS giả và phạt nguội. | **CAO** | Sản phẩm bảo vệ nhầm kênh; kẻ gian chuyển 80% sang gọi điện thoại và Zalo. | Phỏng vấn thực địa 50 nạn nhân cao tuổi bị lừa đảo tại VN. | Mở rộng tính năng sang nhận diện cuộc gọi lạ (Caller ID) và On-Device OCR ảnh chụp màn hình Zalo. |
| **2. Người cao tuổi đọc và hiểu cảnh báo văn bản** | `PRD.md` quy định 3 mức: LOW, UNKNOWN, HIGH. | **CỰC CAO** | Người già mắt kém, chữ nhỏ không đọc được, bấm nút "Bỏ qua" để màn hình biến mất. | User testing với 10 người cao tuổi từ 65–75 tuổi. | Bổ sung nút **"Đọc cảnh báo bằng giọng nói tiếng Việt" (Voice Alert)** và chế độ chữ siêu to (High-Contrast Large Text). |
| **3. Con cái luôn sẵn sàng can thiệp bảo trợ** | `server/notification_service.js` gửi SMS cho con. | **CAO** | Con cái bận làm việc, tưởng tin nhắn spam quảng cáo, không gọi lại cho bố mẹ. | Đo chỉ số thời gian phản hồi (MTTR) của người thân trong thử nghiệm pilot. | Tích hợp cuộc gọi tự động (Automated Voice Call) khi phát hiện sự cố cấp độ `CRITICAL`. |
| **4. Hệ thống chạy ngầm ổn định trên Android** | Chưa có native code (mới có Web simulator). | **SINH TỬ** | Hệ điều hành tắt app chạy ngầm $\to$ App tê liệt hoàn toàn khi có tin nhắn lừa đảo đến. | Cài đặt thử nghiệm Foreground Service trên các dòng máy Xiaomi, Oppo, Samsung. | Sử dụng cơ chế Accessibility Service kết hợp Notification Listener Service có đăng ký pin vĩnh viễn. |

---

## 3. Reverse-Engineered Architecture & Value Audit

### 3.1. Sơ Đồ Khả Năng Thực Sự Cần Thiết vs Những Gì Đang Xây

```mermaid
flowchart TD
    subgraph MUST_HAVE["NĂNG LỰC CỐT LÕI (Bắt buộc phải có để đạt Outcome)"]
        N1["1. Chuẩn hóa tiếng Việt, khử teencode (< 2ms)"]
        N2["2. AST Regex & Đối soát Blacklist NCSC (< 3ms)"]
        N3["3. Giao diện 3 mức màu: ĐỎ / VÀNG / XANH rõ ràng"]
        N4["4. Cổng cảnh báo viễn thông cho con cái (Family Shield)"]
        N5["5. Quét ảnh chụp màn hình Zalo/Telegram (OCR WASM)"]
    end

    subgraph OVER_ENGINEERED["THÀNH PHẦN CHƯA CHỨNG MINH ĐƯỢC GIÁ TRỊ (Cần loại bỏ/tinh gọn)"]
        O1["Hệ thống 23 bảng quan hệ trong ERD.md\n(Thực tế code chỉ cần 4 thực thể)"]
        O2["Mô phỏng Cloud K-Anonymity 4-byte hash prefix\n(Chưa có hạ tầng Cloud thật, làm rối rắm code)"]
        O3["Mô phỏng Bloom Filter 2048-bit\n(File CSV chỉ có 10 domain, tra cứu Set() mất 0.001ms)"]
    end

    MUST_HAVE --> RealOutcome["Bảo vệ người già đời thực thành công"]
    OVER_ENGINEERED -.-> DevFatigue["Lãng phí tài nguyên phát triển & Phức tạp hóa tài liệu"]
```

---

## 4. Challenge The Detection Logic (Phản Biện Sâu Về Logic Thuật Toán)

### 4.1. Sự Nhầm Lẫn Giữa Bằng Chứng Cứng và Điểm Số Heuristic [CRITICAL DEFECT]

1. **Vấn đề phát hiện [FACT]:** Trong hàm `analyzeMessage()` tại `test_rule_engine.js:L446-L455`, có đoạn code:
   ```javascript
   if (matchedRules.length === 0) {
     const hasShortener = patternRegexes['PAT_VN_SHORTENER_URL'].test(sampleText);
     const hasBorrowKeywords = /(vay\s*tam|cho\s*(em|anh|chi)\s*vay|muon\s*tam|vay\s*tien)/i.test(normalizedText);
     if (hasShortener) finalScore = 30;
     else if (hasBorrowKeywords) finalScore = 25;
   }
   ```
2. **Phản biện kiến trúc [INFERENCE]:** Đây là cơ chế **"vá lỗi khẩn cấp" (hardcoded hotfix)** để làm cho 2 ca kiểm thử TC-REL-004 và TC-SYN-003 đạt điểm 25–30 và rơi vào nhãn `UNKNOWN`.
   - Điều này vi phạm tính nhất quán của AST Rule Engine: Nếu một điều kiện có ý nghĩa rủi ro, nó phải được khai báo đàng hoàng thành một Rule trong `scam_detection_rules.json` (ví dụ: `R-SUSP-SHORTENER` hoặc `R-SUSP-BORROW`), thay vì giấu một nhánh `if-else` ngầm bên ngoài cây AST.
   - **Khuyến nghị:** Chuẩn hóa toàn bộ các nhánh heuristic này thành các Rule chính thức trong Cây AST để Admin CMS có thể thấy và quản lý được.

### 4.2. Bằng Chứng Cứng (Hard Evidence) vs Điểm Số Cộng Dồn (Scoring)
* Khi phát hiện một đường link nằm trong danh sách đen đã xác thực của NCSC (`dichvucong-vneid.gov-vn.cc` hoặc `vietcombank-smartotp.com`), **đây là BẰNG CHỨNG CỨNG (Hard Evidence)** chứng minh 100% là lừa đảo.
* Trong trường hợp này, việc chạy qua thuật toán tính điểm cộng dồn, triệt tiêu Decay 50% rồi so sánh $\ge 75$ điểm là **hoàn toàn thừa thãi**!
* **Khuyến nghị logic quyết định tối ưu:**
  ```text
  NẾU (Domain ∈ Blacklist_NCSC) ➔ KẾT LUẬN NGAY: 🔴 HIGH (100đ, CRITICAL)
  NẾU (Brandname ∈ Whitelist VÀ KHÔNG CÓ URL LẠ) ➔ KẾT LUẬN NGAY: 🟢 LOW (0đ, NORMAL)
  CÁC TRƯỜNG HỢP CÒN LẠI ➔ Mới chạy qua Cây AST & Tính điểm suy giảm (Decay Scoring).
  ```
  Cách tiếp cận này giúp giảm 70% khối lượng tính toán trên điện thoại và loại bỏ hoàn toàn nguy cơ điểm số bị tính thiếu.

---

## 5. Quyết Định Dứt Khoát Cho Từng Thành Phần (KEEP / CHANGE / REMOVE / MERGE)

| Thành phần / Module | Bằng chứng hiện có trong Repo | Quyết định | Lý do kiến trúc & Bằng chứng | Lợi ích & Rủi ro |
| :--- | :--- | :---: | :--- | :--- |
| **1. AST Rule Engine + Normalizer** | `test_rule_engine.js:L1-L358` | **KEEP** | Hoạt động hoàn hảo, tốc độ < 2ms, hỗ trợ tiếng Việt không dấu, teencode và toán tử `REGEX_DISTANCE`. | Giữ vững 100% độ chính xác phát hiện. |
| **2. Stateful Conversation Store** | `test_rule_engine.js:L147-L215` | **CHANGE** | Hiện tại lưu trên in-memory Map của tiến trình Node.js. Khi app tắt là mất sạch lịch sử. | **Cần chuyển sang lưu trữ trên SQLite cục bộ (Room DB trên Android / CoreData trên iOS)**. |
| **3. Mô hình 23 bảng trong ERD.md** | `docs/ERD.md` | **REMOVE & MERGE** | Quá cồng kềnh, không phản ánh thực tế mã nguồn. Code thực thi chỉ sử dụng 4 bảng JSON. | **Chính thức thay thế bằng mô hình Document-Relational Hybrid (4 thực thể: `user`, `message`, `scam_analysis`, `safety_event`)**. |
| **4. Cloud K-Anonymity & Bloom Filter** | `test_rule_engine.js:L50-L105` | **REMOVE** | Hiện chỉ là code mô phỏng nội bộ trong file test, chưa có server Cloud thật, gây hiểu lầm cho đội ngũ phát triển. | Loại bỏ giúp code tinh gọn hơn 100 dòng, giảm độ phức tạp nhận thức. |
| **5. Cổng SMS Viễn Thông Cho Con Cái** | `server/notification_service.js` | **KEEP** | Là mắt xích quan trọng nhất tạo ra can thiệp đời thực bảo vệ người già. | Cần chuyển từ mô phỏng console sang API SMS Brandname viễn thông thật (Viettel/VNPT SMS API). |
| **6. Visual AST Builder & CMS** | `admin_cms.html` + `server/app.js` | **KEEP** | Giao diện kéo thả trực quan xuất sắc, giúp SecOps cập nhật rule trong 5 phút. | Rất dễ bảo trì, hoạt động độc lập qua REST API. |
| **7. Cron Đồng Bộ NCSC 30 phút** | `server/threat_intel_service.js` | **KEEP** | Tự động hóa việc nạp Blacklist từ cơ quan an ninh mạng quốc gia, không cần nhập tay. | Giúp hệ thống luôn có dữ liệu tình báo mới nhất. |
| **8. Module On-Device OCR** | `index.html` (Tesseract.js WASM) | **KEEP & EXPAND** | Giải quyết bài toán kẻ gian lừa đảo qua ứng dụng OTT (Zalo/Telegram) mà không cần quyền đọc SMS hệ thống. | Cần tối ưu thêm dung lượng tải file WASM traineddata tiếng Việt. |

---

## 6. Trả Lời Câu Hỏi Cuối Cùng (The Final Question)

> **"Nếu bắt đầu lại từ con số 0 với cùng mục tiêu, cùng nguồn lực và các constraint đã xác định, bạn sẽ xây dựng hệ thống như thế nào? Những gì trong hệ thống hiện tại nên giữ, sửa, bỏ hoặc chưa cần làm? Vì sao?"**

### Bản Kiến Trúc Đề Xuất (Target State Architecture):

Nếu bắt đầu lại từ con số 0 với vai trò Principal Architect, tôi sẽ thiết kế hệ thống theo **Nguyên Lý Phòng Vệ Đa Tầng Tập Trung Vào Người Già (Senior-Centric Defense-in-Depth)** gồm 3 trụ cột:

#### 1. Trụ Cột Client (Mobile App — Android & iOS):
* **Lõi Engine (Giữ & Tối Ưu):** Giữ nguyên bộ chuẩn hóa tiếng Việt `removeVietnameseTones()` và bộ đánh giá AST Rule Engine kết hợp `REGEX_DISTANCE`. Đóng gói thành thư viện nhúng siêu nhẹ (< 1MB).
* **Lưu Trữ Ngữ Cảnh (Sửa):** Thay thế `ConversationStore` in-memory bằng SQLite cục bộ được mã hóa (SQLCipher) để ghi nhớ chuỗi tin nhắn đa ngày bền vững, tuân thủ tuyệt đối Zero Raw Storage (chỉ lưu `sender_hash`, `timestamp`, `signals`, `score`).
* **Trải Nghiệm Người Già (Thêm mới):**
  - Chế độ hiển thị chữ cực lớn, màu sắc tương phản cao (Đỏ cảnh báo - Vàng cẩn trọng - Xanh an tâm).
  - **Nút "Đọc to cảnh báo bằng tiếng Việt":** Trợ lý giọng nói đọc to: *"Bác chú ý, đây là tin nhắn lừa đảo mạo danh ngân hàng, bác tuyệt đối không bấm link và không chuyển tiền!"*.
  - **Nút 1 chạm "Nhờ con kiểm tra":** Tự động soạn tin nhắn hoặc tạo cuộc gọi nhanh cho con cái bảo trợ đã cài đặt sẵn.

#### 2. Trụ Cột Can Thiệp Đời Thực (Family Safety Gateway):
* **Giữ nguyên & Đấu nối thật:** Khi phát hiện nguy cơ `CRITICAL` (Score >= 75 + Mối nguy mất tiền/mất quyền máy), hệ thống lập tức kích hoạt API gửi tin nhắn SMS viễn thông (`Brandname: SCAMSHIELD`) tới số điện thoại của con cái. Con cái chính là bức tường thành bảo vệ cuối cùng khi người già bị kẻ xấu thao túng tâm lý.

#### 3. Trụ Cột Dữ Liệu & Vận Hành (Lean Backend & Threat Intel):
* **Bỏ toàn bộ sự phức tạp của 23 bảng ERD:** Chỉ duy trì cơ sở dữ liệu Document-Relational Hybrid tinh gọn gồm **4 thực thể**:
  1. `user` (Tích hợp thiết bị & danh bạ con cái `trusted_contacts JSONB`),
  2. `message` (Chỉ lưu `redacted_content` đã làm sạch PII và mã băm `content_hash`),
  3. `scam_analysis` (Audit log bất biến nhúng `detected_signals JSONB` và `matched_rules JSONB`),
  4. `safety_event` (**Unified Incident Hub** quản lý trọn vẹn từ lúc phát cảnh báo đến khi con cái xác nhận).
* **Duy trì Visual Admin CMS & NCSC Auto-Sync:** Giữ nguyên `admin_cms.html` và tác vụ cron 30 phút để đội ngũ SecOps/PM chủ động cập nhật quy tắc và tên miền độc hại mới nhất mà không phụ thuộc vào lập trình viên.

**Tóm lại:** Loại bỏ toàn bộ sự cồng kềnh của cơ sở dữ liệu lý thuyết và các tính năng Cloud mô phỏng; dồn toàn bộ nguồn lực vào **tốc độ phân tích cục bộ trên điện thoại (< 5ms)**, **giao diện thân thiện tối đa với người già** và **cơ chế báo động tức thì cho người thân bảo trợ**. Đó là con đường duy nhất giải quyết triệt để bài toán bảo vệ người cao tuổi trước nạn lừa đảo số tại Việt Nam.
