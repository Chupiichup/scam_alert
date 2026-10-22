-- ============================================================================
-- SCAM DETECTION RULES & PATTERNS — SEED DATA (POSTGRESQL)
-- Milestone 2: Production-Ready Seed Data for 5 Core Vietnam Scam Categories
-- Streamlined Atomic Document-Relational Hybrid Schema (8 Core Functional Entities)
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. SCAM CATEGORY ENUM (Thay thế bảng scam_category tĩnh bằng ENUM chuẩn hóa)
-- ----------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE scam_category_type AS ENUM (
        'BANK_IMPERSONATION',       -- Mạo danh Ngân hàng & Tài chính
        'GOV_IMPERSONATION',        -- Mạo danh Cơ quan Nhà nước & Công an
        'RELATIVE_IMPERSONATION',   -- Mạo danh Người thân & Chiếm quyền Zalo
        'JOB_SCAM',                 -- Lừa đảo Tuyển dụng & Đầu tư tài chính
        'RECOVERY_SCAM',            -- Lừa đảo Thu hồi vốn treo
        'CREDENTIAL_THEFT',         -- Đánh cắp Thông tin xác thực & OTP
        'URGENCY',                  -- Thao túng Tâm lý Khẩn cấp
        'PAYMENT_REQUEST',          -- Yêu cầu Chuyển khoản Tiền mặt
        'BENIGN_SIGNAL'             -- Tín hiệu An toàn & Giảm trừ rủi ro
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ----------------------------------------------------------------------------
-- 2. THREAT INTEL SOURCES (Nguồn tình báo an toàn không gian mạng)
-- ----------------------------------------------------------------------------
INSERT INTO threat_intel_source (id, source_code, name, trust_level, sync_interval_minutes, last_synced_at, is_active, created_at)
VALUES
    ('21000000-0000-0000-0000-000000000001', 'SRC-GOV-001', 'Cổng Thông tin Điện tử Bộ Công An (BCA/C08)', 'HIGH', 60, CURRENT_TIMESTAMP, TRUE, CURRENT_TIMESTAMP),
    ('21000000-0000-0000-0000-000000000002', 'SRC-GOV-002', 'Cục An toàn thông tin (NCSC / khonggianmang.vn)', 'HIGH', 30, CURRENT_TIMESTAMP, TRUE, CURRENT_TIMESTAMP),
    ('21000000-0000-0000-0000-000000000003', 'SRC-BNK-001', 'Cảnh báo An toàn Ngân hàng TMCP Ngoại thương (VCB)', 'HIGH', 120, CURRENT_TIMESTAMP, TRUE, CURRENT_TIMESTAMP),
    ('21000000-0000-0000-0000-000000000004', 'SRC-CLD-001', 'Cộng đồng Chống Lừa Đảo Việt Nam (chongluadao.vn)', 'HIGH', 15, CURRENT_TIMESTAMP, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (source_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. BRAND IDENTITY TARGETS (Danh bạ thương hiệu được bảo vệ)
-- ----------------------------------------------------------------------------
INSERT INTO brand_identity_target (id, brand_code, brand_name, legitimate_domains_jsonb, legitimate_brandnames_jsonb, is_high_risk_target, created_at)
VALUES
    ('31000000-0000-0000-0000-000000000001', 'VCB', 'Ngân hàng TMCP Ngoại thương Việt Nam (Vietcombank)', '["vietcombank.com.vn", "vcb.com.vn"]'::jsonb, '["Vietcombank", "VCB-Digibank"]'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('31000000-0000-0000-0000-000000000002', 'BIDV', 'Ngân hàng TMCP Đầu tư và Phát triển Việt Nam (BIDV)', '["bidv.com.vn"]'::jsonb, '["BIDV", "BIDV-SmartBanking"]'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('31000000-0000-0000-0000-000000000003', 'TCB', 'Ngân hàng TMCP Kỹ Thương Việt Nam (Techcombank)', '["techcombank.com.vn", "techcombank.com"]'::jsonb, '["Techcombank"]'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('31000000-0000-0000-0000-000000000004', 'BCA', 'Bộ Công An & Cục Cảnh sát Giao thông (C08)', '["bocongan.gov.vn", "csgt.vn"]'::jsonb, '["BoCongAn", "CucCSGT"]'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('31000000-0000-0000-0000-000000000005', 'VNEID', 'Hệ thống Định danh điện tử Quốc gia (VNeID)', '["vneid.gov.vn", "dichvucong.gov.vn"]'::jsonb, '["VNeID"]'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('31000000-0000-0000-0000-000000000006', 'SHOPEE', 'Sàn Thương mại Điện tử Shopee', '["shopee.vn"]'::jsonb, '["Shopee"]'::jsonb, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (brand_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. SIGNAL CATALOG & DEDUPLICATION STRATEGY
-- (Gộp bảng signal_dedup_group trực tiếp vào các cột dedup_group_code, dedup_strategy, group_score_cap)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signal_catalog (
    signal_code VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    category_code VARCHAR(64) NOT NULL,
    default_score NUMERIC(5,2) NOT NULL,
    severity_tier VARCHAR(16) NOT NULL DEFAULT 'HIGH',
    dedup_group_code VARCHAR(64),
    dedup_strategy VARCHAR(16) DEFAULT 'MAX_ONLY',
    group_score_cap NUMERIC(5,2),
    is_negative_evidence BOOLEAN DEFAULT FALSE,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO signal_catalog (signal_code, name, category_code, default_score, severity_tier, dedup_group_code, dedup_strategy, group_score_cap, is_negative_evidence, description, is_active, created_at)
VALUES
    ('OTP_REQUEST', 'Yêu cầu cung cấp mã OTP', 'CREDENTIAL_THEFT', 40.00, 'CRITICAL', 'GRP_CREDENTIAL_THEFT', 'MAX_ONLY', 45.00, FALSE, 'Tin nhắn đòi cung cấp hoặc nhập mã xác thực OTP', TRUE, CURRENT_TIMESTAMP),
    ('ACCOUNT_SUSPENSION_THREAT', 'Đe dọa khóa hoặc ngừng tài khoản', 'BANK_IMPERSONATION', 25.00, 'HIGH', 'GRP_URGENCY', 'DECAY_SUM', 35.00, FALSE, 'Cảnh báo tài khoản hoặc thẻ bị khóa trong 24h để gây hoảng sợ', TRUE, CURRENT_TIMESTAMP),
    ('BANK_IMPERSONATION_CLAIM', 'Tuyên bố mạo danh tổ chức ngân hàng', 'BANK_IMPERSONATION', 35.00, 'HIGH', 'GRP_IMPERSONATION', 'MAX_ONLY', 45.00, FALSE, 'Tự xưng Ngân hàng thương mại nhưng gửi kèm link giả mạo', TRUE, CURRENT_TIMESTAMP),
    ('FAKE_BRAND_DOMAIN', 'Tên miền giả mạo thương hiệu uy tín', 'BANK_IMPERSONATION', 45.00, 'CRITICAL', 'GRP_URL_RISK', 'MAX_ONLY', 50.00, FALSE, 'Tên miền typosquatting hoặc homoglyph nhái thương hiệu ngân hàng', TRUE, CURRENT_TIMESTAMP),
    ('CREDENTIAL_HARVESTING_ATTEMPT', 'Thu thập thông tin đăng nhập', 'CREDENTIAL_THEFT', 35.00, 'CRITICAL', 'GRP_CREDENTIAL_THEFT', 'MAX_ONLY', 45.00, FALSE, 'Điều hướng tới trang nhập mật khẩu hoặc mã PIN', TRUE, CURRENT_TIMESTAMP),
    ('GOV_AUTHORITY_IMPERSONATION', 'Mạo danh cơ quan công an CSGT', 'GOV_IMPERSONATION', 45.00, 'CRITICAL', 'GRP_IMPERSONATION', 'MAX_ONLY', 45.00, FALSE, 'Tự xưng Cục CSGT hoặc Cơ quan Điều tra Bộ Công An', TRUE, CURRENT_TIMESTAMP),
    ('LEGAL_PENALTY_COERCION', 'Đe dọa xử phạt pháp lý phạt nguội', 'GOV_IMPERSONATION', 40.00, 'HIGH', 'GRP_LEGAL_THREAT', 'MAX_ONLY', 40.00, FALSE, 'Đe dọa tăng phạt 50% hoặc tước bằng lái nếu không nộp tiền trong 48h', TRUE, CURRENT_TIMESTAMP),
    ('SUSPICIOUS_SENDER_FOR_AUTHORITY', 'Số cá nhân xưng danh cơ quan nhà nước', 'GOV_IMPERSONATION', 30.00, 'HIGH', 'GRP_SENDER_RISK', 'MAX_ONLY', 30.00, FALSE, 'Số di động cá nhân gửi tin xưng danh cơ quan chức năng', TRUE, CURRENT_TIMESTAMP),
    ('APK_DOWNLOAD_LINK', 'Liên kết tải tệp tin ứng dụng APK độc hại', 'GOV_IMPERSONATION', 50.00, 'CRITICAL', 'GRP_URL_RISK', 'MAX_ONLY', 50.00, FALSE, 'Đường link tải file .apk chiếm quyền trợ năng Android', TRUE, CURRENT_TIMESTAMP),
    ('URGENT_DEADLINE_48H', 'Ép buộc thời hạn gấp rút 24h-48h', 'URGENCY', 15.00, 'NORMAL', 'GRP_URGENCY', 'DECAY_SUM', 35.00, FALSE, 'Thúc ép thời gian hạn chế để nạn nhân không kịp kiểm chứng', TRUE, CURRENT_TIMESTAMP),
    ('RELATIVE_EMERGENCY_CLAIM', 'Viện cớ khẩn cấp liên quan người thân', 'RELATIVE_IMPERSONATION', 35.00, 'HIGH', 'GRP_SOCIAL_ENG', 'DECAY_SUM', 40.00, FALSE, 'Lý do tai nạn máy hỏng viện phí để tạo áp lực tình cảm', TRUE, CURRENT_TIMESTAMP),
    ('URGENT_MONEY_TRANSFER_REQUEST', 'Yêu cầu chuyển tiền gấp vào tài khoản', 'PAYMENT_REQUEST', 40.00, 'HIGH', 'GRP_FINANCIAL_ACTION', 'MAX_ONLY', 45.00, FALSE, 'Yêu cầu chuyển khoản ngay một số tiền cụ thể', TRUE, CURRENT_TIMESTAMP),
    ('UNREALISTIC_EARNING_PROMISE', 'Hứa hẹn thu nhập phi thực tế', 'JOB_SCAM', 35.00, 'HIGH', 'GRP_LURE', 'DECAY_SUM', 40.00, FALSE, 'Hứa hẹn việc nhẹ lương cao kiếm 500k-1tr/ngày hoặc lãi 25%/tuần', TRUE, CURRENT_TIMESTAMP),
    ('TASK_SCAM_KEYWORDS', 'Dụ dỗ làm nhiệm vụ trực tuyến giật đơn', 'JOB_SCAM', 30.00, 'HIGH', 'GRP_LURE', 'DECAY_SUM', 40.00, FALSE, 'Mời gọi đánh giá sản phẩm Shopee Tiktok giật đơn hoa hồng', TRUE, CURRENT_TIMESTAMP),
    ('REDIRECT_TO_UNOFFICIAL_CHAT', 'Điều hướng sang Telegram hoặc Zalo kín', 'JOB_SCAM', 25.00, 'NORMAL', 'GRP_COMMUNICATION', 'MAX_ONLY', 25.00, FALSE, 'Yêu cầu kết bạn Zalo hoặc vào nhóm Telegram kín nhận nhiệm vụ', TRUE, CURRENT_TIMESTAMP),
    ('RECOVERY_SCAM_PROMISE', 'Cam kết thu hồi 100% tiền lừa đảo', 'RECOVERY_SCAM', 45.00, 'CRITICAL', 'GRP_LURE', 'DECAY_SUM', 40.00, FALSE, 'Mạo danh luật sư hoặc an ninh mạng hứa lấy lại tiền đã mất', TRUE, CURRENT_TIMESTAMP),
    ('UPFRONT_FEE_DEMAND', 'Đòi đóng phí hồ sơ giải ngân trước', 'RECOVERY_SCAM', 45.00, 'CRITICAL', 'GRP_FINANCIAL_ACTION', 'MAX_ONLY', 45.00, FALSE, 'Bắt nộp 10-20% phí thủ tục trước khi được giải ngân tiền treo', TRUE, CURRENT_TIMESTAMP),
    ('VNEID_LAND_UPDATE_SCAM', 'Yêu cầu tích hợp cập nhật sổ đỏ vào VNeID', 'GOV_IMPERSONATION', 45.00, 'CRITICAL', 'GRP_LEGAL_THREAT', 'MAX_ONLY', 50.00, FALSE, 'Mạo danh cán bộ yêu cầu đồng bộ sổ đỏ đất đai qua app VNeID giả mạo hoặc nộp phí', TRUE, CURRENT_TIMESTAMP),
    ('OFFICIAL_SECURITY_WARNING_PRESENT', 'Khuyến cáo bảo mật ngân hàng chính thống', 'BENIGN_SIGNAL', -40.00, 'NORMAL', 'GRP_BENIGN_DISCOUNT', 'MAX_ONLY', -50.00, TRUE, 'Chứa câu không cung cấp OTP cho bất kỳ ai giúp giảm điểm rủi ro', TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (signal_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 5. KEYWORD DICTIONARY & VARIANTS
-- (Gộp bảng keyword_variant trực tiếp vào cột variants TEXT[] có GIN Index)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS keyword_dictionary (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keyword_text VARCHAR(256) NOT NULL,
    variants TEXT[] NOT NULL DEFAULT '{}',
    language VARCHAR(8) NOT NULL DEFAULT 'vi',
    category_code VARCHAR(64) NOT NULL,
    default_signal_code VARCHAR(64) NOT NULL REFERENCES signal_catalog(signal_code),
    default_risk_weight NUMERIC(5,2) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_keyword_dict_variants ON keyword_dictionary USING gin (variants);

INSERT INTO keyword_dictionary (id, keyword_text, variants, language, category_code, default_signal_code, default_risk_weight, is_active, valid_from, created_at)
VALUES
    ('c1000000-0000-0000-0000-000000000001', 'tài khoản bị khóa', ARRAY['tai khoan bi khoa', 't.k bi khoa', 'khoa the', 'tam ngung the'], 'vi', 'BANK_IMPERSONATION', 'ACCOUNT_SUSPENSION_THREAT', 25.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000002', 'mã OTP', ARRAY['0TP', 'o-t-p', 'ma otp', 'ma xac thuc'], 'vi', 'CREDENTIAL_THEFT', 'OTP_REQUEST', 40.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000003', 'cung cấp mã OTP', ARRAY['nhap otp', 'gui ma otp', 'cung cap otp', 'nhap 0tp'], 'vi', 'CREDENTIAL_THEFT', 'OTP_REQUEST', 45.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000004', 'cục cảnh sát giao thông', ARRAY['cuc canh sat giao thong', 'c.s.g.t', 'csgt', 'canh sat giao thong'], 'vi', 'GOV_IMPERSONATION', 'GOV_AUTHORITY_IMPERSONATION', 45.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000005', 'thông báo phạt nguội', ARRAY['thong bao phat nguoi', 'phat nguoi', 'nop phat trong 48h'], 'vi', 'GOV_IMPERSONATION', 'LEGAL_PENALTY_COERCION', 40.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000006', 'chuyển gấp', ARRAY['chuyen gap', 'ban ho', 'vay tam', 'chuyen ho'], 'vi', 'PAYMENT_REQUEST', 'URGENT_MONEY_TRANSFER_REQUEST', 40.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000007', 'việc nhẹ lương cao', ARRAY['viec nhe luong cao', 'kiem 500k/ngay', 'giat don shopee', 'lam nhiem vu online'], 'vi', 'JOB_SCAM', 'UNREALISTIC_EARNING_PROMISE', 35.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000008', 'thu hồi vốn treo', ARRAY['thu hoi von treo', 'lay lai tien lua dao', 'thu hoi tien treo'], 'vi', 'RECOVERY_SCAM', 'RECOVERY_SCAM_PROMISE', 45.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000009', 'đóng phí hồ sơ', ARRAY['dong phi ho so', 'phi giai toa', 'phi giai ngan', 'dat coc truoc'], 'vi', 'RECOVERY_SCAM', 'UPFRONT_FEE_DEMAND', 45.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000010', 'không cung cấp mã OTP cho bất kỳ ai', ARRAY['khong cung cap ma otp cho bat ky ai', 'khong chia se ma otp', 'khong chia se otp'], 'vi', 'BENIGN_SIGNAL', 'OFFICIAL_SECURITY_WARNING_PRESENT', -40.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('c1000000-0000-0000-0000-000000000011', 'cập nhật sổ đỏ', ARRAY['cap nhat so do', 'tich hop so do vneid', 'dong bo du lieu dat dai', 'so do vneid', 'dich vu cong dat dai'], 'vi', 'GOV_IMPERSONATION', 'VNEID_LAND_UPDATE_SCAM', 45.00, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 6. DETECTION PATTERNS (Thư viện biểu thức mẫu Regex tái sử dụng)
-- ----------------------------------------------------------------------------
INSERT INTO detection_pattern (id, pattern_code, name, pattern_type, expression_pattern, parameters_jsonb, is_active, created_at)
VALUES
    ('e1000000-0000-0000-0000-000000000001', 'PAT_VN_OTP_DEMAND', 'Mẫu yêu cầu chia sẻ hoặc nhập mã OTP', 'REGEX', '(?i)(nhap|nhập|cung\s*cap|cung\s*cấp|gui|gửi|chia\s*se|chia\s*sẻ)\s*(ma|mã)?\s*(otp|o-t-p|0tp)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000002', 'PAT_VN_BANK_URGENCY', 'Mẫu dọa khóa tài khoản ngân hàng trong thời hạn giờ', 'REGEX', '(?i)(tai\s*khoan|tài\s*khoản|the|thẻ|dich\s*vu|dịch\s*vụ|t\.k)\s*(se|sẽ)?\s*(bi\s*khoa|bị\s*khóa|tam\s*ngung|tạm\s*ngừng|het\s*han|hết\s*hạn|dung\s*chuyen\s*tien|dừng\s*chuyển\s*tiền|k\.h\.o\.a).{0,100}(trong\s*vong|trong\s*vòng|truoc\s*khi|trước\s*khi|\d+\s*gio|\d+\s*giờ|\d+h|tu\s*0h|từ\s*0h)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000003', 'PAT_VN_POLICE_FINE_THREAT', 'Mẫu công an phạt nguội đe dọa tăng phạt', 'REGEX', '(?i)(cuc\s*csgt|cục\s*csgt|cuc\s*canh\s*sat|cục\s*cảnh\s*sát|cong\s*an|công\s*an|phat\s*nguoi|phạt\s*nguội|vien\s*kiem\s*sat|viện\s*kiểm\s*sát).{0,100}(nop\s*phat|nộp\s*phạt|tang\s*muc\s*phat|tăng\s*mức\s*phạt|tam\s*giu|tạm\s*giữ|truy\s*na|truy\s*nã|chuyen\s*toan\s*bo\s*tien|chuyển\s*toàn\s*bộ\s*tiền|tai\s*khoan\s*tam\s*giu)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000004', 'PAT_VN_RELATIVE_BORROW', 'Mẫu người thân xưng hô mượn tiền chuyển gấp', 'REGEX', '(?i)(me\s*oi|mẹ\s*ơi|bo\s*oi|bố\s*ơi|anh\s*oi|anh\s*ơi|chi\s*oi|chị\s*ơi|em\s*nho|em\s*nhờ|con\s*day|con\s*đây).{0,150}(((chuyen\s*gap|chuyển\s*gấp|ban\s*ho|bắn\s*hộ|chuyen\s*ho|chuyển\s*hộ|vay\s*tam|vay\s*tạm|chuyen\s*khoan|chuyển\s*khoản|chuyen\s*tien|chuyển\s*tiền|gui\s*cho|gửi\s*cho).{0,80}(\d+\s*(trieu|triệu|tr|k)|tien|tiền))|((\d+\s*(trieu|triệu|tr|k)|tien|tiền).{0,80}(chuyen\s*gap|chuyển\s*gấp|ban\s*ho|bắn\s*hộ|chuyen\s*ho|chuyển\s*hộ|vay\s*tam|vay\s*tạm|chuyen\s*khoan|chuyển\s*khoản|chuyen\s*tien|chuyển\s*tiền|gui\s*cho|gửi\s*cho)))', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000005', 'PAT_VN_TASK_JOB_OFFER', 'Mẫu tuyển dụng CTV việc nhẹ lương cao giật đơn hoặc đầu tư', 'REGEX', '(?i)(tuyen\s*ctv|tuyển\s*ctv|viec\s*nhe|việc\s*nhẹ|lam\s*nhiem\s*vu|làm\s*nhiệm\s*vụ|ctv\s*online|danh\s*gia\s*san\s*pham|đánh\s*giá\s*sản\s*phẩm|quy\s*dau\s*tu|quỹ\s*đầu\s*tư|dau\s*tu|đầu\s*tư|sinh\s*loi|sinh\s*lời).{0,120}(thu\s*nhap|thu\s*nhập|\d+k\/ngay|\d+k\/ngày|kiem\s*tien|kiếm\s*tiền|hoa\s*hong|hoa\s*hồng|nhan\s*tien|nhận\s*tiền|loi\s*nhuan|lợi\s*nhuận|bao\s*hiem\s*von|bảo\s*hiểm\s*vốn|500k\s*trai\s*nghiem)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000006', 'PAT_VN_RECOVERY_FEE', 'Mẫu lấy lại tiền lừa đảo đòi đóng phí hồ sơ', 'REGEX', '(?i)(thu\s*hoi|thu\s*hồi|lay\s*lai|lấy\s*lại|ho\s*tro|hỗ\s*trợ|cam\s*ket\s*thu\s*hoi|cam\s*kết\s*thu\s*hồi).{0,80}(tien\s*lua\s*dao|tiền\s*lừa\s*đảo|tien\s*treo|tiền\s*treo|tien\s*da\s*mat|tiền\s*đã\s*mất).{0,120}(dong\s*phi|đóng\s*phí|phi\s*giai\s*toa|phí\s*giải\s*tỏa|phi\s*ho\s*so|phí\s*hồ\s*sơ|phi\s*giai\s*ngan|phí\s*giải\s*ngân|dat\s*coc|đặt\s*cọc)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000007', 'PAT_VN_MALICIOUS_APK_LINK', 'Mẫu đường dẫn tải trực tiếp file cài đặt APK ngoài', 'REGEX', '(?i)https?:\/\/[^\s]+\.(apk|bin)(\?[^\s]*)?', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000008', 'PAT_VN_SHORTENER_URL', 'Mẫu dịch vụ rút gọn link che giấu trang đích', 'REGEX', '(?i)https?:\/\/(bit\.ly|tinyurl\.com|t\.co|shorturl\.at|cutt\.ly)\/[a-zA-Z0-9_\-]+', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP),
    ('e1000000-0000-0000-0000-000000000009', 'PAT_VN_VNEID_LAND_SCAM', 'Mẫu mạo danh cập nhật sổ đỏ giấy tờ đất đai qua VNeID', 'REGEX', '(?i)(cap\s*nhat|cập\s*nhật|tich\s*hop|tích\s*hợp|dong\s*bo|đồng\s*bộ|sai\s*lech|sai\s*lệch|thieu|thiếu|chuan\s*hoa|chuẩn\s*hóa).{0,60}(so\s*do|sổ\s*đỏ|so\s*hong|sổ\s*hồng|dat\s*dai|đất\s*đai|nha\s*dat|nhà\s*đất|thua\s*dat|thửa\s*đất|dia\s*chinh|địa\s*chính).{0,80}(vneid|vne-id|dich\s*vu\s*cong|dịch\s*vụ\s*công|muc\s*2|mức\s*2|app|ung\s*dung|ứng\s*dụng)', '{"flags": "i"}'::jsonb, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (pattern_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 7. SCAM SCENARIOS
-- (Gộp bảng scenario_rule_step trực tiếp vào cột steps JSONB)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scam_scenario (
    scenario_code VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    category_code VARCHAR(64) NOT NULL,
    narrative_description TEXT,
    typical_channel VARCHAR(32) NOT NULL DEFAULT 'SMS',
    baseline_severity VARCHAR(16) NOT NULL DEFAULT 'HIGH',
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO scam_scenario (scenario_code, name, category_code, narrative_description, typical_channel, baseline_severity, steps, is_active, created_at)
VALUES
    ('SCEN_VN_BANK_IMPERSONATION', 'Giả danh Ngân hàng chiếm đoạt tài khoản', 'BANK_IMPERSONATION', 'Dọa khóa thẻ hoặc cập nhật sinh trắc học để dẫn dụ vào trang web giả mạo đánh cắp OTP', 'SMS_BRANDNAME', 'CRITICAL',
     '[{"step": 1, "name": "CLAIM_BANK_IDENTITY", "signal": "BANK_IMPERSONATION_CLAIM", "mandatory": true}, {"step": 2, "name": "INDUCE_PANIC_LOCK", "signal": "ACCOUNT_SUSPENSION_THREAT", "mandatory": true}, {"step": 3, "name": "EXTORT_OTP_OR_URL", "signal": "OTP_REQUEST", "mandatory": true}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP),

    ('SCEN_VN_POLICE_COERCION', 'Mạo danh CSGT thông báo phạt nguội dọa bắt giam', 'GOV_IMPERSONATION', 'Mạo danh công an phạt nguội đe dọa tăng phạt để ép chuyển tiền hoặc cài đặt APK mã độc', 'SMS', 'CRITICAL',
     '[{"step": 1, "name": "CLAIM_POLICE_AUTHORITY", "signal": "GOV_AUTHORITY_IMPERSONATION", "mandatory": true}, {"step": 2, "name": "COERCE_FINE_PENALTY", "signal": "LEGAL_PENALTY_COERCION", "mandatory": true}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP),

    ('SCEN_VN_RELATIVE_TAKEOVER', 'Chiếm quyền Zalo mượn tiền người thân', 'RELATIVE_IMPERSONATION', 'Đánh cắp tài khoản Zalo của con cháu viện cớ khẩn cấp máy hỏng nhờ chuyển tiền vào tài khoản lạ', 'ZALO', 'HIGH',
     '[{"step": 1, "name": "RELATIVE_EMERGENCY_CLAIM", "signal": "RELATIVE_EMERGENCY_CLAIM", "mandatory": true}, {"step": 2, "name": "REQUEST_MONEY_TRANSFER", "signal": "URGENT_MONEY_TRANSFER_REQUEST", "mandatory": true}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP),

    ('SCEN_VN_TASK_INVESTMENT', 'Bẫy tuyển cộng tác viên giật đơn Shopee đầu tư sàn ảo', 'JOB_SCAM', 'Hứa hẹn việc nhẹ lương cao nạp tiền làm nhiệm vụ sau đó phong tỏa tiền ép nạp thêm', 'SMS', 'HIGH',
     '[{"step": 1, "name": "OFFER_TASK_OR_JOB", "signal": "UNREALISTIC_EARNING_PROMISE", "mandatory": true}, {"step": 2, "name": "LURE_TO_CHAT_OR_PLATFORM", "signal": "REDIRECT_TO_UNOFFICIAL_CHAT", "mandatory": true}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP),

    ('SCEN_VN_RECOVERY_FRAUD', 'Bẫy thu hồi vốn treo lấy lại tiền bị lừa', 'RECOVERY_SCAM', 'Mạo danh luật sư hoặc an ninh mạng hứa lấy lại tiền đòi nộp phí giải ngân trước', 'ZALO', 'CRITICAL',
     '[{"step": 1, "name": "PROMISE_RECOVERY", "signal": "RECOVERY_SCAM_PROMISE", "mandatory": true}, {"step": 2, "name": "DEMAND_UPFRONT_FEE", "signal": "UPFRONT_FEE_DEMAND", "mandatory": true}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP),

    ('SCEN_VN_VNEID_LAND_FRAUD', 'Mạo danh Công an / Địa chính cập nhật Sổ đỏ trên VNeID', 'GOV_IMPERSONATION', 'Mạo danh cán bộ thông báo hồ sơ đất đai sai lệch, yêu cầu cập nhật sổ đỏ vào VNeID mức 2 để cài app độc hại chiếm quyền ngân hàng hoặc thu phí đồng bộ', 'SMS', 'CRITICAL',
     '[{"step": 1, "name": "CLAIM_GOV_LAND_AUTHORITY", "signal": "GOV_AUTHORITY_IMPERSONATION", "mandatory": true}, {"step": 2, "name": "VNEID_LAND_UPDATE_DEMAND", "signal": "VNEID_LAND_UPDATE_SCAM", "mandatory": true}, {"step": 3, "name": "MALICIOUS_APP_INSTALL", "signal": "APK_DOWNLOAD_LINK", "mandatory": false}, {"step": 4, "name": "UPFRONT_SYNC_FEE", "signal": "URGENT_MONEY_TRANSFER_REQUEST", "mandatory": false}]'::jsonb,
     TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (scenario_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 8. DETECTION RULES (Quy tắc logic phát hiện cốt lõi)
-- ----------------------------------------------------------------------------
INSERT INTO detection_rule (id, rule_code, name, description, category_code, rule_type, target_input, priority, is_active, current_published_version_id, created_at, updated_at)
VALUES
    ('a1000000-0000-0000-0000-000000000001', 'R-BNK-001', 'Yêu cầu mã OTP qua liên kết độc hại', 'Chặn đứng hành vi đòi mã OTP đi kèm link dẫn dụ', 'CREDENTIAL_THEFT', 'COMPOSITE', 'COMPOSITE', 95, TRUE, 'b1000000-0000-0000-0000-000000000001', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000002', 'R-BNK-002', 'Mạo danh Ngân hàng gửi liên kết dọa khóa tài khoản', 'Phát hiện tên miền ngân hàng giả mạo typosquatting', 'BANK_IMPERSONATION', 'COMPOSITE', 'COMPOSITE', 90, TRUE, 'b1000000-0000-0000-0000-000000000002', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000003', 'R-POL-001', 'Mạo danh CSGT thông báo phạt nguội từ số cá nhân', 'Chặn tin nhắn phạt nguội gửi từ sim rác cá nhân', 'GOV_IMPERSONATION', 'COMPOSITE', 'COMPOSITE', 90, TRUE, 'b1000000-0000-0000-0000-000000000003', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000004', 'R-POL-002', 'Giả mạo Dịch vụ công dụ dỗ cài đặt ứng dụng APK độc hại', 'Ngăn chặn tệp tin mã độc APK chiếm quyền trợ năng Android', 'GOV_IMPERSONATION', 'COMPOSITE', 'COMPOSITE', 95, TRUE, 'b1000000-0000-0000-0000-000000000004', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000005', 'R-REL-001', 'Mạo danh người thân viện cớ khẩn cấp nhờ chuyển tiền gấp', 'Phát hiện mẫu mượn tiền gấp và tài khoản bất thường', 'RELATIVE_IMPERSONATION', 'COMPOSITE', 'COMPOSITE', 85, TRUE, 'b1000000-0000-0000-0000-000000000005', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000006', 'R-JOB-001', 'Lừa đảo tuyển cộng tác viên làm nhiệm vụ online', 'Chặn bẫy việc nhẹ lương cao giật đơn ảo Shopee', 'JOB_SCAM', 'COMPOSITE', 'COMPOSITE', 85, TRUE, 'b1000000-0000-0000-0000-000000000006', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000007', 'R-RCV-001', 'Bẫy thu hồi vốn treo / lấy lại tiền lừa đảo đòi nộp phí', 'Chặn chiêu trò thu hồi tiền lừa đảo đòi phí giải ngân', 'RECOVERY_SCAM', 'COMPOSITE', 'COMPOSITE', 95, TRUE, 'b1000000-0000-0000-0000-000000000007', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000008', 'R-SAFE-001', 'Nhận diện tin nhắn cảnh báo an toàn chính thống của Ngân hàng', 'Cơ chế giảm điểm rủi ro khi có khuyến cáo an toàn', 'BENIGN_SIGNAL', 'COMPOSITE', 'COMPOSITE', 99, TRUE, 'b1000000-0000-0000-0000-000000000008', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('a1000000-0000-0000-0000-000000000009', 'R-GOV-003', 'Mạo danh cơ quan chức năng yêu cầu cập nhật Sổ đỏ trên ứng dụng VNeID', 'Cảnh báo thủ đoạn mạo danh công an/địa chính đồng bộ sổ đỏ trên VNeID', 'GOV_IMPERSONATION', 'COMPOSITE', 'COMPOSITE', 95, TRUE, 'b1000000-0000-0000-0000-000000000009', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (rule_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 9. RULE VERSIONS & EMITTED SIGNALS
-- (Gộp bảng rule_signal_mapping trực tiếp vào cột emitted_signals JSONB)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rule_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rule(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    condition_tree_jsonb JSONB NOT NULL,
    emitted_signals JSONB NOT NULL DEFAULT '[]'::jsonb,
    input_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_confidence NUMERIC(3,2) NOT NULL DEFAULT 0.90,
    status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',
    created_by UUID,
    approved_by UUID,
    change_summary TEXT,
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_rule_version UNIQUE (rule_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_rule_version_emitted ON rule_version USING gin (emitted_signals jsonb_path_ops);

INSERT INTO rule_version (id, rule_id, version_number, condition_tree_jsonb, emitted_signals, input_requirements, default_confidence, status, created_by, approved_by, change_summary, published_at, created_at)
VALUES
    ('b1000000-0000-0000-0000-000000000001', 'a1000000-0000-0000-0000-000000000001', 1, 
     '{"operator": "AND", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_OTP_DEMAND"}, {"operator": "OR", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["cung cap ma otp", "nhap otp", "gui ma xac thuc", "gui ma otp", "nhap 0tp", "xac minh"]}, {"operator": "CONTAINS_URL", "field": "urls", "value": true}]}, {"operator": "NOT", "condition": {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["khong cung cap ma otp cho bat ky ai", "khong chia se ma otp", "khong chia se otp", "canh bao lua dao"]}}]}'::jsonb,
     '[{"signal_code": "OTP_REQUEST", "score_contribution": 40.00, "confidence_weight": 0.95, "user_explanation_vi": "Tin nhắn đang yêu cầu bạn cung cấp mã số bí mật (mã OTP). Ngân hàng tuyệt đối không bao giờ yêu cầu chia sẻ mã này!"}, {"signal_code": "CREDENTIAL_HARVESTING_ATTEMPT", "score_contribution": 35.00, "confidence_weight": 0.90, "user_explanation_vi": "Tin nhắn có dấu hiệu dẫn dụ bạn truy cập vào website giả mạo nhằm đánh cắp thông tin tài khoản."}]'::jsonb,
     '["normalized_text", "urls"]'::jsonb, 0.95, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000002', 'a1000000-0000-0000-0000-000000000002', 1,
     '{"operator": "AND", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["vietcombank", "techcombank", "mbbank", "bidv", "agribank", "ngan hang", "vcb", "tai khoan bi khoa", "the bi tam ngung", "dung chuyen tien", "sinh trac hoc", "t.k bi k.h.o.a", "t.k bi khoa"]}, {"operator": "CONTAINS_URL", "field": "urls", "value": true}, {"operator": "OR", "conditions": [{"operator": "URL_HAS_INDICATOR", "indicator_types": ["MALICIOUS", "SUSPICIOUS"]}, {"operator": "IS_HOMOGLYPH_DOMAIN", "value": true}]}]}'::jsonb,
     '[{"signal_code": "BANK_IMPERSONATION_CLAIM", "score_contribution": 35.00, "confidence_weight": 0.95, "user_explanation_vi": "Tin nhắn nhắc tên Ngân hàng nhưng được gửi kèm đường dẫn trang web giả mạo."}, {"signal_code": "FAKE_BRAND_DOMAIN", "score_contribution": 45.00, "confidence_weight": 0.98, "user_explanation_vi": "Đường link trong tin nhắn không phải trang web chính thức của ngân hàng."}, {"signal_code": "ACCOUNT_SUSPENSION_THREAT", "score_contribution": 25.00, "confidence_weight": 0.90, "user_explanation_vi": "Tin nhắn đe dọa khóa thẻ/tài khoản nhằm gây hoang mang, thúc ép bạn bấm vào liên kết lạ."}]'::jsonb,
     '["normalized_text", "urls"]'::jsonb, 0.98, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000003', 'a1000000-0000-0000-0000-000000000003', 1,
     '{"operator": "AND", "conditions": [{"operator": "OR", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_POLICE_FINE_THREAT"}, {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["cuc canh sat giao thong", "phat nguoi", "vi pham giao thong", "nop phat trong 48h", "vien kiem sat", "lenh bat tam giam", "ma tuy", "rua tien", "tai khoan tam giu"]}]}, {"operator": "SENDER_MATCHES_CRITERIA", "field": "sender_type", "in": ["PHONE_DOMESTIC", "PHONE_INTERNATIONAL"]}]}'::jsonb,
     '[{"signal_code": "GOV_AUTHORITY_IMPERSONATION", "score_contribution": 45.00, "confidence_weight": 0.95, "user_explanation_vi": "Cảnh sát giao thông không bao giờ gửi thông báo phạt nguội từ số điện thoại di động cá nhân."}, {"signal_code": "LEGAL_PENALTY_COERCION", "score_contribution": 40.00, "confidence_weight": 0.92, "user_explanation_vi": "Kẻ gian đang đe dọa nộp phạt pháp lý để lừa bạn chuyển tiền hoặc cài đặt ứng dụng độc hại."}]'::jsonb,
     '["normalized_text", "urls", "sender_type"]'::jsonb, 0.96, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000004', 'a1000000-0000-0000-0000-000000000004', 1,
     '{"operator": "AND", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["vneid", "dich vu cong", "cuc thue", "dinh danh muc 2", "cap nhat ho so", "bo cong an"]}, {"operator": "OR", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_MALICIOUS_APK_LINK"}, {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["cai dat ung dung", "tai file apk", "tro nang", "cai dat phan mem"]}]}]}'::jsonb,
     '[{"signal_code": "APK_DOWNLOAD_LINK", "score_contribution": 50.00, "confidence_weight": 0.98, "user_explanation_vi": "Đường link này chứa phần mềm độc hại có thể chiếm quyền điều khiển điện thoại!"}]'::jsonb,
     '["normalized_text"]'::jsonb, 0.98, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000005', 'a1000000-0000-0000-0000-000000000005', 1,
     '{"operator": "AND", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_RELATIVE_BORROW"}, {"operator": "OR", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["may bi hong", "mic hong", "tai nan", "vien phi", "doi so moi", "va quet xe"]}, {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["techcombank", "vietcombank", "mbbank", "so tai khoan", "stk", "ban ho"]}]}]}'::jsonb,
     '[{"signal_code": "RELATIVE_EMERGENCY_CLAIM", "score_contribution": 35.00, "confidence_weight": 0.85, "user_explanation_vi": "Tin nhắn xưng là người thân nhưng viện cớ khẩn cấp để vay tiền."}, {"signal_code": "URGENT_MONEY_TRANSFER_REQUEST", "score_contribution": 40.00, "confidence_weight": 0.88, "user_explanation_vi": "Yêu cầu chuyển tiền gấp vào tài khoản ngân hàng. Bạn hãy gọi điện thoại xác minh danh tính người nhận ngay!"}]'::jsonb,
     '["normalized_text"]'::jsonb, 0.88, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000006', 'a1000000-0000-0000-0000-000000000006', 1,
     '{"operator": "AND", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_TASK_JOB_OFFER"}, {"operator": "OR", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["telegram", "zalo", "ket ban qua so", "nhan thuong ngay", "shopee", "tiktok", "vin-trade", "bao hiem von"]}, {"operator": "CONTAINS_URL", "field": "urls", "value": true}]}]}'::jsonb,
     '[{"signal_code": "UNREALISTIC_EARNING_PROMISE", "score_contribution": 35.00, "confidence_weight": 0.90, "user_explanation_vi": "Hứa hẹn kiếm tiền dễ dàng tại nhà với thu nhập cao bất thường là chiêu trò lừa đảo."}, {"signal_code": "TASK_SCAM_KEYWORDS", "score_contribution": 30.00, "confidence_weight": 0.88, "user_explanation_vi": "Bẫy nạp tiền làm nhiệm vụ giật đơn hàng Shopee ảo."}]'::jsonb,
     '["normalized_text", "urls"]'::jsonb, 0.92, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000007', 'a1000000-0000-0000-0000-000000000007', 1,
     '{"operator": "AND", "conditions": [{"operator": "MATCHES_PATTERN", "field": "normalized_text", "pattern_code": "PAT_VN_RECOVERY_FEE"}, {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["thu hoi 100%", "an ninh mang", "van phong luat su", "phi giai toa", "phi ho so", "tien treo"]}]}'::jsonb,
     '[{"signal_code": "RECOVERY_SCAM_PROMISE", "score_contribution": 45.00, "confidence_weight": 0.95, "user_explanation_vi": "Không có cơ quan nào nhận lấy lại tiền bị lừa qua mạng mà yêu cầu nộp thêm phí."}, {"signal_code": "UPFRONT_FEE_DEMAND", "score_contribution": 45.00, "confidence_weight": 0.96, "user_explanation_vi": "Thủ đoạn mạo danh hỗ trợ thu hồi tiền treo để lừa đóng thêm phí giải ngân lần hai!"}]'::jsonb,
     '["normalized_text"]'::jsonb, 0.96, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000008', 'a1000000-0000-0000-0000-000000000008', 1,
     '{"operator": "AND", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["khong cung cap ma otp cho bat ky ai", "khong chia se ma otp", "khong chia se otp", "canh bao lua dao"]}, {"operator": "NOT", "condition": {"operator": "CONTAINS_URL", "field": "urls", "value": true}}]}'::jsonb,
     '[{"signal_code": "OFFICIAL_SECURITY_WARNING_PRESENT", "score_contribution": -40.00, "confidence_weight": 0.95, "user_explanation_vi": "Tin nhắn chứa câu cảnh báo bảo mật chính thống từ Ngân hàng."}]'::jsonb,
     '["normalized_text", "urls"]'::jsonb, 0.95, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),

    ('b1000000-0000-0000-0000-000000000009', 'a1000000-0000-0000-0000-000000000009', 1,
     '{"operator": "AND", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["vneid", "vne-id", "dinh danh dien tu", "dinh danh muc 2", "ung dung vneid"]}, {"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["so do", "so hong", "dat dai", "quyen su dung dat", "giay chung nhan", "thong tin dat dai", "so do nha dat"]}, {"operator": "OR", "conditions": [{"operator": "CONTAINS_ANY_KEYWORD", "field": "normalized_text", "keywords": ["cap nhat", "dong bo", "tich hop", "xac thuc", "dong phi", "nop phi", "phi xac minh", "phi dong bo", "cai dat", "link cap nhat"]}, {"operator": "CONTAINS_URL", "field": "urls", "value": true}]}, {"operator": "SENDER_MATCHES_CRITERIA", "field": "sender_type", "in": ["PHONE_DOMESTIC", "UNKNOWN", "INTERNATIONAL", "NUMERIC_SHORTCODE"]}]}'::jsonb,
     '[{"signal_code": "GOV_AUTHORITY_IMPERSONATION", "score_contribution": 45.00, "confidence_weight": 0.98, "user_explanation_vi": "Tin nhắn tự xưng cơ quan công an / cán bộ địa chính nhưng gửi từ số điện thoại lạ."}, {"signal_code": "VNEID_LAND_UPDATE_SCAM", "score_contribution": 50.00, "confidence_weight": 0.98, "user_explanation_vi": "Cảnh báo thủ đoạn lừa đảo nguy hiểm: Công an và cơ quan Nhà nước KHÔNG BAO GIỜ yêu cầu cập nhật sổ đỏ qua tin nhắn hoặc link lạ!"}]'::jsonb,
     '["normalized_text", "urls", "sender_type"]'::jsonb, 0.98, 'PUBLISHED', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Phát hành chính thức v1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 10. URL / DOMAIN INDICATORS (Danh sách tên miền phishing đã xác minh)
-- ----------------------------------------------------------------------------
INSERT INTO url_domain_indicator (id, source_id, indicator_type, raw_indicator, normalized_domain, spoofed_brand_id, reputation_status, risk_score, is_shortener, is_dynamic_ip, is_homoglyph, created_at)
VALUES
    ('41000000-0000-0000-0000-000000000001', '21000000-0000-0000-0000-000000000003', 'DOMAIN', 'http://vietcombank-smartotp.com/login', 'vietcombank-smartotp.com', '31000000-0000-0000-0000-000000000001', 'MALICIOUS', 95, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP),
    ('41000000-0000-0000-0000-000000000002', '21000000-0000-0000-0000-000000000003', 'DOMAIN', 'https://vcb-digibank-xacminh.top', 'vcb-digibank-xacminh.top', '31000000-0000-0000-0000-000000000001', 'MALICIOUS', 98, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP),
    ('41000000-0000-0000-0000-000000000003', '21000000-0000-0000-0000-000000000001', 'DOMAIN', 'http://phatnguoi-bocongan.top', 'phatnguoi-bocongan.top', '31000000-0000-0000-0000-000000000004', 'MALICIOUS', 98, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP),
    ('41000000-0000-0000-0000-000000000004', '21000000-0000-0000-0000-000000000002', 'DOMAIN', 'https://dichvucong-gov.online/vneid.apk', 'dichvucong-gov.online', '31000000-0000-0000-0000-000000000005', 'MALICIOUS', 99, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP),
    ('41000000-0000-0000-0000-000000000005', '21000000-0000-0000-0000-000000000002', 'DOMAIN', 'http://thuhoitientreo-bocongan.top', 'thuhoitientreo-bocongan.top', '31000000-0000-0000-0000-000000000004', 'MALICIOUS', 95, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 11. SENDER REPUTATION (Danh mục người gửi & hồ sơ cảnh báo)
-- ----------------------------------------------------------------------------
INSERT INTO sender_reputation (id, sender_raw, sender_hash, sender_type, claimed_brand_id, is_spoofed_brand, is_official_verified, community_reports_count, verified_scam_count, reputation_score, last_seen_at, created_at, updated_at)
VALUES
    ('51000000-0000-0000-0000-000000000001', 'Vietcombank', '6d7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f', 'BRANDNAME', '31000000-0000-0000-0000-000000000001', TRUE, FALSE, 48, 12, 10.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('51000000-0000-0000-0000-000000000002', '+84912345678', 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e', 'PHONE_DOMESTIC', '31000000-0000-0000-0000-000000000004', TRUE, FALSE, 26, 8, 15.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('51000000-0000-0000-0000-000000000003', '+84988776655', 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3', 'PHONE_DOMESTIC', '31000000-0000-0000-0000-000000000006', TRUE, FALSE, 42, 15, 14.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('51000000-0000-0000-0000-000000000004', 'VCB-Digibank', 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5', 'BRANDNAME', '31000000-0000-0000-0000-000000000001', FALSE, TRUE, 0, 0, 99.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('51000000-0000-0000-0000-000000000005', 'CucCSGT', 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6', 'BRANDNAME', '31000000-0000-0000-0000-000000000004', FALSE, TRUE, 0, 0, 98.00, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (sender_hash) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 12. SCORING POLICY VERSION (Chính sách chấm điểm phiên bản 2026.1)
-- ----------------------------------------------------------------------------
INSERT INTO scoring_policy_version (id, policy_code, version_number, threshold_high, threshold_low, min_confidence_for_high, max_score_cap, dedup_strategy_config, is_active, published_at, created_by)
VALUES
    ('b2000000-0000-0000-0000-000000000001', 'POL-2026.1', 1, 75.00, 30.00, 0.70, 100.00,
     '{"decay_factor": 0.5, "group_cap_enforced": true, "negative_evidence_discount_rate": 1.0}'::jsonb,
     TRUE, CURRENT_TIMESTAMP, '00000000-0000-0000-0000-000000000001')
ON CONFLICT (policy_code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 13. CLOUD HASH PREFIX INDEX (Tra cứu K-Anonymity 4-byte hash prefix)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cloud_hash_prefix_index (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hash_prefix_hex VARCHAR(8) NOT NULL,
    full_sha256 VARCHAR(64) NOT NULL,
    domain_or_url VARCHAR(512) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_full_sha256 UNIQUE (full_sha256)
);
CREATE INDEX IF NOT EXISTS idx_hash_prefix ON cloud_hash_prefix_index(hash_prefix_hex);

INSERT INTO cloud_hash_prefix_index (id, hash_prefix_hex, full_sha256, domain_or_url, threat_category, severity)
VALUES
    ('c1000000-0000-0000-0000-000000000001', '8f12a4b2', '8f12a4b209d84e27f9123847a98bcdef0123456789abcdef0123456789abcdef', 'vietcombank-smartotp.com', 'BANK_IMPERSONATION', 'CRITICAL'),
    ('c1000000-0000-0000-0000-000000000002', '3a9f1c7d', '3a9f1c7d1234567890abcdef1234567890abcdef1234567890abcdef12345678', 'vcb-digibank-xacminh.top', 'BANK_IMPERSONATION', 'CRITICAL'),
    ('c1000000-0000-0000-0000-000000000003', '9b2c8f41', '9b2c8f4100112233445566778899aabbccddeeff00112233445566778899aabb', 'phatnguoi-bocongan.top', 'GOV_IMPERSONATION', 'CRITICAL'),
    ('c1000000-0000-0000-0000-000000000004', 'e4d8a1c9', 'e4d8a1c9aabbccddeeff00112233445566778899aabbccddeeff001122334455', 'dichvucong-gov.online', 'GOV_IMPERSONATION', 'CRITICAL'),
    ('c1000000-0000-0000-0000-000000000005', '71a4f0b8', '71a4f0b811223344556677889900aabbccddeeff11223344556677889900aabb', 'thuhoitientreo-bocongan.top', 'RECOVERY_SCAM', 'CRITICAL')
ON CONFLICT (full_sha256) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 14. TELEMETRY SUBMISSION (Đã gộp telemetry_submission_batch & item)
-- Zero Raw Storage, K-Anonymity, Client Hash Only
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry_submission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anonymous_client_token VARCHAR(64) NOT NULL,
    submission_trigger VARCHAR(32) NOT NULL DEFAULT 'AUTO_HIGH_RISK',
    client_engine_version VARCHAR(32) NOT NULL,
    os_platform VARCHAR(16) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    sender_hash VARCHAR(64) NOT NULL,
    redacted_content TEXT NOT NULL,
    local_risk_level VARCHAR(32) NOT NULL,
    local_score NUMERIC(5,2) NOT NULL,
    primary_category VARCHAR(64),
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_telemetry_content_hash ON telemetry_submission(content_hash);
CREATE INDEX IF NOT EXISTS idx_telemetry_submitted_at ON telemetry_submission(submitted_at DESC);

INSERT INTO telemetry_submission (id, anonymous_client_token, submission_trigger, client_engine_version, os_platform, content_hash, sender_hash, redacted_content, local_risk_level, local_score, primary_category, submitted_at, created_at)
VALUES
    ('e1000000-0000-0000-0000-000000000001', 'anon_tok_7c9f28a1e3b54d60', 'AUTO_HIGH_RISK', 'v2026.1.0', 'IOS', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '6d7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f', 'VCB: Tai khoan tam khoa. Vui long truy cap vietcombank-smartotp.com de xac minh truoc khi bi khoa vinh vien.', 'HIGH', 95.00, 'BANK_IMPERSONATION', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

COMMIT;

-- ============================================================================
-- KẾT THÚC SEED DATA — ĐÃ NẠP TOÀN DIỆN THEO MÔ HÌNH HYBRID 8 THỰC THỂ CỐT LÕI
-- ============================================================================
