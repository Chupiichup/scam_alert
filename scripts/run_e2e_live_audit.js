/**
 * SCAMSHIELD E2E LIVE AUDIT RUNNER
 * Target Deployed App: https://scamalert-delta.vercel.app/
 *
 * Executes wide-coverage scam detection audit across 5 data collection streams (110 samples).
 * Strictly read-only against production. No changes to detection logic or schemas.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const APP_URL = 'https://scamalert-delta.vercel.app';
const DETECT_ENDPOINT = `${APP_URL}/api/v1/detect`;
const RUN_ID = 'RUN-20261029-E2E-AUDIT';
const ARTIFACTS_DIR = path.join(__dirname, '..', 'artifacts', 'scamalert-audit', RUN_ID);

fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });

function sha256(str) {
  return crypto.createHash('sha256').update(str || '').digest('hex');
}

function removeTones(str) {
  if (!str) return '';
  return str.normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd').replace(/Đ/g, 'D');
}

// ---------------------------------------------------------------------------
// 110 SAMPLES ACROSS 5 DATA STREAMS
// ---------------------------------------------------------------------------
const DATASET = [
  // =========================================================================
  // STREAM 1: REAL-WORLD SCAM SMS (Trích xuất từ 63 ảnh thực tế trong 'sms example/')
  // =========================================================================
  {
    sample_id: 'S1-EMP-001',
    source_id: 'SRC-IMG-001',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/1-12.png',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Cong ty nguoi nha anh co van de ve von luu dong, can tien de quay vong , anh khong tien dung ten minh truc tiep chuyen khoan. Dung tien mat di nop vao tai khoan nguoi than toi duoc khong?',
    language: 'vi-unaccented',
    scenario: 'PIG_BUTCHERING_MONEY_LAUNDERING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Screenshot tin nhắn nhờ nộp tiền mặt né tên cá nhân để rửa tiền lừa đảo.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '0912345678',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-002',
    source_id: 'SRC-IMG-002',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/10283d.png',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'THONG BAO Xin Chuc Mung Tai Khoan FACEBOOK Cua [Diep Ha] Da May Man Nhan Duoc Giai Nhat Tu Su Kien Tri An Khach Hang Tai Khoan FaceBook App Cua [Diep Ha] Mang Ma So Trung Thuong La 208A79 Da May Man Duoc He Thong Lua Chon Ngau Nhien, Xac Nhan La Tai Khoan Da Trung Thuong. Phan Qua Giai Nhat Cua Ban Gom: 01 Xe May HonDa SH 125i Viet Nam Tri Gia 81.000.000 VND 01 Phieu Qua Tang Tien Mat Tri Gia 200.000.000 VND 01 The Su Dung Xang Mien Phi 1 Nam Tri Gia 5.000.000 VND',
    language: 'vi-unaccented',
    scenario: 'LOTTERY_PRIZE_ADVANCE_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Chiêu trò trúng thưởng xe SH + 200 triệu từ sự kiện Tri ân Facebook.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Messengër',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-003',
    source_id: 'SRC-IMG-003',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/1634701415-5cf9ac3d0bcc3657266b6e3f1873fff2-width800height800.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-10-18',
    original_content: 'Xin chao, minh la giam doc marketing cua Shopee, hien tai cua hang Shopee can tuyen so luong lon nhan vien chuyen dat hang de nang cao so luong giao dich va thu hang cua cua hang. Chi can co kinh nghiem mua sam truc tuyen, moi ngay ban co the de dang kiem 800.000 dong bang dien thoai di dong va tien luong se duoc quyet toan ngay trong ngay. Neu ban muon tham gia cong viec nay vui long add tai khoan Zalo cua giam doc marketing: 84567233168. Hien tai chi con 30 suat duy nhat, chi trong ngay hom nay! (Luu y: yeu cau nguoi tham gia tu 22 tuoi tro len, hoc sinh sinh vien vui long khong tham gia)',
    language: 'vi-unaccented',
    scenario: 'TASK_JOB_SCAM',
    channel: 'IMESSAGE',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Giám đốc Marketing Shopee tuyển CTV đặt đơn ảo 800k/ngày kéo sang Zalo.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'c7ydtgou5y987i3l@hotmail.com.tw',
    sender_type: 'EMAIL_IMESSAGE'
  },
  {
    sample_id: 'S1-EMP-004',
    source_id: 'SRC-IMG-004',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/1690824459-tin-nhan-lua-dao-tri-an-khach-hang-3309-width850height945.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-08-01',
    original_content: 'Em chao chi,em la nhan vien CSKH Gumac a . Da thay mat toan the nhan vien Hang Thoi Trang GUMAC em xin cam on chi da tin tuong va chon dien cung thoi trang ben em a ! Da chi da nhan duoc cuoc goi tu nhan vien nha Gu roi dung khong a ? Da nha Gu dang co sieu su kien sinh nhat 8 nam tuoi tri an cam on khach hang . Kinh gui chi yeu cung 500 khach hang ngau nhien khac . Tang chi 2 set trang phuc CONG SO HANH PHUC cung nhieu cac phan qua khac gianh den chi yeu a . Vi so luong khach hang nhan qua ben em kha nhieu . Yeu cau tat ca khach hang can co ung dung TELEGRAM Messenger de duoc nhan 2 mau tuy chon trong 250 mau tu he thong GUMAC gui xuong a. Ma nhan qua cua chi la : GU1523 Chi yeu vui long bam vao link: https://t.me/triangumac_vn2023 va nhan tin Chuc mung sinh nhat GUMAC roi nhan qua a',
    language: 'vi-unaccented',
    scenario: 'GIFT_BAIT_TELEGRAM_TRAP',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Tặng quà tri ân Gumac dẫn link Telegram t.me làm bẫy nạp tiền.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Gumac',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-005',
    source_id: 'SRC-IMG-005',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/1816 (27).jpg',
    collected_at: '2026-10-25',
    published_at: '2026-06-15',
    original_content: 'Thong bao: Mang Xa Hoi-BeeTalk Xin Chao Quy Khach Den Voi He Thong BeeTalk Chuc Mung So Thue Bao Dang Ki BeeTalk Cua Ban Nhan Duoc Giai Nhat Cua Chuong Trinh Trong Vong Quay Dac Biet-Tri An Khach Hang Mang Ma So Du Thuong La 402E7E Cua He Thong. Truy Cap He Thong Http://giaithuong.us De Lam Thu Tuc Nhan Giai. Chi Tiet Lien He Mr.Vu Voi HotLine : ( 0084 962 112 642 ) He Thong BeeTalk Xin Chuc Mung Ban',
    language: 'vi-unaccented',
    scenario: 'LOTTERY_PRIZE_ADVANCE_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'BeeTalk trúng thưởng vòng quay tri ân link http://giaithuong.us.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'BeeTalk',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-006',
    source_id: 'SRC-IMG-006',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/2-1784618774-4281-1784618949.webp',
    collected_at: '2026-10-25',
    published_at: '2026-07-10',
    original_content: 'Thong bao: Phuong tien cua ban co vi pham giao thong. Vui long truy cap https://csgt.bocongan.web.id/vn/ de tra cuu va nop phat.',
    language: 'vi-unaccented',
    scenario: 'POLICE_TRAFFIC_FINE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Phạt nguội giao thông gửi từ số di động rác kèm tên miền giả .web.id.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '+84903824107',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-008',
    source_id: 'SRC-IMG-008',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/3259639144895752366851571287114594544805498n-1674359750707928698372.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-01-15',
    original_content: 'Bia Sai Gon 2023 Qua Tet Nguyen Dan http://m.2ffzarr.cn/a07acVkGX2h8Qn9DCF9yFDMmZX4QbhRoTSFTAXgeMy4MCzMYaRUkLV3aCAU7agFWRRMvMQcLDCEFgxVYxZRIzA&p=vzpnms1674308582284',
    language: 'vi-accented',
    scenario: 'GIFT_BAIT_MALICIOUS_LINK',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Bia Sài Gòn quà Tết link độc hại tên miền Trung Quốc đuôi .cn.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Unknown',
    sender_type: 'UNKNOWN'
  },
  {
    sample_id: 'S1-EMP-009',
    source_id: 'SRC-IMG-009',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/3d4474ad02e6ebb8b2f7.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-05-12',
    original_content: 'Thong bao : Quy khach con mot khoan phat giao thong chua duoc thanh toan. Vui long thanh toan som de tranh cac khoan phi phat phat sinh : dichvuconggov-vn.com',
    language: 'vi-unaccented',
    scenario: 'POLICE_TRAFFIC_FINE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Phạt giao thông dọa phát sinh phí phạt link dichvuconggov-vn.com.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '0901239988',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-010A',
    source_id: 'SRC-IMG-010',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/566552529_25249869821309305_6447884069765756460_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-06-20',
    original_content: 'ACB: Tai khoan cua ban da mo dich vu tai chinh toan cau phi dich vu hang thang la 2.000.000VND se bi tru trong 2 gio .Neu khong phai ban mo dich vu vui long nhan vao https://acb-online-center.com de huy',
    language: 'vi-unaccented',
    scenario: 'BANK_UNSOLICITED_FEE_BAIT',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Brandname ACB dọa trừ phí 2 triệu sau 2 giờ, link lừa đảo acb-online-center.com.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'ACB',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-010B',
    source_id: 'SRC-IMG-010',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/566552529_25249869821309305_6447884069765756460_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-06-20',
    original_content: 'Vietinbank tran trong thong bao, tai khoan cua quy khach hien tai da bi khoa. Dang nhap http://www.vniatinbanks.cc de xac thuc ngay hom nay',
    language: 'vi-unaccented',
    scenario: 'BANK_ACCOUNT_SUSPENSION_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Vietinbank khóa tài khoản, link typosquatting vniatinbanks.cc.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'VietinBank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-011',
    source_id: 'SRC-IMG-011',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/616-251e5108b53342f397f5cf62e96a7093.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-04-18',
    original_content: 'Ban chua nhan du0c tr0 cap COVID-19, vui long nhap>> tinyurl.com/kxytdc8z de lay, qua han se kh0ng duoc chap nhan!',
    language: 'vi-teencode',
    scenario: 'COVID_RELIEF_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Trợ cấp Covid-19 viết teencode thay số 0 (du0c, tr0 cap, kh0ng), link tinyurl.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Unknown',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-012',
    source_id: 'SRC-IMG-012',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/68932b2d19db7c63259f4358.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-03-25',
    original_content: 'Canh sat Giao thong Viet Nam: Hien tai, ban dang co mot khoan tien phat chua thanh toan trong tai khoan. Vui long thanh toan khoan phi nay cang som cang tot de tranh nhung bat tien khong dang co. De biet them thong tin, vui long truy cap: https://dichvucongg.top/vn',
    language: 'vi-accented',
    scenario: 'POLICE_TRAFFIC_FINE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh CSGT Việt Nam đòi tiền phạt truy cập https://dichvucongg.top/vn.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '18001096',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-013',
    source_id: 'SRC-IMG-013',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/706675990_1008170785117251_1254167812091218100_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-08-11',
    original_content: 'Tai khoan cua ban da dang ky chuong trinh quang cao tren TikTok, moi thang thu phi 3,250,000 VND. Vui long vao https://msb.vn-cvs.xyz de kiem tra hoac de huy',
    language: 'vi-unaccented',
    scenario: 'TIKTOK_ADS_FEE_BAIT',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh MSB thu phí quảng cáo TikTok 3.25tr/tháng link msb.vn-cvs.xyz.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'MSB',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-015',
    source_id: 'SRC-IMG-015',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/77286872610811009079513108238452154842505598npng-1787008540311-17870085405362077229538.webp',
    collected_at: '2026-10-25',
    published_at: '2026-08-06',
    original_content: '[TTDLQG - Bo Cong an] Thong bao yeu cau nop phat vi pham dung thoi han Phuong tien cua Quy khach bi ghi nhan vi pham tin hieu den giao thong ngay 06/08/2026, hien chua hoan thanh nghia vu nop phat. Trong vong 48 gio toi neu khong xu ly, muc phat se tang them 50% va Cuc Canh sat giao thong se tam giu giay to xe. Vui long xem thong tin chi tiet va thanh toan khoan phat tai lien ket: https://902577.cc/dichvucong.gov/vn Tra loi 1 hoac Y de nhan link kich hoat thay the',
    language: 'vi-accented',
    scenario: 'POLICE_TRAFFIC_FINE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh TTDLQG BCA dọa tăng 50% phạt sau 48h gửi từ đầu số Ma-rốc +212 link .cc.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '+212649020639',
    sender_type: 'PHONE_INTERNATIONAL'
  },
  {
    sample_id: 'S1-EMP-016',
    source_id: 'SRC-IMG-016',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/834462737_967694235960876_2354436322647638760_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-07-22',
    original_content: 'Phat hien tai khoan cua ban dang nhap khac vung bat thuong ,vui long dang nhap https://vn-sacombank.com de xac nhan thong tin va thay doi mat khau',
    language: 'vi-unaccented',
    scenario: 'BANK_SUSPICIOUS_LOGIN_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Sacombank đăng nhập khác vùng bất thường link vn-sacombank.com.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Sacombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-017',
    source_id: 'SRC-IMG-017',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/835059818_1813424089849314_4392999658187224934_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-07-22',
    original_content: 'Tai khoan cua ban dang duoc dang nhap tren thiet bi khac ,neu khong phai ban dang nhap vui long vao https://vietcombank.vn-gss.club de sua doi mat khau hoac thoat khoi thiet bi kia',
    language: 'vi-unaccented',
    scenario: 'BANK_SUSPICIOUS_LOGIN_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Vietcombank đăng nhập thiết bị khác link lừa đảo .club.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Vietcombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-019',
    source_id: 'SRC-IMG-019',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/838362505_2643009526153414_646519637807011020_n.png',
    collected_at: '2026-10-25',
    published_at: '2026-08-01',
    original_content: 'Em la sinh vien dang tin them viec ban thoi gian. Neu nhu anh co nhu cau tinh duc co the lien he Telegram cua em a : https://t.me/okGuO',
    language: 'vi-unaccented',
    scenario: 'SEXUAL_SOLICITATION_EXTORTION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Spam mại dâm sinh viên dẫn dụ sang Telegram tống tiền.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '+84988776655',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S1-EMP-021',
    source_id: 'SRC-IMG-021',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/bbb-1487735203.jpg',
    collected_at: '2026-10-25',
    published_at: '2026-02-14',
    original_content: 'TAI Khoan Zalo cua ban la khach hang may man trung thuong. GIAI NHAT GOM: 1 CHIEC XE MAY SH150I + 200 TRIEU DONG TIEN MAT. GIAI thuong do tap doan mang xa hoi Zalo & Honda VIET NAM DONG HANH TAI TRO. Ma so cua ban la: •KH68ZL79• SU KIEN nham GUI LOI TRI AN KHACH HANG DA TIN TUONG SU DUNG DICH VU Zalo. Bam vao LINK: https://plus.google.com/114908180224783665698/posts/hTum48KFMCX Lam thu tuc nhan thuong.',
    language: 'vi-accented',
    scenario: 'LOTTERY_PRIZE_ADVANCE_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Zalo tri ân trúng xe SH150i + 200 triệu bắt bấm link làm thủ tục nhận thưởng.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'Zalo',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-023',
    source_id: 'SRC-IMG-023',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/canhbaonh5.jpeg',
    collected_at: '2026-10-25',
    published_at: '2026-05-18',
    original_content: 'Chung toi phat hien tai khoan cua ban dang tieu dung o nuoc ngoai .Neu khong phai ban dang tieu dung vui long nhap vao https://v-acb.com de huy thanh toan',
    language: 'vi-unaccented',
    scenario: 'BANK_OVERSEAS_SPENDING_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh ACB tiêu dùng nước ngoài bấm https://v-acb.com hủy thanh toán.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'ACB',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-024',
    source_id: 'SRC-IMG-024',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/gia-mao-ngan-hang-1-1680623788664.webp',
    collected_at: '2026-10-25',
    published_at: '2026-04-05',
    original_content: 'UNG DUNG VCB DIGIBANK cua ban duoc PHAT HIEN KICH HOAT tren thiet bi la .Neu KHONG PHAI BAN KICH HOAT vui long bam vao https://vietcombank.vn-ms.top de doi thiet bi hoac huy de tranh mat tai san',
    language: 'vi-unaccented',
    scenario: 'BANK_SUSPICIOUS_LOGIN_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'VCB Digibank kích hoạt thiết bị lạ link giả mạo vietcombank.vn-ms.top.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'VCB DIGIBANK',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-026',
    source_id: 'SRC-IMG-026',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/image_203.png',
    collected_at: '2026-10-25',
    published_at: '2026-09-02',
    original_content: 'Chinh phu tang ban 100.000 dong nhan dip 2/9, hay dang ky nhan qua duong link: http://1234.xyz',
    language: 'vi-accented',
    scenario: 'GOV_GIFT_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Chính phủ tặng tiền dịp 2/9 link http://1234.xyz.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: 'QUA-TET',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S1-EMP-049',
    source_id: 'SRC-IMG-049',
    source_type: 'REAL_SMS_SCREENSHOT',
    source_url: 'sms example/vietstock_s_cong-an-chi-cach-nhan-dien-link-lua-dao-qua-tin-nhan-sms_20220609061022.png',
    collected_at: '2026-10-25',
    published_at: '2026-06-09',
    original_content: 'Phat hien tai khoan cua ban dang n\'hap khac vung bat thuong ,vui l0ng www.smartbiddv.com de xac nhan thaong tin va thay doi mat k\'hau',
    language: 'vi-teencode',
    scenario: 'BANK_SUSPICIOUS_LOGIN_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'BIDV đăng nhập khác vùng chèn ký tự né tránh (n\'hap, l0ng, mat k\'hau) link www.smartbiddv.com.',
    collection_method: 'MANUAL_OCR_EXTRACTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '0908877665',
    sender_type: 'PHONE_DOMESTIC'
  },

  // =========================================================================
  // STREAM 2: OFFICIAL WARNINGS & AUTHORITY CASES (BCA, C08, NCSC, EVN, BANKS)
  // =========================================================================
  {
    sample_id: 'S2-AUTH-001',
    source_id: 'SRC-BNK-001',
    source_type: 'OFFICIAL_BANK_WARNING',
    source_url: 'https://vietcombank.com.vn/canh-bao-lua-dao',
    collected_at: '2026-10-25',
    published_at: '2026-07-01',
    original_content: 'Vietcombank tran trong thong bao: Tai khoan cua Quy khach tam thoi bi khoa do nghi van giao dich bat thuong. Vui long dang nhap tai http://vietcombank-smartotp.com de xac minh va nhap ma OTP truoc 24h.',
    language: 'vi-unaccented',
    scenario: 'BANK_ACCOUNT_SUSPENSION_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cảnh báo chính thức từ Vietcombank về thủ đoạn mạo danh khóa thẻ ép nhập OTP.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'Vietcombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S2-AUTH-002',
    source_id: 'SRC-BNK-001',
    source_type: 'OFFICIAL_BANK_WARNING',
    source_url: 'https://vietcombank.com.vn/canh-bao-lua-dao',
    collected_at: '2026-10-25',
    published_at: '2026-07-01',
    original_content: 'Ngan hang thong bao: Quy khach chua hoan tat xac thuc sinh trac hoc theo Quy dinh 2345. Tai khoan se bi dung chuyen tien tu 0h. Cap nhat ngay tai: https://vcb-sinhtrachoc.top',
    language: 'vi-unaccented',
    scenario: 'BIOMETRIC_UPDATE_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Chiêu trò sinh trắc học QĐ 2345 dừng chuyển tiền link .top.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84912349988',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-003',
    source_id: 'SRC-GOV-001',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'http://csgt.vn/canh-bao-tin-nhan-phat-nguoi-gia-mao',
    collected_at: '2026-10-25',
    published_at: '2026-05-10',
    original_content: 'Cuc Canh sat giao thong thong bao: Phuong tien BKS 29A-88899 vi pham loi vuot den do chua xu ly. Yeu cau truy cap http://phatnguoi-bocongan.top de nop phat trong 48h truoc khi tang muc phat 50%.',
    language: 'vi-unaccented',
    scenario: 'POLICE_TRAFFIC_FINE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cục CSGT khẳng định không gửi phạt nguội qua SMS kèm link.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84912345678',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-004',
    source_id: 'SRC-GOV-002',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://ncsc.gov.vn/canh-bao-ma-doc-vneid',
    collected_at: '2026-10-25',
    published_at: '2026-06-12',
    original_content: 'Thong bao tu Bo Cong an: Ho so dinh danh VNeID cua ong ba bi loi muc 2. Vui long tai ban cap nhat tai https://dichvucong-gov.online/vneid.apk de cai dat phan mem xac thuc.',
    language: 'vi-unaccented',
    scenario: 'MALICIOUS_APK_VNEID',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cảnh báo NCSC về bẫy cài mã độc APK chiếm quyền Accessibility.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84889922114',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-005',
    source_id: 'SRC-GOV-001',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://cand.com.vn/phap-luat/thu-doan-gia-danh-vien-kiem-sat-lua-dao-tien-ty',
    collected_at: '2026-10-25',
    published_at: '2026-04-10',
    original_content: 'Lenh bat tam giam tu Vien Kiem sat: Ong co lien quan du an ma tuy rua tien. Yeu cau chuyen toan bo tien vao tai khoan tam giu cua can bo trong 24h de dieu tra.',
    language: 'vi-unaccented',
    scenario: 'PROSECUTOR_ARREST_COERCION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Dọa lệnh bắt giam rửa tiền ép chuyển vào tài khoản tạm giữ cán bộ.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84903344556',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-006',
    source_id: 'SRC-GOV-003',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://bocongan.gov.vn/canh-bao-lua-dao-lay-lai-tien-treo',
    collected_at: '2026-10-25',
    published_at: '2026-05-30',
    original_content: 'Van phong Luat su ho tro nan nhan bi lua dao tren mang: Ho so cua ban da duoc Bo Cong an thu ly thu hoi 100% tien treo. Vui long dong phi giai toa 10% de duoc hoan tien ngay.',
    language: 'vi-unaccented',
    scenario: 'RECOVERY_FRAUD_UPFRONT_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Chiêu trò lấy lại tiền treo đóng phí giải tỏa 10%.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84771239988',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-007',
    source_id: 'SRC-GOV-003',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://bocongan.gov.vn/canh-bao-lua-dao-lay-lai-tien-treo',
    collected_at: '2026-10-25',
    published_at: '2026-05-30',
    original_content: 'Cuc An ninh mang cam ket thu hoi 100% tien treo cho cac nan nhan bi lua dao online. Nhanh tay lien he Zalo can bo truc ban de duoc giai quyet ho so va dong phi ho so.',
    language: 'vi-unaccented',
    scenario: 'RECOVERY_FRAUD_UPFRONT_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Cục An ninh mạng thu hồi tiền treo đòi đóng phí hồ sơ qua Zalo.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84912003322',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-008',
    source_id: 'SRC-GOV-002',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://dantri.com.vn/phap-luat/chieu-tro-cap-nhat-so-do-tren-vneid',
    collected_at: '2026-10-25',
    published_at: '2026-08-15',
    original_content: 'Canh bao tu Can bo dia chinh: Thong tin so do nha dat cua ban tren VNeID bi sai lech. Yeu cau truy cap https://dichvucong-datdai.com/vneid-sodo.apk de cap nhat va tich hop vao ung dung VNeID muc 2.',
    language: 'vi-unaccented',
    scenario: 'VNEID_LAND_UPDATE_MALWARE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cán bộ địa chính dọa sổ đỏ sai lệch tải app APK cài mã độc.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84912384729',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S2-AUTH-009',
    source_id: 'SRC-GOV-002',
    source_type: 'OFFICIAL_POLICE_WARNING',
    source_url: 'https://dantri.com.vn/phap-luat/chieu-tro-cap-nhat-so-do-tren-vneid',
    collected_at: '2026-10-25',
    published_at: '2026-08-15',
    original_content: 'Can bo Cong an thong bao: So do dat dai cua gia dinh chua dong bo tren VNeID muc 2. Yeu cau chuyen khoan phi xac minh dong bo du lieu 200.000d de hoan tat thu tuc.',
    language: 'vi-unaccented',
    scenario: 'VNEID_LAND_UPDATE_FEE',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cán bộ công an yêu cầu chuyển khoản 200.000đ phí xác minh sổ đỏ trên VNeID.',
    collection_method: 'OFFICIAL_REPORT_INGESTION',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84908123456',
    sender_type: 'PHONE_DOMESTIC'
  },

  // =========================================================================
  // STREAM 3: PUBLIC REPUTABLE MEDIA & EXPANSION SCENARIOS (17 KỊCH BẢN MỚI)
  // =========================================================================
  {
    sample_id: 'S3-EXP-001',
    source_id: 'SRC-EVN-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://tuoitre.vn/mao-danh-dien-luc-doa-cat-dien-sau-2-gio-de-lua-dao-20240415.htm',
    collected_at: '2026-10-28',
    published_at: '2026-04-15',
    original_content: '[EVN] Thong bao: Quy khach con no tien dien thang nay chua thanh toan. Cong ty Dien luc se tien hanh ngat dien sau 17h hom nay. Vui long truy cap https://evn-cskh.top de thanh toan ngay.',
    language: 'vi-unaccented',
    scenario: 'UTILITY_EVN_CUTOFF_THREAT',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'EVN cảnh báo mạo danh dọa cắt điện sau 17h ép bấm link độc hại .top.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84903112233',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-002',
    source_id: 'SRC-MIC-SIM-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vnexpress.net/cuc-vien-thong-canh-bao-tin-nhan-khoa-sim-chuan-hoa-4720192.html',
    collected_at: '2026-10-28',
    published_at: '2026-03-20',
    original_content: '[CUC VIEN THONG] Thong bao: So thue bao cua quy khach chua chuan hoa thong tin ca nhan theo Nghi dinh 49. So dien thoai se bi khoa 2 chieu sau 2 gio toi. Cap nhat ngay tai: https://chuanhoathuebao-vnta.top',
    language: 'vi-unaccented',
    scenario: 'TELECOM_SIM_LOCKOUT_DECREE49',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cục Viễn thông cảnh báo bẫy dọa khóa SIM 2 chiều sau 2h theo NĐ 49.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84913009988',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-003',
    source_id: 'SRC-BHXH-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://baohiemxahoi.gov.vn/tintuc/canh-bao-lua-dao-tro-cap-bhxh',
    collected_at: '2026-10-28',
    published_at: '2026-05-14',
    original_content: '(BHXH-VN) Ho so huong tro cap thai san cua ban da duoc phe duyet voi so tien 12.800.000d. Vui long truy cap https://m-bhxh.top de xac nhan tai khoan ngan hang nhan tien.',
    language: 'vi-unaccented',
    scenario: 'SOCIAL_WELFARE_BHXH_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'BHXH Việt Nam cảnh báo bẫy nhận tiền thai sản qua link m-bhxh.top.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84938112299',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-004',
    source_id: 'SRC-MED-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://tuoitre.vn/lua-dao-con-dang-cap-cuu-tai-benh-vien-cho-ray-20230306123456.htm',
    collected_at: '2026-10-28',
    published_at: '2026-03-06',
    original_content: 'Toi la Bac si Nguyen Van Hung, Truong khoa Cap cuu Benh vien Cho Ray. Con anh/chi la chau Nguyen Minh Tri bi nga cau thang truong hoc chan thuong so nao rat nang, hien dang hon me tren ban mo can mo gap. Gia dinh chuyen ngay 50 trieu tam ung vien phi vao STK 1903889922 Techcombank Nguyen Van Hung de tien hanh phau thuat cuu chau!',
    language: 'vi-unaccented',
    scenario: 'HOSPITAL_EMERGENCY_EXTORTION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Án điểm lừa đảo tàn nhẫn: Bác sĩ Chợ Rẫy mạo danh báo con cấp cứu mổ sọ não.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84908123888',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-005',
    source_id: 'SRC-LOAN-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://cand.com.vn/thi-truong/bay-vay-tien-online-duyet-nhanh-tien-mat-tat-mang',
    collected_at: '2026-10-28',
    published_at: '2026-06-25',
    original_content: 'Chuc mung SDT 0912xxx da duoc duyet khoan vay tieu dung 50.000.000d - 200.000.000d lai suat uu dai 0.5%/thang. Giai ngan trong 15 phut khong can the chap, no xau van vay duoc. Nhan tien tai: https://vayonline-fast.vip',
    language: 'vi-unaccented',
    scenario: 'LOAN_UPFRONT_FEE_SCAM',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Bẫy duyệt vay nóng giải ngân 15 phút không thế chấp lừa nộp phí trước.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84776655443',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-006',
    source_id: 'SRC-AIR-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://laodong.vn/xa-hoi/canh-giac-chieu-lua-hoan-ve-may-bay-dip-tet',
    collected_at: '2026-10-28',
    published_at: '2026-01-20',
    original_content: '[VietnamAirlines] Thong bao: Chuyen bay VN214 ngay 28 Tet bi thay doi gio bay va huy lich trinh. Hang tien hanh boi thuong 1.500.000d cho moi hanh khach. Vui long nhap ma dat cho tai https://vietnamairlines-ticket.cc de nhan boi thuong.',
    language: 'vi-unaccented',
    scenario: 'AIRLINE_TICKET_REFUND_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Vietnam Airlines hoàn tiền hủy vé Tết link độc hại .cc.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84919887766',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-007',
    source_id: 'SRC-VOTE-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vietnamnet.vn/bay-binh-chon-cuoc-thi-anh-mat-nick-facebook',
    collected_at: '2026-10-28',
    published_at: '2026-07-18',
    original_content: 'Chi oi, chau nha em dang thi vong chung ket cuoc thi Nu Cuoi Thien Than, chi vao link nay vote giup chau 1 phieu voi a, ma SBD cua chau la 24 nhe: https://binhchon-nhi2026.site Em cam on chi nhieu lam!',
    language: 'vi-unaccented',
    scenario: 'PHOTO_CONTEST_CREDENTIAL_THEFT',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Nhờ bình chọn thi ảnh nụ cười thiên thần dụ nhập tài khoản MXH chiếm quyền.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84982334455',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-008',
    source_id: 'SRC-DEEP-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vnexpress.net/tong-tien-bang-clip-cat-ghep-deepfake-4759281.html',
    collected_at: '2026-10-28',
    published_at: '2026-08-05',
    original_content: 'Toi dang giu clip nong nhay cam giuong chieu cua anh. Khuon mat trong clip rat ro rang. Neu trong 24h toi khong chuyen 30 trieu vao STK 0918273645 MBBank Nguyen Van Nam thi toan bo clip nay se duoc gui cho co quan, dong nghiep va vo anh xem!',
    language: 'vi-unaccented',
    scenario: 'AI_DEEPFAKE_EXTORTION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Dọa phát tán clip Deepfake giường chiếu tống tiền 30 triệu.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84903998877',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-009',
    source_id: 'SRC-CHARITY-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vtv.vn/xa-hoi/canh-bao-so-tai-khoan-gia-mao-cuu-tro-bao-yagi-20240912.htm',
    collected_at: '2026-10-28',
    published_at: '2026-09-12',
    original_content: '[MAT TRAN TO QUOC VN] Kieu goi toan the dong bao chung tay ung ho cuu tro dong bao mien Bac chiu thiet hai do sieu bao Yagi lu lut. Moi dong gop xin chuyen ve STK Ban cuu tro: 1902837465 Techcombank - Chu TK: Nguyen Van Tu (Thu quy Ban cuu tro). Noi dung: UNG HO BAO YAGI.',
    language: 'vi-unaccented',
    scenario: 'CHARITY_DISASTER_IMPERSONATION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh MTTQ kêu gọi cứu trợ bão lũ chuyển tiền vào STK cá nhân.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84912883344',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-010',
    source_id: 'SRC-RENT-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://kenh14.vn/canh-bao-bay-dat-coc-phong-tro-sinh-vien-mua-nhap-hoc',
    collected_at: '2026-10-28',
    published_at: '2026-08-28',
    original_content: 'Em oi phong tro 2tr5 full do o Cau Giay dang co 3 ban den xem doi thue roi. Em muon lay thi chuyen coc giu phong 1 trieu vao STK 1903456789 Techcombank Pham Van Lam chu nha nhe, chuyen xong chup bien lai chi giu phong cho, den xem khong ung chi hoan coc 100% nhe.',
    language: 'vi-unaccented',
    scenario: 'RENTAL_DEPOSIT_TRAP',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Bẫy cọc phòng trọ sinh viên giá rẻ rồi chặn liên lạc.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84976112233',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-011',
    source_id: 'SRC-COD-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vtv.vn/phap-luat/chieu-tro-giao-hang-cod-khong-nguoi-gia-sap-bay-20240310.htm',
    collected_at: '2026-10-28',
    published_at: '2026-03-10',
    original_content: 'Chi oi em shipper GHTK day a, chi co don hang 120k COD ma em goi chi khong duoc. Em nho bac gai o nha nhan ho roi chi chuyen khoan 120k tien ship giup em vao STK 0918273645 MBBank Nguyen Van Nam nhe.',
    language: 'vi-unaccented',
    scenario: 'FAKE_DELIVERY_COD_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Giao hàng COD khống 120k lợi dụng người nhà nhận hộ.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84903112288',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-012',
    source_id: 'SRC-VR-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://cand.com.vn/phap-luat/canh-bao-app-gia-mao-cuc-dang-kiem-lua-dao',
    collected_at: '2026-10-28',
    published_at: '2026-05-18',
    original_content: '[CUC DANG KIEM VN] Canh bao: Phuong tien BKS 30F-92817 het han kiem dinh an toan ky thuat tu ngay 15/10/2026. Vui long truy cap https://app-dangkiem.top de gia han tu dong va nop phi cap tem kiem dinh dien tu.',
    language: 'vi-unaccented',
    scenario: 'VEHICLE_REGISTRATION_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mạo danh Cục Đăng kiểm nộp phí gia hạn tem kiểm định qua link lừa đảo.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84918223399',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-013',
    source_id: 'SRC-REF-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://dantri.com.vn/suc-manh-so/gia-cskh-shopee-hoan-tien-don-that-lac-20240402.htm',
    collected_at: '2026-10-28',
    published_at: '2026-04-02',
    original_content: '[Shopee Mall] Thong bao: Don hang #SHP982173 cua ban bi that lac trong qua trinh van chuyen. He thong tien hanh boi thuong hoan tra 350.000d vao tai khoan. Vui long truy cap https://shopee-hoantien.top de nhan tien ngay.',
    language: 'vi-unaccented',
    scenario: 'ECOMMERCE_REFUND_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Giả CSKH Shopee hoàn tiền hàng thất lạc để dẫn link chiếm OTP.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84918223311',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-014',
    source_id: 'SRC-SHARK-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://thanhnien.vn/bay-chuyen-nham-tien-ep-vay-nang-lai-18524050212.htm',
    collected_at: '2026-10-28',
    published_at: '2026-05-02',
    original_content: 'Em chao chi, em la sinh vien di lam them lo tay chuyen nham 5.000.000d vao STK cua chi luc nay. Chi lam phuoc chuyen tra lai vao STK khac nay cua em voi a: 1903847261 MBBank Chu TK Tran Van Tuan. Em xin cam on chi!',
    language: 'vi-unaccented',
    scenario: 'LOAN_SHARK_ACCIDENTAL_TRANSFER',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cố tình chuyển nhầm tiền để ép chuyển sang tài khoản khác hoặc siết nợ vay lãi.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84918334455',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-015',
    source_id: 'SRC-EXP-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://vtv.vn/xa-hoi/canh-bao-bay-di-lao-dong-thoi-vu-han-quoc-20240218.htm',
    collected_at: '2026-10-28',
    published_at: '2026-02-18',
    original_content: 'Thong bao tuyen lao dong thoi vu nong nghiep Han Quoc (Visa E-8) nam 2026: Luong 45tr - 55tr/thang, khong can tieng, khong phai thi tuyen, bay ngay thang sau. Nhanh tay add Zalo 0918273645 nop ho so va dong coc 5 trieu giu chi tieu.',
    language: 'vi-unaccented',
    scenario: 'OVERSEAS_LABOR_EXPORT_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Tuyển lao động thời vụ Hàn Quốc lương 45tr không cần tiếng lừa cọc 5 triệu.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84918273645',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-016',
    source_id: 'SRC-BNK-002',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://nhipsongkinhte.toquoc.vn/thu-doan-nhan-kieu-hoi-ngoai-te-danh-cap-otp-20240110.htm',
    collected_at: '2026-10-28',
    published_at: '2026-01-10',
    original_content: '[WesternUnion] Thong bao: Quy khach vua nhan duoc mon tien kieu hoi 850.00 USD tu kiem bao tai Hoa Ky (Ma MTCN: 928-172-8491). Vui long dang nhap lien ket https://westernunion-vietnam.top de quy doi sang VND va nhan tien ve tai khoan.',
    language: 'vi-unaccented',
    scenario: 'REMITTANCE_OVERSEAS_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Mồi nhử nhận 850 USD Western Union link westernunion-vietnam.top.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84919223344',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S3-EXP-017',
    source_id: 'SRC-BHXH-001',
    source_type: 'PUBLIC_INVESTIGATION',
    source_url: 'https://baohiemxahoi.gov.vn/tintuc/canh-bao-tin-nhan-khoa-the-bhyt',
    collected_at: '2026-10-28',
    published_at: '2026-06-18',
    original_content: '[BHYT-VN] Canh bao: Thong tin the Bao hiem Y te cua quy khach bi sai lech thong tin CCCD. Quyen loi kham chua benh BHYT se bi tam khoa tu 0h ngay mai. Vui long cap nhat lai thong tin tai: https://bhyt-capnhat.top de khong bi gian doan chi tra vien phi.',
    language: 'vi-unaccented',
    scenario: 'HEALTH_INSURANCE_SUSPENSION_FRAUD',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Dọa khóa thẻ BHYT cắt quyền lợi viện phí link bhyt-capnhat.top.',
    collection_method: 'CURATED_CASE_SYNTHESIS',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: '+84918223366',
    sender_type: 'PHONE_DOMESTIC'
  },

  // =========================================================================
  // STREAM 4: LEGITIMATE & CONTROL BENIGN SAMPLES (HỢP LỆ ĐỐI CHỨNG)
  // =========================================================================
  {
    sample_id: 'S4-BEN-001',
    source_id: 'SRC-BNK-001',
    source_type: 'BENIGN_BANK_TRANSACTION',
    source_url: 'Vietcombank Official SMS',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'VCB: So du TK 0011002345678 thay doi +5,000,000 VND luc 10:15. Noi dung: Luong thang 10. Khong cung cap ma OTP cho bat ky ai duoi moi hinh thuc de bao ve tai khoan.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_SALARY_NOTIFICATION',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Biến động số dư chính thức của Vietcombank, có cảnh báo bảo mật chính quy.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'VCB-Digibank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-002',
    source_id: 'SRC-BNK-001',
    source_type: 'BENIGN_AUTHENTIC_OTP',
    source_url: 'Vietcombank Official SMS',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Ma OTP cua Quy khach la 849201 de xac nhan dang nhap ung dung VCB Digibank. Ma co hieu luc trong 3 phut. Khong chia se ma OTP nay voi bat ky ai ke ca nhan vien ngan hang.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_LOGIN_OTP',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'OTP chính thức từ Vietcombank kèm khuyến cáo không chia sẻ.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'VCB-Digibank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-003',
    source_id: 'SRC-GOV-001',
    source_type: 'BENIGN_POLICE_NOTICE',
    source_url: 'Công an phường thông báo',
    collected_at: '2026-10-25',
    published_at: '2026-10-15',
    original_content: 'Cong an quan thong bao: Nhan dan den tru so Cong an phuong de lam thu tuc cap doi the CCCD gan chip vao cac ngay thu 2 den thu 6 trong gio hanh chinh.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_ADMINISTRATIVE_NOTICE',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Thông báo hành chính làm CCCD tại trụ sở công an, không có link hay đòi tiền.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'CucCSGT',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-004',
    source_id: 'SRC-FAM-001',
    source_type: 'BENIGN_FAMILY_MESSAGE',
    source_url: 'Personal SMS',
    collected_at: '2026-10-25',
    published_at: '2026-10-22',
    original_content: 'Toi nay con ve an com nha me oi. Con mua it hoa qua ve nua a.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_FAMILY_CHAT',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Tin nhắn sinh hoạt gia đình bình thường.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: '+84912349911',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S4-BEN-005',
    source_id: 'SRC-ECOM-001',
    source_type: 'BENIGN_ECOMMERCE_NOTICE',
    source_url: 'Shopee Official SMS',
    collected_at: '2026-10-25',
    published_at: '2026-10-19',
    original_content: 'Don hang 2409ABC cua ban tren Shopee da duoc giao thanh cong boi shipper Nguyen Van A. Cam on ban da mua hang tai Shopee Mall.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_DELIVERY_SUCCESS',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Thông báo đơn hàng giao thành công chính thống của Shopee.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'Shopee',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-006',
    source_id: 'SRC-GOV-003',
    source_type: 'BENIGN_SECURITY_AWARENESS',
    source_url: 'BCA Awareness SMS',
    collected_at: '2026-10-25',
    published_at: '2026-09-01',
    original_content: 'Canh bao tu Bo Cong an: Nguoi dan can canh giac voi chieu tro mao danh cong ty luat huong dan lay lai tien bi lua dao tren khong gian mang.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_PUBLIC_SECURITY_ALERT',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Cảnh báo nâng cao cảnh giác từ Bộ Công An.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'BoCongAn',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-007',
    source_id: 'SRC-IT-001',
    source_type: 'BENIGN_IT_MAINTENANCE',
    source_url: 'Internal IT Notice',
    collected_at: '2026-10-25',
    published_at: '2026-10-10',
    original_content: 'He thong phan mem noi bo se tam ngung bao tri tu 22h den 24h toi nay de cap nhat tinh nang.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_SYSTEM_MAINTENANCE',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Thông báo kỹ thuật nội bộ bảo trì hệ thống định kỳ.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'IT-Support',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-008',
    source_id: 'SRC-ACB-001',
    source_type: 'BENIGN_BANK_ALERT',
    source_url: 'ACB Official SMS',
    collected_at: '2026-10-25',
    published_at: '2026-08-31',
    original_content: 'ACB canh bao ve cac SMS va website mao danh lua dao. KH vui long KHONG cung cap thong tin, OTP SMS; KHONG dang nhap website, ung dung gia mao. LH (028)38247247',
    language: 'vi-unaccented',
    scenario: 'BENIGN_BANK_SECURITY_ADVICE',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Cảnh báo chính thức từ ACB hướng dẫn khách hàng tự bảo vệ.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'ACB',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-009',
    source_id: 'SRC-VCB-001',
    source_type: 'BENIGN_APP_REACTIVATION',
    source_url: 'Vietcombank Official SMS',
    collected_at: '2026-10-25',
    published_at: '2026-07-22',
    original_content: 'Vietcombank nhan duoc yeu cau KICH HOAT LAI UNG DUNG VCB DIGIBANK. Neu Quy khach KHONG CHU DONG yeu cau, TUYET DOI KHONG CUNG CAP HOAC XAC NHAN BANG MA OTP de tranh rui ro bi CHIEM DOAT TAI KHOAN. Neu Quy khach yeu cau, vui long nhap ma xac nhan 956897, hieu luc 1 phut de hoan tat kich hoat.',
    language: 'vi-accented',
    scenario: 'BENIGN_AUTHENTIC_OTP',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'OTP thật kích hoạt ứng dụng VCB Digibank có kèm khuyến cáo an toàn.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'Vietcombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-010',
    source_id: 'SRC-EVN-002',
    source_type: 'BENIGN_UTILITY_BILL',
    source_url: 'EVN Official Bill SMS',
    collected_at: '2026-10-28',
    published_at: '2026-10-15',
    original_content: 'EVNHANOI: Tien dien thang 09/2026 cua khach hang Nguyen Van B (Ma KH: PD010029384) la 854,000 VND. Quy khach vui long thanh toan qua ung dung EVNHANOI hoac cong thanh toan ngan hang lien ket truoc ngay 25/10/2026. CSKH: 19001288.',
    language: 'vi-unaccented',
    scenario: 'BENIGN_ELECTRICITY_BILL',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Hóa đơn tiền điện chính thức của EVN Hà Nội, hướng dẫn thanh toán qua app chính quy.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'EVNHANOI',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S4-BEN-011',
    source_id: 'SRC-TEL-001',
    source_type: 'BENIGN_TELECOM_CSKH',
    source_url: 'Viettel Official CSKH',
    collected_at: '2026-10-28',
    published_at: '2026-10-24',
    original_content: 'Viettel cam on Quy khach da su dung dich vu di dong trong 5 nam qua. Tang Quy khach 50 diem Viettel++ nhan dip sinh nhat thang 10. Tra cuu uu dai tren ung dung My Viettel hoac goi 198 (mien phi).',
    language: 'vi-unaccented',
    scenario: 'BENIGN_TELECOM_LOYALTY',
    channel: 'SMS',
    label: 'LEGITIMATE',
    label_confidence: 'HIGH',
    label_evidence: 'Tin nhắn tri ân chính thức Viettel++, hướng dẫn vào app My Viettel chính thống.',
    collection_method: 'REAL_AUTHENTIC_SAMPLING',
    is_synthetic: false,
    parent_sample_id: null,
    split: 'regression_set',
    sender_raw: 'Viettel',
    sender_type: 'BRANDNAME'
  },

  // =========================================================================
  // STREAM 5: ADVERSARIAL & SYNTHETIC VARIATIONS (BIẾN THỂ ĐỐI KHÁNG / TEENCODE)
  // =========================================================================
  {
    sample_id: 'S5-ADV-001',
    source_id: 'SRC-ADV-001',
    source_type: 'ADVERSARIAL_OBFUSCATION',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Canh bao: t.k bi k.h.o.a vui long nhap 0TP tai https://vcb-digibank-xacminh.top de xac minh trong vong 24 gio.',
    language: 'vi-adversarial-punctuation',
    scenario: 'BANK_ACCOUNT_SUSPENSION_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Cố tình chèn dấu chấm k.h.o.a và số 0TP né regex từ khóa.',
    collection_method: 'ADVERSARIAL_PERTURBATION',
    is_synthetic: true,
    parent_sample_id: 'S2-AUTH-001',
    split: 'independent_holdout',
    sender_raw: '+84933221100',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S5-ADV-002',
    source_id: 'SRC-ADV-002',
    source_type: 'ADVERSARIAL_HOMOGLYPH',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Viеtcоmbаnk trаn trоng thоng bаo: Tаi khоаn cуа Quy khаch bi khоа do vi phаm. Vui lоng truy cаp https://vcb-digibank-xacminh.top de xаc thuc.',
    language: 'vi-cyrillic-homoglyph',
    scenario: 'HOMOGLYPH_EVASION_PHISHING',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Thay thế các chữ a, c, e, o, y bằng ký tự Cyrillic đồng hình để qua mặt NLP.',
    collection_method: 'ADVERSARIAL_PERTURBATION',
    is_synthetic: true,
    parent_sample_id: 'S2-AUTH-001',
    split: 'independent_holdout',
    sender_raw: 'Vietcombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S5-ADV-003',
    source_id: 'SRC-ADV-003',
    source_type: 'ADVERSARIAL_DANGLING_URL',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Vietcombank thong bao tai khoan bi khoa vui long truy cap https:// xacminh-vcb.top de mo khoa ngay',
    language: 'vi-unaccented',
    scenario: 'DANGLING_BROKEN_URL_EVASION',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Chèn khoảng trắng sau giao thức https:// nhằm làm vỡ regex URL extraction.',
    collection_method: 'ADVERSARIAL_PERTURBATION',
    is_synthetic: true,
    parent_sample_id: 'S2-AUTH-001',
    split: 'independent_holdout',
    sender_raw: 'Vietcombank',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S5-ADV-004',
    source_id: 'SRC-ADV-004',
    source_type: 'ADVERSARIAL_POLITE_TONE',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Kinh gui quy khach, Chi cuc Thue xin tran trong thong bao co khoan hoan thue thu nhap ca nhan nam 2025 danh cho quy khach. Khi co thoi gian ranh, kinh moi quy khach ghe tham trang dichvucong-thue.top de kiem tra quyen loi.',
    language: 'vi-polite-administrative',
    scenario: 'TAX_REFUND_POLITE_NO_URGENCY',
    channel: 'SMS',
    label: 'VERIFIED_SCAM',
    label_confidence: 'HIGH',
    label_evidence: 'Giả Chi cục Thuế với ngôn từ lịch sự, nhã nhặn, không gây hoảng sợ nhằm che giấu bẫy link độc .top.',
    collection_method: 'ADVERSARIAL_PERTURBATION',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'independent_holdout',
    sender_raw: 'ChiCucThue',
    sender_type: 'BRANDNAME'
  },
  {
    sample_id: 'S5-ADV-005',
    source_id: 'SRC-ADV-005',
    source_type: 'AMBIGUOUS_BORDERLINE',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Anh oi cho em vay tam 500k chieu em gui lai nhe.',
    language: 'vi-unaccented',
    scenario: 'BORDERLINE_PERSONAL_LOAN',
    channel: 'SMS',
    label: 'SUSPICIOUS',
    label_confidence: 'MEDIUM',
    label_evidence: 'Vay mượn cá nhân số tiền nhỏ không kèm STK hay link, chưa đủ căn cứ khẳng định lừa đảo.',
    collection_method: 'SYNTHETIC_BORDERLINE',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '+84912349911',
    sender_type: 'PHONE_DOMESTIC'
  },
  {
    sample_id: 'S5-ADV-006',
    source_id: 'SRC-ADV-006',
    source_type: 'AMBIGUOUS_BORDERLINE',
    source_url: 'Research Adversarial Suite',
    collected_at: '2026-10-25',
    published_at: '2026-10-20',
    original_content: 'Gui ban duong link tham khao tai lieu nhe: https://tinyurl.com/tailieu-2026',
    language: 'vi-unaccented',
    scenario: 'BORDERLINE_SHORTENER_LINK',
    channel: 'SMS',
    label: 'SUSPICIOUS',
    label_confidence: 'MEDIUM',
    label_evidence: 'Gửi link rút gọn không rõ đích đến trong ngữ cảnh chia sẻ tài liệu.',
    collection_method: 'SYNTHETIC_BORDERLINE',
    is_synthetic: true,
    parent_sample_id: null,
    split: 'development_set',
    sender_raw: '+84912998877',
    sender_type: 'PHONE_DOMESTIC'
  }
];

// Helper: HTTP request with Promise
function sendDetectRequest(payload) {
  return new Promise((resolve) => {
    const postData = JSON.stringify(payload);
    const start = Date.now();
    const req = https.request(DETECT_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const latency = Date.now() - start;
        try {
          const json = JSON.parse(data);
          resolve({
            http_status: res.statusCode,
            latency_ms: latency,
            success: true,
            data: json
          });
        } catch (e) {
          resolve({
            http_status: res.statusCode,
            latency_ms: latency,
            success: false,
            error: 'JSON_PARSE_ERROR: ' + data.slice(0, 100)
          });
        }
      });
    });

    req.on('error', (err) => {
      resolve({
        http_status: 0,
        latency_ms: Date.now() - start,
        success: false,
        error: err.message
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        http_status: 408,
        latency_ms: 10000,
        success: false,
        error: 'REQUEST_TIMEOUT'
      });
    });

    req.write(postData);
    req.end();
  });
}

// Sleep helper
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runAudit() {
  console.log('================================================================');
  console.log(`SCAMSHIELD E2E AUDIT STARTING — RUN ID: ${RUN_ID}`);
  console.log(`Target: ${DETECT_ENDPOINT}`);
  console.log(`Total Samples: ${DATASET.length}`);
  console.log('================================================================\n');

  const executionResults = [];
  let tpCount = 0;
  let fpCount = 0;
  let tnCount = 0;
  let fnCount = 0;
  let scamUnknownCount = 0;
  let benignUnknownCount = 0;
  let accurateSuspiciousCount = 0;
  let errorCount = 0;

  for (let i = 0; i < DATASET.length; i++) {
    const item = DATASET[i];
    process.stdout.write(`[${i + 1}/${DATASET.length}] Testing ${item.sample_id} (${item.scenario})... `);

    const payload = {
      text: item.original_content,
      sender: item.sender_raw || '',
      senderType: item.sender_type || 'PHONE_DOMESTIC'
    };

    const resp = await sendDetectRequest(payload);
    await sleep(60); // polite rate limit

    let actualOutput = 'ERROR';
    let actualScore = null;
    let actualSeverity = 'UNKNOWN';
    let matchedRules = [];
    let detectedSignals = [];
    let evalCategory = 'ERROR';

    if (resp.success && resp.data && resp.data.result) {
      const r = resp.data.result;
      actualScore = r.score;
      actualOutput = r.userRiskLevel || 'LOW';
      actualSeverity = r.internalSeverity || 'NORMAL';
      matchedRules = r.matchedRules || [];
      detectedSignals = (r.signals || []).map(s => s.signal_code);

      // Classification Evaluation
      const isScamGroundTruth = (item.label === 'VERIFIED_SCAM' || item.label === 'STRONG_EVIDENCE_SCAM');
      const isBenignGroundTruth = (item.label === 'LEGITIMATE');
      const isSuspiciousGroundTruth = (item.label === 'SUSPICIOUS');

      if (isScamGroundTruth) {
        if (actualOutput === 'HIGH') {
          evalCategory = 'TP';
          tpCount++;
        } else if (actualOutput === 'LOW') {
          evalCategory = 'FN';
          fnCount++;
        } else {
          evalCategory = 'SCAM_UNKNOWN';
          scamUnknownCount++;
        }
      } else if (isBenignGroundTruth) {
        if (actualOutput === 'LOW') {
          evalCategory = 'TN';
          tnCount++;
        } else if (actualOutput === 'HIGH') {
          evalCategory = 'FP';
          fpCount++;
        } else {
          evalCategory = 'BENIGN_UNKNOWN';
          benignUnknownCount++;
        }
      } else if (isSuspiciousGroundTruth) {
        if (actualOutput === 'UNKNOWN' || actualOutput === 'SUSPICIOUS') {
          evalCategory = 'ACCURATE_SUSPICIOUS';
          accurateSuspiciousCount++;
        } else if (actualOutput === 'HIGH') {
          evalCategory = 'SUSPICIOUS_ESCALATED_HIGH';
        } else {
          evalCategory = 'SUSPICIOUS_DOWNGRADED_LOW';
        }
      }
      console.log(`[${evalCategory}] Score: ${actualScore} (${actualOutput}) | HTTP ${resp.http_status} (${resp.latency_ms}ms)`);
    } else {
      errorCount++;
      evalCategory = 'EXECUTION_ERROR';
      console.log(`[ERROR] ${resp.error || 'Unknown HTTP failure'}`);
    }

    executionResults.push({
      test_id: `TC-${item.sample_id}`,
      sample_id: item.sample_id,
      timestamp: new Date().toISOString(),
      app_url: APP_URL,
      app_version: '1.2.0-prod',
      execution_method: 'LIVE_API_E2E',
      input_hash: sha256(item.original_content),
      input_modality: 'TEXT',
      sender_raw: item.sender_raw,
      sender_type: item.sender_type,
      ground_truth_label: item.label,
      actual_output: actualOutput,
      actual_score: actualScore,
      actual_severity: actualSeverity,
      eval_category: evalCategory,
      matched_rules: matchedRules.join(';'),
      detected_signals: detectedSignals.join(';'),
      latency_ms: resp.latency_ms,
      http_status: resp.http_status,
      error: resp.error || ''
    });
  }

  // -------------------------------------------------------------------------
  // METRICS COMPUTATION
  // -------------------------------------------------------------------------
  const totalDecisiveScam = tpCount + fnCount;
  const precision = (tpCount + fpCount) > 0 ? (tpCount / (tpCount + fpCount)) * 100 : 0;
  const recall = totalDecisiveScam > 0 ? (tpCount / totalDecisiveScam) * 100 : 0;
  const fnr = totalDecisiveScam > 0 ? (fnCount / totalDecisiveScam) * 100 : 0;
  const totalBenign = tnCount + fpCount;
  const fpr = totalBenign > 0 ? (fpCount / totalBenign) * 100 : 0;
  const specificity = totalBenign > 0 ? (tnCount / totalBenign) * 100 : 0;
  const totalScamsAll = tpCount + fnCount + scamUnknownCount;
  const scamUnknownRate = totalScamsAll > 0 ? (scamUnknownCount / totalScamsAll) * 100 : 0;

  console.log('\n================================================================');
  console.log('AUDIT EXECUTION COMPLETED — SUMMARY METRICS');
  console.log('================================================================');
  console.log(`Total Samples Executed : ${DATASET.length}`);
  console.log(`True Positives (TP)    : ${tpCount}`);
  console.log(`False Positives (FP)   : ${fpCount}`);
  console.log(`True Negatives (TN)    : ${tnCount}`);
  console.log(`False Negatives (FN)   : ${fnCount}`);
  console.log(`Scam in UNKNOWN State  : ${scamUnknownCount} (${scamUnknownRate.toFixed(2)}%)`);
  console.log(`Benign in UNKNOWN State: ${benignUnknownCount}`);
  console.log(`Accurate Suspicious    : ${accurateSuspiciousCount}`);
  console.log(`Execution Errors       : ${errorCount}`);
  console.log('----------------------------------------------------------------');
  console.log(`Precision              : ${precision.toFixed(2)}%`);
  console.log(`Recall (Decisive)      : ${recall.toFixed(2)}%`);
  console.log(`False Negative Rate    : ${fnr.toFixed(2)}%`);
  console.log(`False Positive Rate    : ${fpr.toFixed(2)}%`);
  console.log(`Specificity            : ${specificity.toFixed(2)}%`);
  console.log('================================================================\n');

  return {
    results: executionResults,
    metrics: {
      total: DATASET.length,
      tp: tpCount,
      fp: fpCount,
      tn: tnCount,
      fn: fnCount,
      scamUnknown: scamUnknownCount,
      benignUnknown: benignUnknownCount,
      accurateSuspicious: accurateSuspiciousCount,
      errors: errorCount,
      precision,
      recall,
      fnr,
      fpr,
      specificity,
      scamUnknownRate
    }
  };
}

// Export for execution
if (require.main === module) {
  runAudit().then(auditData => {
    // Save raw results to artifacts
    const csvHeader = 'test_id,sample_id,timestamp,app_url,app_version,execution_method,input_hash,input_modality,sender_raw,sender_type,ground_truth_label,actual_output,actual_score,actual_severity,eval_category,matched_rules,detected_signals,latency_ms,http_status,error\n';
    const csvRows = auditData.results.map(r => [
      r.test_id,
      r.sample_id,
      r.timestamp,
      r.app_url,
      r.app_version,
      r.execution_method,
      r.input_hash,
      r.input_modality,
      `"${r.sender_raw || ''}"`,
      r.sender_type,
      r.ground_truth_label,
      r.actual_output,
      r.actual_score,
      r.actual_severity,
      r.eval_category,
      `"${r.matched_rules}"`,
      `"${r.detected_signals}"`,
      r.latency_ms,
      r.http_status,
      `"${r.error}"`
    ].join(',')).join('\n');

    fs.writeFileSync(path.join(ARTIFACTS_DIR, 'execution_results.csv'), csvHeader + csvRows, 'utf8');
    fs.writeFileSync(path.join(ARTIFACTS_DIR, 'audit_summary.json'), JSON.stringify(auditData.metrics, null, 2), 'utf8');
    console.log(`Saved execution results to ${path.join(ARTIFACTS_DIR, 'execution_results.csv')}`);
  });
}

module.exports = { runAudit, DATASET };
