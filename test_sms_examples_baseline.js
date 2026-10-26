/**
 * SCAM ALERT AUTOMATED REGRESSION TEST SUITE (REAL SMS SCREENSHOT DATASET)
 * 
 * Tập 49 ca kiểm thử thực nghiệm trích xuất từ 63 ảnh chụp tin nhắn lừa đảo thực tế
 * trong thư mục 'sms example/'.
 * 
 * Cách chạy:
 *   node test_sms_examples_baseline.js
 */

const fs = require('fs');
const path = require('path');
const { analyzeMessage } = require('./test_rule_engine');

const testCases = [
  {
    id: 'SMS-CASE-001',
    imgId: 'SMS-IMG-001',
    file: '1-12.png',
    sender: '0912345678',
    senderType: 'PHONE_DOMESTIC',
    text: 'Cong ty nguoi nha anh co van de ve von luu dong, can tien de quay vong , anh khong tien dung ten minh truc tiep chuyen khoan. Dung tien mat di nop vao tai khoan nguoi than toi duoc khong?',
    expectedLabel: 'SCAM_HIGH_CONFIDENCE',
    expectedRisk: 'HIGH',
    category: 'PIG_BUTCHERING_LENDING'
  },
  {
    id: 'SMS-CASE-002',
    imgId: 'SMS-IMG-002',
    file: '10283d.png',
    sender: 'Messengër',
    senderType: 'BRANDNAME',
    text: 'THONG BAO Xin Chuc Mung Tai Khoan FACEBOOK Cua [Diep Ha] Da May Man Nhan Duoc Giai Nhat Tu Su Kien Tri An Khach Hang Tai Khoan FaceBook App Cua [Diep Ha] Mang Ma So Trung Thuong La 208A79 Da May Man Duoc He Thong Lua Chon Ngau Nhien, Xac Nhan La Tai Khoan Da Trung Thuong. Phan Qua Giai Nhat Cua Ban Gom: 01 Xe May HonDa SH 125i Viet Nam Tri Gia 81.000.000 VND 01 Phieu Qua Tang Tien Mat Tri Gia 200.000.000 VND 01 The Su Dung Xang Mien Phi 1 Nam Tri Gia 5.000.000 VND',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'LOTTERY_PRIZE'
  },
  {
    id: 'SMS-CASE-003A',
    imgId: 'SMS-IMG-003',
    file: '1634701415-5cf9ac3d0bcc3657266b6e3f1873fff2-width800height800.jpg',
    sender: 'c7ydtgou5y987i3l@hotmail.com.tw',
    senderType: 'UNKNOWN',
    text: 'Xin chao, minh la giam doc marketing cua Shopee, hien tai cua hang Shopee can tuyen so luong lon nhan vien chuyen dat hang de nang cao so luong giao dich va thu hang cua cua hang. Chi can co kinh nghiem mua sam truc tuyen, moi ngay ban co the de dang kiem 800.000 dong bang dien thoai di dong va tien luong se duoc quyet toan ngay trong ngay. Neu ban muon tham gia cong viec nay vui long add tai khoan Zalo cua giam doc marketing: 84567233168. Hien tai chi con 30 suat duy nhat, chi trong ngay hom nay! (Luu y: yeu cau nguoi tham gia tu 22 tuoi tro len, hoc sinh sinh vien vui long khong tham gia)',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TASK_JOB_SCAM'
  },
  {
    id: 'SMS-CASE-003B',
    imgId: 'SMS-IMG-003',
    file: '1634701415-5cf9ac3d0bcc3657266b6e3f1873fff2-width800height800.jpg',
    sender: 'jk37578544@126.com',
    senderType: 'UNKNOWN',
    text: 'Xin chao, minh la giam doc marketing cua Lazada, hien tai cua hang Lazada can tuyen so luong lon nhan vien chuyen dat hang de nang cao so luong giao dich va thu hang cua cua hang. Chi can co kinh nghiem mua sam truc tuyen, moi ngay ban co the de dang kiem 800.000 dong bang dien thoai di dong va tien luong se duoc quyet toan ngay trong ngay. Neu ban muon tham gia cong viec nay vui long add tai khoan Zalo cua giam doc marketing: 840569564100. Hien tai chi con 30 suat duy nhat, chi trong ngay hom nay! (Luu y: yeu cau nguoi tham gia tu 22 tuoi tro len, hoc sinh sinh vien vui long khong tham gia)',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TASK_JOB_SCAM'
  },
  {
    id: 'SMS-CASE-004',
    imgId: 'SMS-IMG-004',
    file: '1690824459-tin-nhan-lua-dao-tri-an-khach-hang-3309-width850height945.jpg',
    sender: 'Gumac',
    senderType: 'BRANDNAME',
    text: 'Em chao chi,em la nhan vien CSKH Gumac a. Da thay mat toan the nhan vien Hang Thoi Trang GUMAC em xin cam on chi da tin tuong va chon dien cung thoi trang ben em a! Da nha Gu dang co sieu su kien sinh nhat 8 nam tuoi tri an cam on khach hang. Tang chi 2 set trang phuc CONG SO HANH PHUC. Vi so luong khach hang nhan qua ben em kha nhieu. Yeu cau tat ca khach hang can co ung dung TELEGRAM Messenger de duoc nhan. Ma nhan qua cua chi la: GU1523. Chi yeu vui long bam vao link: https://t.me/triangumac_vn2023 va nhan tin Chuc mung sinh nhat GUMAC roi nhan qua a',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BRAND_IMPERSONATION_LURE'
  },
  {
    id: 'SMS-CASE-005',
    imgId: 'SMS-IMG-005',
    file: '1816 (27).jpg',
    sender: 'BeeTalk',
    senderType: 'BRANDNAME',
    text: 'Thong bao: {* Mang Xa Hoi-BeeTalk Xin Chao Quy Khach Den Voi He Thong BeeTalk *} Chuc Mung So Thue Bao Dang Ki BeeTalk Cua Ban Nhan Duoc Giai Nhat Cua Chuong Trinh Trong Vong Quay Dac Biet-Tri An Khach Hang Mang Ma So Du Thuong La [402E7E] Cua He Thong. Truy Cap He Thong Http://giaithuong.us ---- ...De Lam Thu Tuc Nhan Giai. Chi Tiet Lien He Mr.Vu Voi HotLine : ( 0084 962 112 642 )',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'LOTTERY_PRIZE'
  },
  {
    id: 'SMS-CASE-006',
    imgId: 'SMS-IMG-006',
    file: '2-1784618774-4281-1784618949.webp',
    sender: '+84903824107',
    senderType: 'PHONE_DOMESTIC',
    text: 'Thong bao: Phuong tien cua ban co vi pham giao thong. Vui long truy cap https://csgt.bocongan.web.id/vn/ de tra cuu va nop phat.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-007',
    imgId: 'SMS-IMG-007',
    file: '20220831-ta16.webp',
    sender: 'ACB',
    senderType: 'BRANDNAME',
    text: 'ACB canh bao ve cac SMS va website mao danh lua dao. KH vui long KHONG cung cap thong tin, OTP SMS; KHONG dang nhap website, ung dung gia mao. LH (028)38247247',
    expectedLabel: 'BENIGN_CONFIRMED',
    expectedRisk: 'LOW',
    category: 'BENIGN_SECURITY_WARNING'
  },
  {
    id: 'SMS-CASE-008',
    imgId: 'SMS-IMG-008',
    file: '3259639144895752366851571287114594544805498n-1674359750707928698372.jpg',
    sender: 'Unknown',
    senderType: 'UNKNOWN',
    text: 'Bia Sai Gon 2023 Qua Tet Nguyen Dan http://m.2ffzarr.cn/a07acVkGX2h8Qn9DCF9yFDMmZX4QbhRoTSFTAXgeMy4MCzMYaRUkLV3aCAU7agFWRRMvMQcLDCEFgxVYxZRIzA&p=vzpnms1674308582284',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'MALICIOUS_DOMAIN'
  },
  {
    id: 'SMS-CASE-009',
    imgId: 'SMS-IMG-009',
    file: '3d4474ad02e6ebb8b2f7.jpg',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Thong bao : Quy khach con mot khoan phat giao thong chua duoc thanh toan. Vui long thanh toan som de tranh cac khoan phi phat phat sinh : dichvuconggov-vn.com',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-010A',
    imgId: 'SMS-IMG-010',
    file: '566552529_25249869821309305_6447884069765756460_n.png',
    sender: 'ACB',
    senderType: 'BRANDNAME',
    text: 'ACB: Tai khoan cua ban da mo dich vu tai chinh toan cau phi dich vu hang thang la 2.000.000VND se bi tru trong 2 gio .Neu khong phai ban mo dich vu vui long nhan vao https://acb-online-center.com de huy',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-010B',
    imgId: 'SMS-IMG-010',
    file: '566552529_25249869821309305_6447884069765756460_n.png',
    sender: 'VietinBank',
    senderType: 'BRANDNAME',
    text: 'Vietinbank tran trong thong bao, tai khoan cua quy khach hien tai da bi khoa. Dang nhap http://www.vniatinbanks.cc de xac thuc ngay hom nay',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ACCOUNT_LOCKED'
  },
  {
    id: 'SMS-CASE-011',
    imgId: 'SMS-IMG-011',
    file: '616-251e5108b53342f397f5cf62e96a7093.jpg',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Ban chua nhan du0c tr0 cap COVID-19, vui long nhap>> tinyurl.com/kxytdc8z de lay, qua han se kh0ng duoc chap nhan!',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_RELIEF_LEETSPEAK'
  },
  {
    id: 'SMS-CASE-012',
    imgId: 'SMS-IMG-012',
    file: '68932b2d19db7c63259f4358.jpg',
    sender: '18001096',
    senderType: 'PHONE_DOMESTIC',
    text: 'Canh sat Giao thong Viet Nam: Hien tai, ban dang co mot khoan tien phat chua thanh toan trong tai khoan. Vui long thanh toan khoan phi nay cang som cang tot de tranh nhung bat tien khong dang co. De biet them thong tin, vui long truy cap: https://dichvucongg.top/vn',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-013',
    imgId: 'SMS-IMG-013',
    file: '706675990_1008170785117251_1254167812091218100_n.png',
    sender: 'MSB',
    senderType: 'BRANDNAME',
    text: 'Tai khoan cua ban da dang ky chuong trinh quang cao tren TikTok, moi thang thu phi 3,250,000 VND. Vui long vao https://msb.vn-cvs.xyz de kiem tra hoac de huy',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-014',
    imgId: 'SMS-IMG-014',
    file: '76052_c1bdcdbdd5a7bb21dbf3752296001645.jpg',
    sender: '+84342026095',
    senderType: 'PHONE_DOMESTIC',
    text: '2302030732222 NGUYEN TAN HUNG MB BANK. 245k chi chuyen khoan de em chot don xong bao em nhe',
    expectedLabel: 'SUSPICIOUS',
    expectedRisk: 'UNKNOWN',
    category: 'STRANGER_DEPOSIT_REQUEST'
  },
  {
    id: 'SMS-CASE-015',
    imgId: 'SMS-IMG-015',
    file: '77286872610811009079513108238452154842505598npng-1787008540311-17870085405362077229538.webp',
    sender: '+212649020639',
    senderType: 'PHONE_INTERNATIONAL',
    text: '[TTDLQG - Bo Cong an] Thong bao yeu cau nop phat vi pham dung thoi han Phuong tien cua Quy khach bi ghi nhan vi pham tin hieu den giao thong ngay 06/08/2026, hien chua hoan thanh nghia vu nop phat. Trong vong 48 gio toi neu khong xu ly, muc phat se tang them 50% va Cuc Canh sat giao thong se tam giu giay to xe. Vui long xem thong tin chi tiet va thanh toan khoan phat tai lien ket: https://902577.cc/dichvucong.gov/vn Tra loi 1 hoac Y de nhan link kich hoat thay the',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-016',
    imgId: 'SMS-IMG-016',
    file: '834462737_967694235960876_2354436322647638760_n.png',
    sender: 'Sacombank',
    senderType: 'BRANDNAME',
    text: 'Phat hien tai khoan cua ban dang nhap khac vung bat thuong ,vui long dang nhap https://vn-sacombank.com de xac nhan thong tin va thay doi mat khau',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-017',
    imgId: 'SMS-IMG-017',
    file: '835059818_1813424089849314_4392999658187224934_n.png',
    sender: 'Vietcombank',
    senderType: 'BRANDNAME',
    text: 'Tai khoan cua ban dang duoc dang nhap tren thiet bi khac ,neu khong phai ban dang nhap vui long vao https://vietcombank.vn-gss.club de sua doi mat khau hoac thoat khoi thiet bi kia',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-018',
    imgId: 'SMS-IMG-018',
    file: '835302931_1670029138171771_3816771424990099594_n.png',
    sender: 'Vietcombank',
    senderType: 'BRANDNAME',
    text: 'Vietcombank nhan duoc yeu cau KICH HOAT LAI UNG DUNG VCB DIGIBANK. Neu Quy khach KHONG CHU DONG yeu cau, TUYET DOI KHONG CUNG CAP HOAC XAC NHAN BANG MA OTP de tranh rui ro bi CHIEM DOAT TAI KHOAN. Neu Quy khach yeu cau, vui long nhap ma xac nhan 956897, hieu luc 1 phut de hoan tat kich hoat.',
    expectedLabel: 'BENIGN_CONFIRMED',
    expectedRisk: 'LOW',
    category: 'BENIGN_BANK_OTP'
  },
  {
    id: 'SMS-CASE-019',
    imgId: 'SMS-IMG-019',
    file: '838362505_2643009526153414_646519637807011020_n.png',
    sender: '+84988776655',
    senderType: 'PHONE_DOMESTIC',
    text: 'Em la sinh vien dang tin them viec ban thoi gian. Neu nhu anh co nhu cau tinh duc co the lien he Telegram cua em a : https://t.me/okGuO',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'ADULT_EXTORTION_LURE'
  },
  {
    id: 'SMS-CASE-020',
    imgId: 'SMS-IMG-020',
    file: 'a-ld-4-17218113421262018897545-1721814216443-1721814216625414420-1743056180980933755899.webp',
    sender: '0977665544',
    senderType: 'PHONE_DOMESTIC',
    text: 'Chao em may nay cong viec cua anh hoi ban gio nho toi nen gio anh moi nhan tin cho em duoc that tinh xin loi em. Khong biet co lien co noi gi ve anh cho em nghe chua. Anh la truong con me hien. Anh nghe co lien noi em la chau co nen co cho anh so cua em de hai dua noi chuyen. Co lien vk chu Tuan lam ben chi cuc thue o ha noi A em. Em co phai la hoa khong ?',
    expectedLabel: 'SUSPICIOUS',
    expectedRisk: 'UNKNOWN',
    category: 'PIG_BUTCHERING_APPROACH'
  },
  {
    id: 'SMS-CASE-021',
    imgId: 'SMS-IMG-021',
    file: 'bbb-1487735203.jpg',
    sender: 'Zalo',
    senderType: 'BRANDNAME',
    text: 'TAI Khoan Zalo cua ban la khach hang may man trung thuong. GIAI NHAT GOM: 1 CHIEC XE MAY SH150I + 200 TRIEU DONG TIEN MAT. GIAI thuong do tap doan mang xa hoi Zalo & Honda VIET NAM DONG HANH TAI TRO. Ma so cua ban la: KH68ZL79 SU KIEN nham GUI LOI TRI AN KHACH HANG DA TIN TUONG SU DUNG DICH VU Zalo. Bam vao LINK: https://plus.google.com/114908180224783665698/posts/hTum48KFMCX Lam thu tuc nhan thuong.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'LOTTERY_PRIZE'
  },
  {
    id: 'SMS-CASE-022A',
    imgId: 'SMS-IMG-022',
    file: 'c1-1658839686.jpg',
    sender: 'xxxxxx44716@piaoju18.icu',
    senderType: 'UNKNOWN',
    text: 'Trang thuong mai dien tu TIKI hop tac cung DSC ! Tuyen nhan vien lam viec online tren dien thoai . So luong : 80 nguoi . Thu nhap 300k - 1000k . Chi can ban co thoi gian ranh . zalo: zalo.me/84378088763 Vui long add zalo :84378088763',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TASK_JOB_SCAM'
  },
  {
    id: 'SMS-CASE-022B',
    imgId: 'SMS-IMG-022',
    file: 'c1-1658839686.jpg',
    sender: 'fd324724172@126.com',
    senderType: 'UNKNOWN',
    text: 'Xin chao, minh la giam doc marketing cua Tiki, hien tai cua hang Tiki can tuyen so luong lon nhan vien chuyen dat hang de nang cao so luong giao dich va thu hang cua cua hang. Chi can co kinh nghiem mua sam truc tuyen, moi ngay ban co the de dang kiem 800.000 dong bang dien thoai di dong va tien luong se duoc quyet toan ngay trong ngay. Neu ban muon tham gia cong viec nay vui long add tai khoan Zalo cua giam doc marketing: 1697075320. Hien tai chi con 30 suat duy nhat, chi trong ngay hom nay!',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TASK_JOB_SCAM'
  },
  {
    id: 'SMS-CASE-023',
    imgId: 'SMS-IMG-023',
    file: 'canhbaonh5.jpeg',
    sender: 'ACB',
    senderType: 'BRANDNAME',
    text: 'Chung toi phat hien tai khoan cua ban dang tieu dung o nuoc ngoai .Neu khong phai ban dang tieu dung vui long nhap vao https://v-acb.com de huy thanh toan',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-024',
    imgId: 'SMS-IMG-024',
    file: 'gia-mao-ngan-hang-1-1680623788664.webp',
    sender: 'VCB DIGIBANK',
    senderType: 'BRANDNAME',
    text: 'UNG DUNG VCB DIGIBANK cua ban duoc PHAT HIEN KICH HOAT tren thiet bi la .Neu KHONG PHAI BAN KICH HOAT vui long bam vao https://vietcombank.vn-ms.top de doi thiet bi hoac huy de tranh mat tai san',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-025',
    imgId: 'SMS-IMG-025',
    file: 'h2_1280x720-800-resize.jpg',
    sender: '+84769528877',
    senderType: 'PHONE_DOMESTIC',
    text: 'Em chao minh a, TK tradivi tai cong game 88 hom nay duoc nhan DIEM TRI AN tu bo phan CSKH VIP. Neu la chu tai khoan minh phan hoi em ho tro minh nhe. Zalo 0792812345 (Nhi Pham) - Tele: @kieu123 (Nhi Pham). Em thong bao them la hien tai cong ty khong co hop tac voi dai li nua nen co van de gi can ho tro thi cu lien he voi em hoac cskh truc tuyen , chu khong nhan tin nho dai li ho tro de tranh that thoat',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_VIP_LURE'
  },
  {
    id: 'SMS-CASE-026',
    imgId: 'SMS-IMG-026',
    file: 'image_203.png',
    sender: 'QUA-TET',
    senderType: 'BRANDNAME',
    text: 'Chinh phu tang ban 100.000 dong nhan dip 2/9, hay dang ky nhan qua duong link: http://1234.xyz',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'LOTTERY_PRIZE'
  },
  {
    id: 'SMS-CASE-027',
    imgId: 'SMS-IMG-027',
    file: 'images (1).jpg',
    sender: '+84373959541',
    senderType: 'PHONE_DOMESTIC',
    text: 'LENH TRUY NA: Can cu tai lieu thu thap duoc, ngay 09/03/2022 Co quan canh sat dieu tra Cong An chinh thuc TRUY NA ONG/BA va DONG PHAM ve hanh vi LUA DAO, CAU KET, CHIEM DOAT TAI SAN. NOI TRONG 48H TOI Doi Tuong khong tu giac trinh dien se tien hanh Chuyen giao Khoan Vay cho CONG TY DOI NO THUE, TRUY TIM va XU LY tat ca cac nguoi lien quan va TRUY THU TAI SAN.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'LEGAL_THREAT'
  },
  {
    id: 'SMS-CASE-028',
    imgId: 'SMS-IMG-028',
    file: 'images (3).jpg',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Cong an giao thong Ho Chi Minh: Ban co hinh phat vi pham can duoc xu ly kip thoi. De biet chi tiet, vui long kiem tra http://dichvucong.xyz/DLGAWTBtGW',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-029',
    imgId: 'SMS-IMG-029',
    file: 'images (4).jpg',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Nho chi goi qua fb cua e a , noi cho chi muon 100 trieu chi co viec gap sang mai chi tra , chi dien that that de e bat loa ngoai cho a nghe , roi chi nhan so tai khoan qua fb e chuyen qua cho chi nhe',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'SOCIAL_ENGINEERING_COLLUSION'
  },
  {
    id: 'SMS-CASE-030',
    imgId: 'SMS-IMG-030',
    file: 'images5499207_mot_tin_nhan_mao_danh_ngan_hang_de_lua_dao.jpg',
    sender: 'VCB Digibank',
    senderType: 'BRANDNAME',
    text: 'VCB Digibank tran trong thong bao.tai khoan cua quy khach hien tai da bi khoa.Dang nhap www.vcbigaobink.com de xac thuc ngay hom nay.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ACCOUNT_LOCKED'
  },
  {
    id: 'SMS-CASE-031',
    imgId: 'SMS-IMG-031',
    file: 'images721691_luadaochiem.jpg',
    sender: '+84582675931',
    senderType: 'PHONE_DOMESTIC',
    text: '(BHXHTB) Ban th0a dieu k!en nahn t!en ho tro tu quy BHTN, vui long nhap NGAY>> m.bidstk.icu de lay. QUA_HAN SE KH0NG_DUOC_CHAP_NHAN! ErHg',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_RELIEF_LEETSPEAK'
  },
  {
    id: 'SMS-CASE-032A',
    imgId: 'SMS-IMG-032',
    file: 'img-0703-jpg-1640509658-6635-1640537038.webp',
    sender: 'Sacombank',
    senderType: 'BRANDNAME',
    text: 'CANH BAO: Neu quy khach nhan duoc tin nhan mao danh Sacombank yeu cau bam vao link, cung cap thong tin, OTP, tat ca deu nham muc dich LUA DAO. Tuyet doi KHONG thuc hien. Hotline ho tro KH: 1900555588',
    expectedLabel: 'BENIGN_CONFIRMED',
    expectedRisk: 'LOW',
    category: 'BENIGN_SECURITY_WARNING'
  },
  {
    id: 'SMS-CASE-032B',
    imgId: 'SMS-IMG-032',
    file: 'img-0703-jpg-1640509658-6635-1640537038.webp',
    sender: 'Sacombank',
    senderType: 'BRANDNAME',
    text: 'Tai khoan cua ban da mo dich vu tai chinh toan cau phi dich vu hang thang la 2.800.000VND se bi tru trong 2 gio. Neu khong phai ban mo dich vu vui long nhan vao sacombank.vn-me.top de huy',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-033',
    imgId: 'SMS-IMG-033',
    file: 'img_3392.jpeg.jpg',
    sender: 'Vietcombank',
    senderType: 'BRANDNAME',
    text: 'Vietcombank luu y: Ban co 18699 diem thuong se het han sau 24 gio, vui long truy cap: https://vietcombankd.cfd/vn de doi qua.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_POINTS_EXPIRY'
  },
  {
    id: 'SMS-CASE-034',
    imgId: 'SMS-IMG-034',
    file: 'Lua-Dao-01.jpg',
    sender: 'HUIT',
    senderType: 'BRANDNAME',
    text: 'HUIT- Chuc mung Ban da TRUNG TUYEN CHINH THUC! Moi ban den HUIT nhap hoc tu ngay 18/8 den 17h00 ngay 27/8/2024. Dong thoi, HUIT tang ngay uu dai 3 trieu dong danh cho 2.000 thi sinh nhap hoc som nhat. Tra cuu ket qua tai: huit.edu.vn/kqtt. Lien he: 02871085555, 0949981717, Zalo:',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'UNIVERSITY_ADMISSION_SCAM'
  },
  {
    id: 'SMS-CASE-035',
    imgId: 'SMS-IMG-035',
    file: 'luadao_20250811095819.webp',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Canh sat Giao thong Viet Nam: Ho so vi pham giao thong duoc luu tru duoi ten cua ban. De biet them thong tin, vui long truy cap https://dichvucongs.top/vn',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_POLICE_FINE'
  },
  {
    id: 'SMS-CASE-036',
    imgId: 'SMS-IMG-036',
    file: 'mang-xh.jpg',
    sender: '0988112233',
    senderType: 'PHONE_DOMESTIC',
    text: 'Nho chut nao. A co viec chut. Em chuyen anh muon 2tr5 nha mai ah gui. Anh co chut viec gia dinh',
    expectedLabel: 'SCAM_HIGH_CONFIDENCE',
    expectedRisk: 'HIGH',
    category: 'HACKED_ACQUAINTANCE_LENDING'
  },
  {
    id: 'SMS-CASE-037',
    imgId: 'SMS-IMG-037',
    file: 'mao-danh-ngan-hang=lua-dao.jpg',
    sender: 'Techcombank',
    senderType: 'BRANDNAME',
    text: 'Tai khoan cua ban da mo dich vu tai chinh toan cau phi dich vu hang thang la 2.000.000VND se bi tru trong 2 gio. Neu khong phai ban mo dich vu vui long nhan vao https://techcombank.vn-pl.top de huy',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-038',
    imgId: 'SMS-IMG-038',
    file: 'nhan-dien-loi-so-dang-trong-tin-nhan-lua-dao-qua-ngan-hang-luu-y-ngay-de-bao-toan-tai-khoan.webp',
    sender: 'Vietcombank',
    senderType: 'BRANDNAME',
    text: '(Vietcombank)Chung toi phat hien tai khoan cua ban dang tieu dung o nuoc ngoai .Neu khong phai ban dang tieu dung vui long nhap vao https://i-vietcombank.com',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-039',
    imgId: 'SMS-IMG-039',
    file: 'phat-tan-tin-nhan-rac-lua-dao-hon-20-ty-dong-0.jpg',
    sender: '+841216243309',
    senderType: 'PHONE_DOMESTIC',
    text: 'Goi lai vao so 19004555, E gui tang mon qua dac biet, nho nghe loi nhan roi tra loi e nhe. E T',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TOLL_FRAUD_1900'
  },
  {
    id: 'SMS-CASE-040',
    imgId: 'SMS-IMG-040',
    file: 'photo-1-1677141674806405551639.webp',
    sender: 'gai goi',
    senderType: 'BRANDNAME',
    text: 'Phuc vu so mot viet nam, nguoi mau, dien vien, nhan vien van phong, dich vu tot nhat hien nay.. dang ky ngay: lenlut.info',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'ADULT_EXTORTION_LURE'
  },
  {
    id: 'SMS-CASE-041A',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0582366721',
    senderType: 'PHONE_DOMESTIC',
    text: 'Corona` vua choi game giai tri vua kiem tien, www.470407.com nhieu phan thuong,ngay ngay tang.! add zalo:0582366721',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_SPAM'
  },
  {
    id: 'SMS-CASE-041B',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0898970137',
    senderType: 'PHONE_DOMESTIC',
    text: 'Casin0 phu quoc ra mat phien ban online roi , o nha cung co the tham gia! kb zalo:0898970137 Dang ki tai khoan nhan qua khai truong tu...',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_SPAM'
  },
  {
    id: 'SMS-CASE-041C',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0922470187',
    senderType: 'PHONE_DOMESTIC',
    text: 'Corona` vua choi game giai tri vua kiem tien, www.470412.com nhieu phan thuong,ngay ngay tang.! add zalo:.0922470187 nhan ngay 200k',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_SPAM'
  },
  {
    id: 'SMS-CASE-041D',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0921128644',
    senderType: 'PHONE_DOMESTIC',
    text: 'quoc hoan nghenh ban, add zalo gai xinh, nhan ngay 200k web: www.470420.com zalo:0921128644',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_SPAM'
  },
  {
    id: 'SMS-CASE-041E',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0337678213',
    senderType: 'PHONE_DOMESTIC',
    text: 'Corona` vua choi game giai tri vua kiem tien, www.470407.com nhieu phan thuong,ngay ngay tang.! add zalo:·0337678213 nhan ngay 200k',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GAMBLING_SPAM'
  },
  {
    id: 'SMS-CASE-041F',
    imgId: 'SMS-IMG-041',
    file: 'tin-nhan-16814371843211693788764.jpg',
    sender: '0922340845',
    senderType: 'PHONE_DOMESTIC',
    text: 'tinh ban luon la su khoi dau cho mot moi quan he dep, mong duoc ket ban zalo voi nguoi co duyen zalo 0922340845',
    expectedLabel: 'SUSPICIOUS',
    expectedRisk: 'UNKNOWN',
    category: 'PIG_BUTCHERING_APPROACH'
  },
  {
    id: 'SMS-CASE-042',
    imgId: 'SMS-IMG-042',
    file: 'tin-nhan-gia-mao.jpg',
    sender: 'BO GTVT',
    senderType: 'BRANDNAME',
    text: 'Bo giao thong van tai,xin thong bao ong/ba co bien lai chua nop phat.Hom nay la thong bao cuoi cung.Yeu cau nhanh chong giai quyet moi thac mac Vui long lien he : 0782320830',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'GOV_MINISTRY_FINE'
  },
  {
    id: 'SMS-CASE-043',
    imgId: 'SMS-IMG-043',
    file: 'tin-nhan-lua-dao.jpg',
    sender: 'programasinteligentes@web.de',
    senderType: 'UNKNOWN',
    text: 'Con 28 luot dang ky cuoi cung ! Xin chao, co phai ban dang muon tim cong viec khong? Voi muc luong la 6tr-36tr moi thang voi cong viec hoan toan hop phap va dam bao thu nhap Moi ngay ban nhan thap nhat 800k, kiem tien tai nha don gian Neu nhu ban co nhu cau vui long lien he zalo ID :84904595364 Duoi 23 tuoi vui long khong lien he tham gia Sao chep lien ket vao trinh duyet :https://zalo.me/84904595364 Dich vu 1 voi 1',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TASK_JOB_SCAM'
  },
  {
    id: 'SMS-CASE-044',
    imgId: 'SMS-IMG-044',
    file: 'tin-nhan-trung-thuong.webp',
    sender: '0912345678',
    senderType: 'PHONE_DOMESTIC',
    text: 'Xin chuc mung TB0913838170 Da trung thuong 1 IP5s trong chuong trinh du thuong cuoi nam Lien He: 1>9>0>0>1>9>9>5 de nhan giai. De nghi LH truoc ngay 28/01',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'TOLL_FRAUD_PRIZE'
  },
  {
    id: 'SMS-CASE-045A',
    imgId: 'SMS-IMG-045',
    file: 'tinnhanluadao1-1741070631435-17410706322511474996733-1741134252801-1741134253249376604803.webp',
    sender: 'Vietcombank',
    senderType: 'BRANDNAME',
    text: 'UNG DUNG VCB DIGIBANK cua ban duoc PHAT HIEN KICH HOAT tren thiet bi la .Neu KHONG PHAI BAN KICH HOAT vui long bam vao https://vietcombank.vn-dii.vip de doi thiet bi hoac huy de tranh mat tai san',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-045B',
    imgId: 'SMS-IMG-045',
    file: 'tinnhanluadao1-1741070631435-17410706322511474996733-1741134252801-1741134253249376604803.webp',
    sender: 'TPBank',
    senderType: 'BRANDNAME',
    text: 'TPbank: Tran trong thong bao.Tai khoan cua quy khach hien tai da bi khoa.Dang nhap https://ebank.tbplik.com de xac thuc ngay hom nay.',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ACCOUNT_LOCKED'
  },
  {
    id: 'SMS-CASE-046',
    imgId: 'SMS-IMG-046',
    file: 'tinnhanrac.jpg',
    sender: '+841657197888',
    senderType: 'PHONE_DOMESTIC',
    text: 'Anh khong can biet toi la ai nhung toi biet anh. Va toi con biet ca vo anh khong don gian nhu nhung gi anh nghi. Toi khuyen anh nen lam xet nghiem ADN vi toi biet vo anh da lam nhung viec gi truoc luc co em be.',
    expectedLabel: 'SUSPICIOUS',
    expectedRisk: 'UNKNOWN',
    category: 'BLACKMAIL_EXTORTION'
  },
  {
    id: 'SMS-CASE-047',
    imgId: 'SMS-IMG-047',
    file: 'viber-image-2022-10-02-08-05-16-472-4397.jpg',
    sender: 'Techcombank',
    senderType: 'BRANDNAME',
    text: 'Tai khoan cua ban da dang ky chuong trinh quang cao tren TikTok, moi thang thu phi 3,600,000VND. Vui long vao https://techcombank.vn-iy.life de kiem tra hoac de huy',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-048',
    imgId: 'SMS-IMG-048',
    file: 'vietinbanh-1618502999028.webp',
    sender: 'VietinBanh',
    senderType: 'BRANDNAME',
    text: 'Chung toi phat hien tai khoan cua ban dang tieu dung o nuoc ngoai .Neu khong phai ban dang tieu dung vui long nhap vao https://vietinbank-ipay.com de huy thanh toan',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_UNSOLICITED_FEE'
  },
  {
    id: 'SMS-CASE-049',
    imgId: 'SMS-IMG-049',
    file: 'vietstock_s_cong-an-chi-cach-nhan-dien-link-lua-dao-qua-tin-nhan-sms_20220609061022.png',
    sender: 'Unknown',
    senderType: 'PHONE_DOMESTIC',
    text: 'Phat hien tai khoan cua ban dang n\'hap khac vung bat thuong ,vui l0ng www.smartbiddv.com de xac nhan thaong tin va thay doi mat k\'hau',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'BANK_ANOMALOUS_LOGIN'
  },
  {
    id: 'SMS-CASE-050',
    imgId: 'SMS-IMG-050',
    file: 'vietnampost-vov1-don-hang.png',
    sender: 'VIETNAMPOST',
    senderType: 'BRANDNAME',
    text: 'Đơn hàng số VN99876395512 của bạn đã đến kho nhưng không thể giao do địa chỉ không đầy đủ. Cập nhật https://vietteltelecomshop.cfd/vn',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'DELIVERY_PARCEL_SCAM'
  },
  {
    id: 'SMS-CASE-051',
    imgId: 'SMS-IMG-051',
    file: 'vietnampost-ocr-truncated.png',
    sender: 'VIETNAMPOST',
    senderType: 'BRANDNAME',
    text: 'bạn đã đến kho nhưng không thể giao do địa chỉ không đầy đủ. Cập nhật https://',
    expectedLabel: 'SCAM_CONFIRMED',
    expectedRisk: 'HIGH',
    category: 'DELIVERY_PARCEL_SCAM'
  }
];

function runSuite() {
  console.log('================================================================');
  console.log('🔍 SCAMSHIELD — BASELINE REGRESSION RUN (REAL SMS DATASET)');
  console.log(`Tổng số kịch bản thực tế: ${testCases.length} cases`);
  console.log('================================================================\n');

  let pass = 0, fn = 0, fp = 0, insuff = 0;
  const failureDetails = [];

  testCases.forEach(tc => {
    const res = analyzeMessage(tc.text, tc.sender, tc.senderType);
    let outcome = 'PASS';

    if (tc.expectedRisk === 'HIGH') {
      if (res.userRiskLevel === 'LOW') {
        outcome = 'FALSE_NEGATIVE';
        fn++;
        failureDetails.push({ ...tc, actualRisk: res.userRiskLevel, score: res.finalScore, reason: 'Missed HIGH risk' });
      } else if (res.userRiskLevel === 'UNKNOWN') {
        outcome = 'INSUFFICIENT_DETECTION';
        insuff++;
        failureDetails.push({ ...tc, actualRisk: res.userRiskLevel, score: res.finalScore, reason: 'Expected HIGH, got UNKNOWN' });
      } else {
        pass++;
      }
    } else if (tc.expectedRisk === 'LOW') {
      if (res.userRiskLevel !== 'LOW') {
        outcome = 'FALSE_POSITIVE';
        fp++;
        failureDetails.push({ ...tc, actualRisk: res.userRiskLevel, score: res.finalScore, reason: 'Benign flagged as risk' });
      } else {
        pass++;
      }
    } else if (tc.expectedRisk === 'UNKNOWN') {
      if (res.userRiskLevel === 'UNKNOWN') {
        pass++;
      } else if (res.userRiskLevel === 'LOW') {
        outcome = 'INSUFFICIENT_DETECTION';
        insuff++;
        failureDetails.push({ ...tc, actualRisk: res.userRiskLevel, score: res.finalScore, reason: 'Expected UNKNOWN, got LOW' });
      } else if (res.userRiskLevel === 'HIGH') {
        outcome = 'FALSE_POSITIVE';
        fp++;
        failureDetails.push({ ...tc, actualRisk: res.userRiskLevel, score: res.finalScore, reason: 'Ambiguous flagged as HIGH' });
      }
    }

    const tag = outcome === 'PASS' ? '✅ [PASS]' : (outcome === 'FALSE_NEGATIVE' ? '❌ [FN]  ' : '⚠️ [' + outcome.substring(0, 4) + ']');
    console.log(`${tag} ${tc.id.padEnd(14)} | Cat: ${tc.category.padEnd(25)} | Exp: ${tc.expectedRisk.padEnd(7)} | Pred: ${res.userRiskLevel.padEnd(7)} (Score: ${res.finalScore.toString().padStart(3)}đ, Rules: [${res.matchedRules.join(',')}])`);
  });

  console.log('\n================================================================');
  console.log('📊 TỔNG KẾT METRICS:');
  console.log(`• Tổng số ca : ${testCases.length}`);
  console.log(`• PASS        : ${pass} (${(pass / testCases.length * 100).toFixed(2)}%)`);
  console.log(`• FALSE_NEG   : ${fn} (${(fn / testCases.length * 100).toFixed(2)}%)`);
  console.log(`• FALSE_POS   : ${fp} (${(fp / testCases.length * 100).toFixed(2)}%)`);
  console.log(`• INSUFFICIENT: ${insuff} (${(insuff / testCases.length * 100).toFixed(2)}%)`);
  console.log('================================================================\n');

  return { total: testCases.length, pass, fn, fp, insuff, failureDetails };
}

if (require.main === module) {
  runSuite();
}

module.exports = { testCases, runSuite };
