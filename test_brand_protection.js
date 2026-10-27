/**
 * UNIT & INTEGRATION TEST SUITE: BRAND PROTECTION DIRECTORY & MATCHING ENGINE
 */

const brandProtectionService = require('./server/brand_protection_service');

console.log('================================================================');
console.log('🛡️  KIỂM THỬ HỆ THỐNG DANH BẠ THƯƠNG HIỆU CẦN BẢO VỆ (BRAND PROTECTION)');
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`✅ [PASS] ${message}`);
    passCount++;
  } else {
    console.error(`❌ [FAIL] ${message}`);
    failCount++;
  }
}

// 1. Kiểm tra tải dữ liệu danh bạ
console.log('--- 1. Kiểm tra cấu trúc & thống kê danh bạ ---');
const allBrands = brandProtectionService.getAll();
const stats = brandProtectionService.getStats();

assert(allBrands.length >= 40, `Đã nạp đủ danh bạ ${allBrands.length} thương hiệu lớn (Kỳ vọng >= 40)`);
assert(stats.totalOfficialDomains >= 80, `Đã lập Whitelist ${stats.totalOfficialDomains} tên miền chính thức (Kỳ vọng >= 80)`);
assert(stats.totalBrandnames >= 45, `Đã bảo vệ ${stats.totalBrandnames} SMS Brandname hợp pháp (Kỳ vọng >= 45)`);
assert(stats.riskTierCounts['TIER_1'] >= 20, `Nhận diện ${stats.riskTierCounts['TIER_1']} đơn vị Nguy cấp TIER 1 (Ngân hàng, DVC, Công an)`);

// 2. Kiểm tra nhận diện Tên miền chính thức (Whitelisted Official Domains)
console.log('\n--- 2. Kiểm tra tên miền chính thức (Whitelisted - Không cảnh báo nhầm) ---');
const vcbOfficial = brandProtectionService.checkDomain('https://vcbdigibank.vietcombank.com.vn/login');
assert(vcbOfficial && vcbOfficial.isOfficial === true, 'vietcombank.com.vn được xác nhận là tên miền chính thức');

const vneidOfficial = brandProtectionService.checkDomain('https://vneid.gov.vn');
assert(vneidOfficial && vneidOfficial.isOfficial === true, 'vneid.gov.vn được xác nhận là cổng DVC/VNeID chính thống');

const shopeeOfficial = brandProtectionService.checkDomain('https://shopee.vn/product/12345');
assert(shopeeOfficial && shopeeOfficial.isOfficial === true, 'shopee.vn được xác nhận là sàn TMĐT chính thức');

// 3. Kiểm tra phát hiện Tên miền mạo danh (Typosquatting & Subdomain Spoofing)
console.log('\n--- 3. Kiểm tra phát hiện Tên miền mạo danh (Phishing Detection) ---');
const vcbTypo = brandProtectionService.checkDomain('http://vietcombannk.com.vn');
assert(vcbTypo && vcbTypo.isMalicious === true, 'vietcombannk.com.vn bị bắt lỗi Typosquatting (sai 1 ký tự)');

const vcbSubdomainSpoof = brandProtectionService.checkDomain('http://vietcombank.xacminh-otp.xyz/security');
assert(vcbSubdomainSpoof && vcbSubdomainSpoof.isMalicious === true && vcbSubdomainSpoof.type === 'SUBDOMAIN_BRAND_SPOOF', 'vietcombank.xacminh-otp.xyz bị bắt lỗi mạo danh Subdomain');

const punycodeAttack = brandProtectionService.checkDomain('http://xn--vietcombnk-q4a.com');
assert(punycodeAttack && punycodeAttack.isMalicious === true && punycodeAttack.type === 'PUNYCODE_IDN_HOMOGRAPH', 'xn--vietcombnk-q4a.com bị chặn do sử dụng Punycode Homograph');

const csgtSpoof = brandProtectionService.checkDomain('http://phatnguoi-csgt-bocongan.top');
assert(csgtSpoof && csgtSpoof.isMalicious === true, 'phatnguoi-csgt-bocongan.top bị phát hiện chèn từ khóa CSGT ngoài hệ thống');

// 4. Kiểm tra Người gửi mạo danh (SIM Rác mạo danh Cơ quan / Ngân hàng)
console.log('\n--- 4. Kiểm tra Người gửi mạo danh (Sender Impersonation) ---');
const phoneImpersonatingVneid = brandProtectionService.checkSender(
  '+84912345678',
  'PHONE_DOMESTIC',
  'Can bo Cong an thong bao tai khoan VNeID cua ong ba can cap nhat gap so do dat dai.'
);
assert(phoneImpersonatingVneid && phoneImpersonatingVneid.isMalicious === true && phoneImpersonatingVneid.type === 'PERSONAL_PHONE_IMPERSONATING_BRAND', 'Bắt số di động cá nhân tự xưng cơ quan VNeID/Bộ Công An');

const officialBrandnameVCB = brandProtectionService.checkSender('VCB-Digibank', 'BRANDNAME', 'Thong bao bien dong so du');
assert(officialBrandnameVCB && officialBrandnameVCB.isOfficial === true, 'Xác nhận Brandname VCB-Digibank đã đăng ký hợp pháp');

// 5. Kiểm tra Verify Target (Toàn diện)
console.log('\n--- 5. Kiểm tra Verify Target API (Audit Toàn Diện) ---');
const fullAudit = brandProtectionService.verifyTarget({
  url: 'http://dichvucong-gov.online/phatnguoi.apk',
  sender: '+84988776655',
  content: 'Cuc CSGT yeu cau dong phi phat nguoi truc tuyen.'
});
assert(fullAudit.overallRisk === 'CRITICAL_IMPERSONATION', 'Target bị đánh giá mức rủi ro CRITICAL_IMPERSONATION');
assert(fullAudit.alerts.length >= 2, `Phát hiện đầy đủ ${fullAudit.alerts.length} vi phạm mạo danh đồng thời (URL + SIM rác)`);

// 6. Kiểm tra Thêm / Cập nhật / Xóa Thương hiệu
console.log('\n--- 6. Kiểm tra CRUD động ---');
const testBrand = brandProtectionService.create({
  name: 'Ngân hàng Thử Nghiệm Mock',
  code: 'MOCKBANK',
  category: 'BANKING',
  risk_tier: 'TIER_1',
  official_domains: ['mockbank.vn'],
  official_brandnames: ['MockBank']
});
assert(testBrand && testBrand.id === 'BRAND_MOCKBANK', 'Thêm thương hiệu mới thành công');

const updatedBrand = brandProtectionService.update('BRAND_MOCKBANK', {
  name: 'Ngân hàng Thử Nghiệm Mock Pro',
  official_domains: ['mockbank.vn', 'online.mockbank.vn']
});
assert(updatedBrand.name === 'Ngân hàng Thử Nghiệm Mock Pro' && updatedBrand.official_domains.length === 2, 'Cập nhật thương hiệu thành công');

const deletedBrand = brandProtectionService.delete('BRAND_MOCKBANK');
assert(deletedBrand && deletedBrand.id === 'BRAND_MOCKBANK', 'Xóa thương hiệu mock thành công');

console.log('\n================================================================');
console.log(`TỔNG KẾT KIỂM THỬ: ${passCount} PASS | ${failCount} FAIL`);
console.log('================================================================\n');

if (failCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
