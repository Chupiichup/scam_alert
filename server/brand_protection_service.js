/**
 * BRAND PROTECTION DIRECTORY & MATCHING SERVICE
 * Quản lý danh bạ thương hiệu được bảo vệ (Whitelisted Official Assets)
 * & Thuật toán đối soát mạo danh thương hiệu (Typosquatting, Homoglyph, Combosquatting, SMS Brand Spoofing)
 */

const fs = require('fs');
const path = require('path');

const BRANDS_JSON_PATH = path.join(__dirname, '..', 'data', 'protected_brands.json');

// Helper: Levenshtein Distance
function levenshteinDistance(a, b) {
  if (!a || !b) return (a || b || '').length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Helper: Confusable String Normalization
function normalizeConfusable(str) {
  if (!str) return '';
  return str
    .toLowerCase()
    .replace(/[0]/g, 'o')
    .replace(/[1!|]/g, 'i')
    .replace(/l/g, 'i')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a');
}

// Helper: Clean Hostname from URL
function cleanHostname(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
    return parsed.hostname.toLowerCase();
  } catch (e) {
    return url.replace(/https?:\/\//i, '').split('/')[0].split('?')[0].split('#')[0].toLowerCase();
  }
}

class BrandProtectionService {
  constructor() {
    this.brands = [];
    this.brandMapById = new Map();
    this.brandMapByCode = new Map();
    this.loadBrands();
  }

  loadBrands() {
    try {
      if (fs.existsSync(BRANDS_JSON_PATH)) {
        const raw = fs.readFileSync(BRANDS_JSON_PATH, 'utf8');
        this.brands = JSON.parse(raw);
      } else {
        this.brands = [];
      }
    } catch (err) {
      console.error('[BRAND-PROTECTION] Lỗi khi nạp protected_brands.json:', err.message);
      this.brands = [];
    }

    this.brandMapById.clear();
    this.brandMapByCode.clear();
    for (const b of this.brands) {
      this.brandMapById.set(b.id, b);
      if (b.code) this.brandMapByCode.set(b.code.toUpperCase(), b);
    }
  }

  saveBrands() {
    fs.writeFileSync(BRANDS_JSON_PATH, JSON.stringify(this.brands, null, 2), 'utf8');
    this.loadBrands();
  }

  getAll(filter = {}) {
    let list = [...this.brands];
    if (filter.category && filter.category !== 'ALL') {
      list = list.filter(b => b.category === filter.category);
    }
    if (filter.risk_tier && filter.risk_tier !== 'ALL') {
      list = list.filter(b => b.risk_tier === filter.risk_tier);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase().trim();
      list = list.filter(b =>
        b.name.toLowerCase().includes(q) ||
        b.code.toLowerCase().includes(q) ||
        (b.aliases || []).some(a => a.toLowerCase().includes(q)) ||
        (b.official_domains || []).some(d => d.toLowerCase().includes(q))
      );
    }
    return list;
  }

  getById(id) {
    return this.brandMapById.get(id) || null;
  }

  create(brandData) {
    if (!brandData.id) {
      brandData.id = `BRAND_${(brandData.code || Date.now().toString()).toUpperCase().replace(/[^A-Z0-9_]/g, '')}`;
    }
    if (this.brandMapById.has(brandData.id)) {
      throw new Error(`Thương hiệu với ID "${brandData.id}" đã tồn tại!`);
    }

    const newBrand = {
      id: brandData.id,
      name: brandData.name || 'Thương hiệu chưa đặt tên',
      code: (brandData.code || '').toUpperCase(),
      category: brandData.category || 'OTHER',
      risk_tier: brandData.risk_tier || 'TIER_2',
      aliases: Array.isArray(brandData.aliases) ? brandData.aliases : (brandData.aliases ? brandData.aliases.split(',').map(s => s.trim().toLowerCase()) : []),
      official_domains: Array.isArray(brandData.official_domains) ? brandData.official_domains : (brandData.official_domains ? brandData.official_domains.split(',').map(s => s.trim().toLowerCase()) : []),
      official_brandnames: Array.isArray(brandData.official_brandnames) ? brandData.official_brandnames : (brandData.official_brandnames ? brandData.official_brandnames.split(',').map(s => s.trim()) : []),
      official_hotlines: Array.isArray(brandData.official_hotlines) ? brandData.official_hotlines : (brandData.official_hotlines ? brandData.official_hotlines.split(',').map(s => s.trim()) : []),
      app_identifiers: Array.isArray(brandData.app_identifiers) ? brandData.app_identifiers : [],
      keywords_patterns: Array.isArray(brandData.keywords_patterns) ? brandData.keywords_patterns : []
    };

    this.brands.push(newBrand);
    this.saveBrands();
    return newBrand;
  }

  update(id, updateData) {
    const idx = this.brands.findIndex(b => b.id === id);
    if (idx === -1) {
      throw new Error(`Không tìm thấy thương hiệu với ID "${id}"`);
    }

    const current = this.brands[idx];
    this.brands[idx] = {
      ...current,
      ...updateData,
      id: current.id // ID cannot change
    };

    this.saveBrands();
    return this.brands[idx];
  }

  delete(id) {
    const idx = this.brands.findIndex(b => b.id === id);
    if (idx === -1) {
      throw new Error(`Không tìm thấy thương hiệu với ID "${id}"`);
    }
    const removed = this.brands.splice(idx, 1)[0];
    this.saveBrands();
    return removed;
  }

  getStats() {
    const totalBrands = this.brands.length;
    let totalOfficialDomains = 0;
    let totalBrandnames = 0;
    const categoryCounts = {};
    const riskTierCounts = {};

    for (const b of this.brands) {
      totalOfficialDomains += (b.official_domains || []).length;
      totalBrandnames += (b.official_brandnames || []).length;
      categoryCounts[b.category] = (categoryCounts[b.category] || 0) + 1;
      riskTierCounts[b.risk_tier] = (riskTierCounts[b.risk_tier] || 0) + 1;
    }

    return {
      totalBrands,
      totalOfficialDomains,
      totalBrandnames,
      categoryCounts,
      riskTierCounts,
      lastUpdated: new Date().toISOString()
    };
  }

  /**
   * CORE CROSS-CHECK MATCHER: Đối soát tên miền với danh bạ thương hiệu
   */
  checkDomain(url) {
    if (!url) return null;
    const host = cleanHostname(url);
    if (!host) return null;

    // Check IDN Punycode
    if (host.includes('xn--')) {
      return {
        isMalicious: true,
        type: 'PUNYCODE_IDN_HOMOGRAPH',
        host,
        brand: 'UNKNOWN',
        risk_score: 95,
        detail: `Tên miền "${host}" sử dụng mã hóa Punycode (xn--) để ngụy trang ký tự đồng hình quốc tế`
      };
    }

    // Check Non-ASCII Cyrillic
    if (/[^\x00-\x7F]/.test(host)) {
      return {
        isMalicious: true,
        type: 'CYRILLIC_HOMOGLYPH',
        host,
        brand: 'UNKNOWN',
        risk_score: 95,
        detail: `Tên miền "${host}" trộn lẫn ký tự phi Latin (Cyrillic/Greek) để đánh lừa mắt người`
      };
    }

    // Extract Second-Level Domain (SLD)
    const hostParts = host.split('.');
    let sld = hostParts[0];
    if (hostParts.length >= 3 && ['com', 'edu', 'gov', 'org', 'net'].includes(hostParts[hostParts.length - 2])) {
      sld = hostParts[hostParts.length - 3];
    } else if (hostParts.length >= 2) {
      sld = hostParts[hostParts.length - 2];
    }

    const confusableSld = normalizeConfusable(sld);

    for (const brand of this.brands) {
      // 1. Is it an official whitelisted domain?
      const isOfficial = (brand.official_domains || []).some(od => host === od || host.endsWith('.' + od));
      if (isOfficial) {
        return {
          isOfficial: true,
          brand: brand.name,
          brandId: brand.id,
          code: brand.code,
          category: brand.category,
          host,
          detail: `Tên miền chính thức của ${brand.name}`
        };
      }

      // Check all brand aliases & main codes
      const candidateTokens = [brand.code.toLowerCase(), ...(brand.aliases || [])].filter(t => t.length >= 3);

      for (const token of candidateTokens) {
        const normToken = token.replace(/[^a-z0-9]/g, '');
        if (normToken.length < 3) continue;

        // A. Direct Subdomain / Path Spoofing (e.g. vietcombank.xac-thuc-otp.xyz)
        if (host.includes(normToken)) {
          return {
            isMalicious: true,
            type: 'SUBDOMAIN_BRAND_SPOOF',
            host,
            brand: brand.name,
            brandId: brand.id,
            code: brand.code,
            risk_score: brand.risk_tier === 'TIER_1' ? 98 : 85,
            detail: `Tên miền "${host}" chèn từ khóa thương hiệu "${brand.name}" (${normToken}) nhưng KHÔNG thuộc máy chủ chính thức!`
          };
        }

        // B. Levenshtein Distance === 1 (Typosquatting)
        const dist = levenshteinDistance(sld, normToken);
        if (dist === 1 && sld !== normToken) {
          return {
            isMalicious: true,
            type: 'TYPOSQUATTING_LEVENSHTEIN_1',
            host,
            brand: brand.name,
            brandId: brand.id,
            code: brand.code,
            sld,
            risk_score: brand.risk_tier === 'TIER_1' ? 95 : 85,
            detail: `Tên miền "${host}" giả mạo thương hiệu "${brand.name}" sai lệch 1 ký tự (${sld} thay vì ${normToken})`
          };
        }

        // C. Visual Confusable Match (0 vs o, rn vs m, l vs i)
        const confusableToken = normalizeConfusable(normToken);
        if (confusableSld === confusableToken && sld !== normToken) {
          return {
            isMalicious: true,
            type: 'VISUAL_CONFUSABLE_MATCH',
            host,
            brand: brand.name,
            brandId: brand.id,
            code: brand.code,
            sld,
            risk_score: brand.risk_tier === 'TIER_1' ? 95 : 85,
            detail: `Tên miền "${host}" dùng ký tự đồng hình thị giác để nhái thương hiệu "${brand.name}"`
          };
        }
      }
    }

    return null;
  }

  /**
   * SENDER AUDIT: Kiểm tra người gửi có mạo danh thương hiệu hay không
   */
  checkSender(senderRaw, senderType = '', content = '') {
    if (!senderRaw) return null;
    const normSender = senderRaw.trim();
    const isDomesticPhone = normSender.startsWith('+84') || /^0\d{9,10}$/.test(normSender);

    for (const brand of this.brands) {
      // 1. Check if sender brandname is legitimate
      const isOfficialBrandname = (brand.official_brandnames || []).some(ob => ob.toLowerCase() === normSender.toLowerCase());
      if (isOfficialBrandname) {
        return {
          isOfficial: true,
          brand: brand.name,
          brandId: brand.id,
          senderRaw,
          detail: `Brandname chính thống của ${brand.name} đã được cấp phép`
        };
      }

      // 2. Check if a personal mobile number claims to be from a Protected Brand (especially TIER_1 Banks/Gov)
      if (isDomesticPhone) {
        const lowerContent = (content || '').toLowerCase();
        const matchesBrand = (brand.aliases || []).some(a => lowerContent.includes(a.toLowerCase())) ||
                             (brand.official_brandnames || []).some(b => lowerContent.includes(b.toLowerCase()));

        if (matchesBrand && (brand.risk_tier === 'TIER_1' || brand.risk_tier === 'TIER_2')) {
          return {
            isMalicious: true,
            type: 'PERSONAL_PHONE_IMPERSONATING_BRAND',
            brand: brand.name,
            brandId: brand.id,
            senderRaw,
            risk_score: brand.risk_tier === 'TIER_1' ? 95 : 85,
            detail: `Số điện thoại cá nhân (${senderRaw}) tự xưng/mạo danh cơ quan/thương hiệu "${brand.name}". Cơ quan chính thống không bao giờ dùng SIM cá nhân gửi tin nhắn nghiệp vụ!`
          };
        }
      }

      // 3. Sender is a Brandname but slightly misspelled (BTS Spoofing attack)
      if (!isDomesticPhone) {
        const brandTokens = [brand.code.toLowerCase(), ...(brand.aliases || [])].filter(t => t.length >= 3);
        for (const token of brandTokens) {
          const dist = levenshteinDistance(normSender.toLowerCase(), token);
          if (dist === 1 && normSender.toLowerCase() !== token) {
            return {
              isMalicious: true,
              type: 'SPOOFED_BRANDNAME_BTS',
              brand: brand.name,
              brandId: brand.id,
              senderRaw,
              risk_score: 98,
              detail: `Brandname "${senderRaw}" giả mạo trạm BTS thương hiệu "${brand.name}" sai lệch ký tự`
            };
          }
        }
      }
    }

    return null;
  }

  /**
   * VERIFY TARGET: Kiểm tra toàn diện 1 URL hoặc Tin nhắn
   */
  verifyTarget({ url, sender, content }) {
    const results = {
      timestamp: new Date().toISOString(),
      urlResult: null,
      senderResult: null,
      isFlagged: false,
      overallRisk: 'SAFE',
      alerts: []
    };

    if (url) {
      results.urlResult = this.checkDomain(url);
      if (results.urlResult && results.urlResult.isMalicious) {
        results.isFlagged = true;
        results.alerts.push(results.urlResult.detail);
      }
    }

    if (sender) {
      results.senderResult = this.checkSender(sender, '', content || '');
      if (results.senderResult && results.senderResult.isMalicious) {
        results.isFlagged = true;
        results.alerts.push(results.senderResult.detail);
      }
    }

    if (results.isFlagged) {
      results.overallRisk = 'CRITICAL_IMPERSONATION';
    } else if (results.urlResult && results.urlResult.isOfficial) {
      results.overallRisk = 'VERIFIED_OFFICIAL';
    }

    return results;
  }

  /**
   * Export to light client array format compatible with index.html & test_rule_engine.js
   */
  toClientArray() {
    return this.brands.map(b => ({
      brand: b.code.toLowerCase(),
      name: b.name,
      official: b.official_domains || []
    }));
  }
}

const brandProtectionService = new BrandProtectionService();
module.exports = brandProtectionService;
