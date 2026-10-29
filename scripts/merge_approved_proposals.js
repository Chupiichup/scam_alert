/**
 * MERGE APPROVED PROPOSALS INTO PRODUCTION RULES & PROTECTION DATASETS
 * Approved by User: 29/10/2026
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.join(__dirname, '..');
const RULES_PATH = path.join(ROOT_DIR, 'scam_detection_rules.json');
const EXPANSION_DATASET_PATH = path.join(ROOT_DIR, 'data', 'scam_scenario_expansion_dataset.json');
const PROTECTED_BRANDS_PATH = path.join(ROOT_DIR, 'data', 'protected_brands.json');
const URL_INDICATORS_PATH = path.join(ROOT_DIR, 'scam_url_domain_indicators.csv');

// 1. Merge 17 expansion rules into scam_detection_rules.json
const rulesData = JSON.parse(fs.readFileSync(RULES_PATH, 'utf8'));
const expansionData = JSON.parse(fs.readFileSync(EXPANSION_DATASET_PATH, 'utf8'));

const existingCodes = new Set(rulesData.rules.map(r => r.rule_code));
let addedCount = 0;

for (const propRule of expansionData.proposed_rules) {
  if (!existingCodes.has(propRule.rule_code)) {
    const approvedRule = { ...propRule, status: 'APPROVED' };
    rulesData.rules.push(approvedRule);
    existingCodes.add(propRule.rule_code);
    addedCount++;
    console.log(`[MERGE RULE] Added ${propRule.rule_code}: ${propRule.name}`);
  } else {
    console.log(`[SKIP RULE] ${propRule.rule_code} already exists.`);
  }
}

fs.writeFileSync(RULES_PATH, JSON.stringify(rulesData, null, 2), 'utf8');
console.log(`Successfully merged ${addedCount} new rules into ${RULES_PATH}. Total rules: ${rulesData.rules.length}\n`);

// 2. Add Sacombank (BRAND_STB) to data/protected_brands.json if missing
const brandsData = JSON.parse(fs.readFileSync(PROTECTED_BRANDS_PATH, 'utf8'));
const hasSacombank = brandsData.some(b => b.code === 'STB' || b.aliases.includes('sacombank'));

if (!hasSacombank) {
  const stbBrand = {
    id: 'BRAND_STB',
    name: 'Ngân hàng TMCP Sài Gòn Thương Tín (Sacombank)',
    code: 'STB',
    category: 'BANKING',
    risk_tier: 'TIER_1',
    aliases: [
      'sacombank',
      'stb',
      'ngan hang sai gon thuong tin',
      'sacom bank'
    ],
    official_domains: [
      'sacombank.com.vn',
      'sacombank.com'
    ],
    official_brandnames: [
      'Sacombank'
    ],
    official_hotlines: [
      '1900555588',
      '1800585888'
    ],
    app_identifiers: [
      'com.sacombank.mplus',
      'com.vnpay.sacombank'
    ],
    keywords_patterns: [
      'sacombank mbanking',
      'sacombank pay',
      'tai khoan sacombank'
    ]
  };
  brandsData.push(stbBrand);
  fs.writeFileSync(PROTECTED_BRANDS_PATH, JSON.stringify(brandsData, null, 2), 'utf8');
  console.log(`[ADD BRAND] Sacombank (BRAND_STB) added to ${PROTECTED_BRANDS_PATH}`);
} else {
  console.log(`[SKIP BRAND] Sacombank already present in ${PROTECTED_BRANDS_PATH}`);
}

// 3. Add vn-sacombank.com and i-vietcombank.com to scam_url_domain_indicators.csv if missing
let urlIndicators = fs.readFileSync(URL_INDICATORS_PATH, 'utf8');
let appendedDomains = 0;

if (!urlIndicators.includes('vn-sacombank.com')) {
  urlIndicators += '\nDOMAIN,https://vn-sacombank.com,vn-sacombank.com,SACOMBANK,PHISHING_BANK,MALICIOUS,95,false,false,OBSERVED,SRC-BNK-002';
  appendedDomains++;
  console.log('[ADD DOMAIN] vn-sacombank.com added to scam_url_domain_indicators.csv');
}

if (!urlIndicators.includes('i-vietcombank.com')) {
  urlIndicators += '\nDOMAIN,https://i-vietcombank.com,i-vietcombank.com,VCB,PHISHING_BANK,MALICIOUS,95,false,false,OBSERVED,SRC-BNK-001';
  appendedDomains++;
  console.log('[ADD DOMAIN] i-vietcombank.com added to scam_url_domain_indicators.csv');
}

if (appendedDomains > 0) {
  fs.writeFileSync(URL_INDICATORS_PATH, urlIndicators.trim() + '\n', 'utf8');
  console.log(`Appended ${appendedDomains} new malicious phishing domains to indicators.\n`);
}

console.log('Merge complete!');
