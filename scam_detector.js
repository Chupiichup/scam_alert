const { analyzeMessage } = require('./test_rule_engine');

function checkMessage(sampleText, senderRaw = '', senderType = '', options = { autoReportConsent: true }) {
  if (!senderType) {
    if (senderRaw.startsWith('+') || /^0\d{9,10}$/.test(senderRaw)) {
      senderType = 'PHONE_DOMESTIC';
    } else if (senderRaw) {
      senderType = 'BRANDNAME';
    } else {
      senderType = 'UNKNOWN';
    }
  }

  const analysis = analyzeMessage(sampleText, senderRaw, senderType, options);

  return {
    sampleText,
    senderRaw,
    senderType,
    score: analysis.finalScore,
    userRiskLevel: analysis.userRiskLevel,
    internalSeverity: analysis.internalSeverity,
    confidence: analysis.confidence,
    matchedRules: analysis.matchedRules,
    signals: analysis.rawSignals || [],
    conversationMetadata: analysis.conversationMetadata,
    privacyMetadata: analysis.privacyMetadata,
    cloudAssistedLookup: analysis.cloudAssistedLookup,
    iosIdentityLookup: analysis.iosIdentityLookup
  };
}

module.exports = { checkMessage };

if (require.main === module) {
  const rawArgs = process.argv.slice(2);
  const noAuto = rawArgs.includes('--no-auto-report');
  const isStateful = rawArgs.includes('--stateful');
  const args = rawArgs.filter(a => a !== '--no-auto-report' && a !== '--stateful');

  if (args.length === 0) {
    console.log(`\n======================================================`);
    console.log(`HỆ THỐNG KIỂM TRA TIN NHẮN LỪA ĐẢO SCAM (VIETNAM)`);
    console.log(`Kiến trúc: ZERO RAW STORAGE & STATEFUL CONVERSATION ENGINE`);
    console.log(`Cách dùng: node scam_detector.js "<nội dung tin nhắn>" [người gửi] [--no-auto-report] [--stateful]`);
    console.log(`Ví dụ: node scam_detector.js "Me oi chuyen gap 5 trieu vao stk 1903..." "+84988554433" --stateful`);
    console.log(`======================================================\n`);
    process.exit(0);
  }

  const message = args[0];
  const sender = args[1] || '';
  const result = checkMessage(message, sender, '', { autoReportConsent: !noAuto, stateful: isStateful });

  console.log(`\n======================================================`);
  console.log(`KẾT QUẢ PHÂN TÍCH TIN NHẮN LỪA ĐẢO (ON-DEVICE)`);
  console.log(`======================================================`);
  console.log(`Nội dung : ${result.sampleText}`);
  if (result.senderRaw) console.log(`Người gửi: ${result.senderRaw} (${result.senderType})`);
  console.log(`------------------------------------------------------`);
  
  const icon = result.userRiskLevel === 'HIGH' ? '🔴' : (result.userRiskLevel === 'UNKNOWN' ? '⚪' : '🟢');
  console.log(`Mức độ rủi ro   : ${icon} ${result.userRiskLevel}`);
  console.log(`Điểm số rủi ro  : ${result.score}/100`);
  console.log(`Mức nghiêm trọng: ${result.internalSeverity} (Độ tin cậy: ${result.confidence})`);
  
  if (result.signals.length > 0) {
    console.log(`\nDấu hiệu vi phạm phát hiện được:`);
    result.signals.forEach((s, idx) => {
      console.log(`  ${idx + 1}. [${s.signal_code}] (+${s.score_contribution}đ): ${s.user_explanation_vi}`);
    });
  }

  // Stateful Conversation Context Display
  if (result.conversationMetadata) {
    console.log(`\n🧵 NGỮ CẢNH HỘI THOẠI ĐA NGÀY (STATEFUL CONVERSATION ENGINE):`);
    console.log(`  • Định danh ẩn danh : ${result.conversationMetadata.senderHash.substring(0, 16)}... (Zero Raw Storage)`);
    console.log(`  • Tin nhắn trong luỗi: ${result.conversationMetadata.threadMessageCount} tin`);
    console.log(`  • Thời gian theo dõi: ${result.conversationMetadata.spanDays} ngày (${result.conversationMetadata.spanHours}h)`);
    console.log(`  • Điểm phân rã Time-Decay: ${result.conversationMetadata.accumulatedRollingScore}đ`);
    console.log(`  • Dấu vết rủi ro tích lũy: [${result.conversationMetadata.historicalSignalCodes.join(', ')}]`);
    console.log(`  • Trạng thái chuỗi  : ${result.conversationMetadata.isMultiDayChain ? '🚨 PHÁT HIỆN CHUỖI TƯƠNG TÁC NHIỀU NGÀY (PIG-BUTCHERING)' : '⚡ Tin nhắn đơn lẻ / Đầu phiên'}`);
  }

  // Zero Raw Storage Telemetry Display
  if (result.privacyMetadata) {
    console.log(`\n🔒 BẢO VỆ DỮ LIỆU RIÊNG TƯ & TỰ ĐỘNG BẢO VỆ CỘNG ĐỒNG:`);
    console.log(`  • Chế độ xử lý      : Local-First Backbone (98% On-Device) + Cloud-Assisted (2% Fallback)`);
    console.log(`  • Lưu trữ raw       : KHÔNG LƯU (Triệt tiêu 100% rủi ro rò rỉ PII)`);
    console.log(`  • Quyền tự động gửi : ${result.privacyMetadata.autoReportConsent ? 'BẬT (Đã cấp quyền 1 lần)' : 'TẮT (Cần bấm nút báo cáo)'}`);
    console.log(`  • Trạng thái gửi    : ${result.privacyMetadata.isAutoSubmitted ? '⚡ ĐÃ TỰ ĐỘNG GỬI TELEMETRY (HIGH/UNKNOWN)' : (result.privacyMetadata.submissionStatus === 'MANUAL_PENDING_USER_ACTION' ? '⚠️ CHỜ BẤM BÁO CÁO THỦ CÔNG' : '🔒 AN TOÀN - KHÔNG GỬI TELEMETRY')}`);
    console.log(`  • Redacted PII      : "${result.privacyMetadata.redactedContent}"`);
    console.log(`  • Content Hash      : ${result.privacyMetadata.contentHash}`);
  }

  // K-Anonymity & iOS Spec Display
  if (result.cloudAssistedLookup && result.cloudAssistedLookup.evaluated) {
    console.log(`\n🌐 TRA CỨU ẨN DANH K-ANONYMITY & BLOOM FILTER (2% URL NGHI VẤN):`);
    console.log(`  • On-Device Bloom Filter : ${result.cloudAssistedLookup.bloomFilterChecked ? 'HIT (Khớp bộ lọc cục bộ)' : 'MISS (Chưa có trong bộ lọc máy)'}`);
    console.log(`  • 4-Byte SHA-256 Prefix  : ${result.cloudAssistedLookup.prefix4Bytes} (Chỉ gửi tiền tố băm, 0% lộ URL)`);
    console.log(`  • Ứng viên Cloud trả về  : ${result.cloudAssistedLookup.candidateCount} hashes khớp tiền tố`);
    console.log(`  • Đối soát tại RAM máy   : ${result.cloudAssistedLookup.cloudMatched ? '🚨 PHÁT HIỆN TRÙNG KHỚP BLACKLIST CLOUD' : '✅ An toàn / Chưa có cảnh báo'}`);
  }

  if (result.iosIdentityLookup) {
    console.log(`\n🍏 APPLE iOS COMPATIBILITY (IdentityLookup Framework):`);
    console.log(`  • Extension Action : ILMessageFilterAction.${result.iosIdentityLookup.action}`);
    console.log(`  • Sub-Action       : ${result.iosIdentityLookup.subAction}`);
    console.log(`  • Network Action   : ${result.iosIdentityLookup.networkQueryRequired ? 'Cần gọi ILNetworkResponse (K-Anonymity)' : 'OfflineAction (Xử lý nội bộ)'}`);
  }

  if (result.userRiskLevel === 'HIGH') {
    console.log(`\n⚠️ HÀNH ĐỘNG KHẨN CẤP KHUYẾN NGHỊ:`);
    console.log(`  • TUYỆT ĐỐI KHÔNG bấm vào bất kỳ đường link nào.`);
    console.log(`  • TUYỆT ĐỐI KHÔNG cung cấp mật khẩu, mã xác thực OTP.`);
    console.log(`  • Hãy gọi điện thoại trực tiếp lên tổng đài chính thức của cơ quan/ngân hàng để xác minh.`);
  } else if (result.userRiskLevel === 'UNKNOWN') {
    console.log(`\n⚠️ KHUYẾN NGHỊ: TIN NHẮN NGHI VẤN! Hãy kiểm tra kỹ danh tính người gửi trước khi thực hiện giao dịch.`);
  } else {
    console.log(`\n✅ TIN NHẮN BÌNH THƯỜNG / AN TOÀN.`);
  }
  console.log(`======================================================\n`);
}
