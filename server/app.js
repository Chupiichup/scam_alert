/**
 * SCAMSHIELD BACKEND API & SERVER
 * Hosts:
 *  1. Client Simulator with On-Device OCR (/)
 *  2. Visual AST Rule Builder & CMS (/admin)
 *  3. Ingestion & Incident Hub API (/api/v1/...)
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const db = require('./db');
const notificationService = require('./notification_service');
const threatIntelService = require('./threat_intel_service');
const aiCopilotService = require('./ai_copilot_service');
const { checkMessage } = require('../scam_detector');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static paths
const ROOT_DIR = path.join(__dirname, '..');
const RULES_JSON_PATH = path.join(ROOT_DIR, 'scam_detection_rules.json');

// Serve client simulator
app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'index.html'));
});

// Serve Visual AST CMS
app.get('/admin', (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'admin_cms.html'));
});

// Serve static assets
app.use(express.static(ROOT_DIR));

// Live Detection API for Simulator & Mobile clients
app.post('/api/v1/detect', (req, res) => {
  try {
    const { text, sender, senderType, options } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Nội dung tin nhắn không được để trống' });
    }
    const result = checkMessage(text, sender || '', senderType || '', options || {});
    res.json({ status: 'SUCCESS', result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// P0: INGESTION ENDPOINT & INCIDENT HUB API
// ============================================================================

/**
 * Ingestion Endpoint: Records scam analysis and initiates Incident Hub event
 */
app.post('/api/v1/ingest/analysis', async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ error: 'Missing analysis payload' });
    }

    const result = await db.ingestAnalysis(payload);

    // If autoEscalate is requested and internal_severity is CRITICAL
    if (payload.auto_escalate && result.safety_event && payload.internal_severity === 'CRITICAL') {
      try {
        const escalationResult = await notificationService.dispatchEscalation(result.safety_event.id, {
          phone: payload.guardian_phone,
          name: payload.guardian_name
        });
        result.escalation = escalationResult;
      } catch (escErr) {
        console.error('[API] Auto-escalation error:', escErr.message);
        result.escalation_error = escErr.message;
      }
    }

    res.status(201).json({
      status: 'SUCCESS',
      data: result
    });
  } catch (err) {
    console.error('[API] Ingest analysis failed:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * Family Escalation Dispatcher: Triggers automated SMS / Carrier alert to guardian
 */
app.post('/api/v1/safety-events/:id/escalate', async (req, res) => {
  try {
    const eventId = req.params.id;
    const { phone, name } = req.body || {};

    const escalation = await notificationService.dispatchEscalation(eventId, {
      phone,
      name
    });

    res.json({
      status: 'SUCCESS',
      message: 'Family escalation dispatched successfully via carrier gateway',
      data: escalation
    });
  } catch (err) {
    console.error('[API] Escalation failed:', err);
    res.status(500).json({ error: 'Escalation Failed', message: err.message });
  }
});

/**
 * List Safety Events in Incident Hub
 */
app.get('/api/v1/safety-events', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '50', 10);
    const events = await db.listSafetyEvents(limit);
    res.json({
      status: 'SUCCESS',
      count: events.length,
      data: events
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Update Safety Event Resolution & User Action
 */
app.post('/api/v1/safety-events/:id/action', async (req, res) => {
  try {
    const eventId = req.params.id;
    const { action_type, notes } = req.body;

    const updated = await db.updateSafetyEvent(eventId, {
      event_status: 'RESOLVED',
      user_action_type: action_type || 'ACKNOWLEDGED_SAFE',
      user_action_taken_at: new Date().toISOString(),
      user_action_notes: notes || ''
    });

    if (!updated) {
      return res.status(404).json({ error: 'Safety event not found' });
    }

    res.json({
      status: 'SUCCESS',
      data: updated
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// P1: THREAT INTEL AUTOMATED SYNC & STATUS
// ============================================================================

app.get('/api/v1/threat-intel/status', (req, res) => {
  res.json(threatIntelService.getStatus());
});

app.post('/api/v1/threat-intel/sync', async (req, res) => {
  try {
    const summary = await threatIntelService.syncFeeds();
    res.json({
      status: 'SUCCESS',
      message: 'Threat intelligence synchronized from NCSC & Chongluadao feeds',
      data: summary
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// P1: VISUAL AST CMS - RULES MANAGEMENT API
// ============================================================================

app.get('/api/v1/rules', (req, res) => {
  try {
    const raw = fs.readFileSync(RULES_JSON_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    res.json({
      status: 'SUCCESS',
      count: (parsed.rules || []).length,
      data: parsed.rules || []
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read rules JSON', message: err.message });
  }
});

app.post('/api/v1/rules', (req, res) => {
  try {
    const { rules } = req.body;
    if (!Array.isArray(rules)) {
      return res.status(400).json({ error: 'Rules must be an array' });
    }

    // Backup current rules
    const backupPath = path.join(ROOT_DIR, `scam_detection_rules.backup_${Date.now()}.json`);
    fs.copyFileSync(RULES_JSON_PATH, backupPath);

    // Save updated rules
    fs.writeFileSync(RULES_JSON_PATH, JSON.stringify({ rules }, null, 2), 'utf8');

    res.json({
      status: 'SUCCESS',
      message: `Đã lưu và xuất bản thành công ${rules.length} quy tắc AST!`,
      backup_created: path.basename(backupPath)
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update rules', message: err.message });
  }
});

// ============================================================================
// STATS & POSTGRESQL DUMP EXPORT
// ============================================================================

app.get('/api/v1/stats', async (req, res) => {
  try {
    const stats = await db.getStats();
    res.json({
      status: 'SUCCESS',
      data: stats
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/export/sql', (req, res) => {
  try {
    const sql = db.exportSqlDump();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="scamshield_runtime_export.sql"');
    res.send(sql);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// AI COPILOT THREAT RADAR & CRAWLER API
// ============================================================================

// Get list of configured sources
app.get('/api/v1/copilot/sources', (req, res) => {
  try {
    const sources = aiCopilotService.getSources();
    res.json({ status: 'SUCCESS', count: sources.length, sources });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add new source
app.post('/api/v1/copilot/sources', (req, res) => {
  try {
    const newSrc = aiCopilotService.addSource(req.body);
    res.status(201).json({ status: 'SUCCESS', message: 'Đã thêm nguồn cào mới!', source: newSrc });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update source (e.g. interval, enable/disable, target)
app.put('/api/v1/copilot/sources/:id', (req, res) => {
  try {
    const updated = aiCopilotService.updateSource(req.params.id, req.body);
    if (!updated) {
      return res.status(404).json({ error: 'Source not found' });
    }
    res.json({ status: 'SUCCESS', message: 'Đã cập nhật nguồn cào!', source: updated });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete source
app.delete('/api/v1/copilot/sources/:id', (req, res) => {
  try {
    const ok = aiCopilotService.deleteSource(req.params.id);
    if (!ok) {
      return res.status(404).json({ error: 'Source not found' });
    }
    res.json({ status: 'SUCCESS', message: 'Đã xóa nguồn cào!' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Trigger crawl for a single source
app.post('/api/v1/copilot/sources/:id/crawl', async (req, res) => {
  try {
    const result = await aiCopilotService.crawlSource(req.params.id);
    res.json({ status: 'SUCCESS', result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trigger crawl for all active sources
app.post('/api/v1/copilot/crawl-all', async (req, res) => {
  try {
    const results = await aiCopilotService.crawlAllSources();
    res.json({ status: 'SUCCESS', results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get draft rule proposals
app.get('/api/v1/copilot/proposals', (req, res) => {
  try {
    const status = req.query.status || null;
    const proposals = aiCopilotService.getProposals(status);
    res.json({ status: 'SUCCESS', count: proposals.length, proposals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Approve a proposal (Deploy to scam_detection_rules.json with 0% FPR guarantee)
app.post('/api/v1/copilot/proposals/:id/approve', (req, res) => {
  try {
    const result = aiCopilotService.approveProposal(req.params.id);
    res.json({ status: 'SUCCESS', message: 'Đã duyệt và xuất bản Cây AST vào Engine!', result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Reject a proposal
app.post('/api/v1/copilot/proposals/:id/reject', (req, res) => {
  try {
    const reason = req.body.reason || 'Admin từ chối';
    const result = aiCopilotService.rejectProposal(req.params.id, reason);
    res.json({ status: 'SUCCESS', message: 'Đã từ chối bản thảo.', result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Custom Text/Link Synthesizer (Instant Sandbox)
app.post('/api/v1/copilot/synthesize-custom', async (req, res) => {
  try {
    const { title, content, url } = req.body;
    if (!content) {
      return res.status(400).json({ error: 'Nội dung phân tích không được để trống!' });
    }
    const proposal = await aiCopilotService.synthesizeCustomText({ title, content, url });
    res.json({ status: 'SUCCESS', proposal });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Threat Intel Automated 30-min sync on server startup
threatIntelService.startAutomatedSync();

// Start Server
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================================`);
    console.log(`🛡️  SCAMSHIELD BACKEND API & PLATFORM SẴN SÀNG!`);
    console.log(`- 📱 Simulator (Mobile & Desktop): http://localhost:${PORT}`);
    console.log(`- 🌳 Visual AST Rule CMS          : http://localhost:${PORT}/admin`);
    console.log(`- 📡 Ingestion API Endpoint       : http://localhost:${PORT}/api/v1/ingest/analysis`);
    console.log(`- 🚨 Incident Hub Events          : http://localhost:${PORT}/api/v1/safety-events`);
    console.log(`- 🔄 30-Min Threat Intel Feed     : Active (Syncing NCSC/ChốngLừaĐảo)`);
    console.log(`========================================================\n`);
  });
}

module.exports = app;
