const app = require('./server/app');
const os = require('os');

const PORT = process.env.PORT || 8080;

function getLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

const localIp = getLocalIp();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`🛡️  SCAMSHIELD SUITE SẴN SÀNG!`);
  console.log(`- 📱 Simulator (Mobile & Desktop): http://localhost:${PORT}`);
  console.log(`- 📱 Trên điện thoại Z Flip5     : http://${localIp}:${PORT}`);
  console.log(`- 🌳 Visual AST Rule CMS (P1)    : http://localhost:${PORT}/admin`);
  console.log(`- 📡 Ingestion Endpoint (P0)     : http://localhost:${PORT}/api/v1/ingest/analysis`);
  console.log(`- 🚨 Incident Hub Events (P0)    : http://localhost:${PORT}/api/v1/safety-events`);
  console.log(`- 🔄 30-Min Threat Intel Feed    : Đang tự động kéo NCSC/ChốngLừaĐảo`);
  console.log(`====================================================`);
});

