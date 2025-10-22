import express from "express";
import cors from "cors";
import sslChecker from "ssl-checker";
import dns from "dns/promises";

const app = express();
app.use(cors());

app.get("/", async (req, res) => {
  const host = req.query.host;
  const port = Number(req.query.port) || 443;

  if (!host) {
    return res.status(400).json({ error: "Falta el parámetro 'host'" });
  }

  try {
    // Resolver IP
    const ips = await dns.lookup(host, { all: true });
    const ip = ips[0]?.address || null;

    // Obtener datos SSL
    const sslData = await sslChecker(host, { method: "GET", port });

    return res.json({
      host,
      ip,
      port,
      valid_from: sslData.valid_from,
      valid_to: sslData.valid_to,
      days_remaining: sslData.days_remaining,
      valid: sslData.valid,
      issuer: sslData.issuer,
      subject: sslData.subject,
      has_https: sslData.valid,
    });
  } catch (err) {
    return res.status(500).json({
      error: err.message,
      has_https: false,
    });
  }
});

const portServer = process.env.PORT || 8080;
app.listen(portServer, () => {
  console.log(`SSL Checker API corriendo en puerto ${portServer}`);
});
