import tls from "tls";
import dns from "dns/promises";
import net from "net";
import http from "http";

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const host = url.searchParams.get("host");
  const port = Number(url.searchParams.get("port") || 443);

  res.setHeader("content-type", "application/json");
  res.setHeader("access-control-allow-origin", "*");

  if (!host) {
    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "Falta el parámetro 'host'" }));
  }

  try {
    const ips = await dns.resolve4(host);
    const ip = ips[0];

    const socket = tls.connect(
      { host, port, servername: host, timeout: 5000 },
      () => {
        const cert = socket.getPeerCertificate(true);

        if (!cert || !cert.valid_to) throw new Error("No se pudo obtener el certificado SSL.");

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isValidNow = validFrom <= now && now <= validTo;

        const data = {
          ip,
          host,
          port,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          days_remaining: daysRemaining,
          issuer: cert.issuer?.O || cert.issuer?.CN || null,
          subject: cert.subject?.CN || null,
          is_valid_now: isValidNow,
          has_https: true,
        };

        res.end(JSON.stringify(data, null, 2));
        socket.end();
      }
    );

    socket.on("error", (err) => {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: err.message, has_https: false }));
    });
  } catch (err) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message, has_https: false }));
  }
});

server.listen(process.env.PORT || 8080);
console.log("✅ SSL Checker API corriendo en puerto", process.env.PORT || 8080);
