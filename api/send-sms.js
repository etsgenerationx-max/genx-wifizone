// Vercel Serverless Function — Proxy SMS Africa's Talking
// Fichier : api/send-sms.js

export default async function handler(req, res) {
  // CORS — autorise uniquement ton domaine Vercel
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  // Preflight OPTIONS
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Méthode non autorisée" });
  }

  const { to, message, username } = req.body;

  if (!to || !message) {
    return res.status(400).json({ error: "Champs 'to' et 'message' requis" });
  }

  // Clé API lue depuis les variables d'environnement Vercel (jamais dans le code)
  const AT_KEY = process.env.AT_API_KEY;
  const AT_USERNAME = username || process.env.AT_USERNAME || "sandbox";

  if (!AT_KEY) {
    return res.status(500).json({ error: "Clé API Africa's Talking non configurée sur Vercel" });
  }

  try {
    const body = new URLSearchParams({
      username: AT_USERNAME,
      to,
      message,
    }).toString();

    const atResp = await fetch("https://api.africastalking.com/version1/messaging", {
      method: "POST",
      headers: {
        apiKey: AT_KEY,
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    const data = await atResp.json();
    return res.status(200).json(data);

  } catch (err) {
    return res.status(500).json({ error: err.message || "Erreur inconnue" });
  }
}
