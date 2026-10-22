// api/mikrotik-ping.js — Vercel Serverless Function
// Teste la connexion MikroTik avec des credentials passés directement en POST
// Utilisé par le bouton "Tester la connexion" dans la fiche succursale
// Les credentials ne sont PAS stockés ici, ils sont passés dans le body de la requête

import { RouterOSAPI } from 'node-routeros';

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, msg: 'Méthode non autorisée' });
  }

  let body = {};
  try {
    // Lire le body (bodyParser désactivé donc on le lit manuellement)
    const raw = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => { data += chunk; });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
    body = JSON.parse(raw);
  } catch (e) {
    return res.status(400).json({ ok: false, msg: 'Body JSON invalide' });
  }

  const { host, port, user, password } = body;

  if (!host || !user) {
    return res.status(400).json({ ok: false, msg: 'Hôte et identifiant requis' });
  }

  const conn = new RouterOSAPI({
    host:      host.trim(),
    port:      Number(port) || 8728,
    user:      user.trim(),
    password:  password || '',
    timeout:   8000,
    keepalive: false,
  });

  try {
    await conn.connect();

    // Commande légère : récupérer l'identité du routeur
    const identity = await conn.write('/system/identity/print');
    await conn.close();

    const name = identity?.[0]?.name || 'MikroTik';
    return res.status(200).json({
      ok:  true,
      msg: `Connecté — routeur : ${name}`,
    });

  } catch (err) {
    try { await conn.close(); } catch (_) {}

    // Identifier le type d'erreur
    const msg = err.message || '';
    let friendly = 'Connexion échouée';

    if (msg.includes('ECONNREFUSED'))  friendly = `Port ${port || 8728} refusé sur ${host}`;
    else if (msg.includes('ETIMEDOUT') || msg.includes('timeout')) friendly = `Délai dépassé — hôte injoignable : ${host}`;
    else if (msg.includes('ENOTFOUND')) friendly = `Hôte introuvable : ${host}`;
    else if (msg.includes('wrong credentials') || msg.includes('invalid user') || msg.includes('login failure')) friendly = 'Identifiant ou mot de passe incorrect';
    else if (msg.includes('ECONNRESET')) friendly = 'Connexion interrompue par le routeur';
    else friendly = msg;

    return res.status(200).json({  // 200 intentionnel : l'erreur est métier, pas HTTP
      ok:  false,
      msg: friendly,
    });
  }
}

export const config = {
  api: { bodyParser: false },
};
