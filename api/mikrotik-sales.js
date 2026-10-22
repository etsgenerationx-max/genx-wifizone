// api/mikrotik-sales.js — Vercel Serverless Function
// Récupère les ventes MikroTik via RouterOS API pour une annexe donnée
// Déployer dans le repo etsgenerationx-max/genx-wifizone à la racine sous /api/

import { createClient } from '@supabase/supabase-js';
import { RouterOSAPI } from 'node-routeros';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // clé service (pas anon) pour lire mikrotik_password
);

export default async function handler(req, res) {
  // CORS — autoriser l'app GENERATION X
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { annexe_id, month, day } = req.query;
  // month = "MMYYYY" ex: "102026"
  // day   = "YYYY-MM-DD" ex: "2026-10-15"
  // si aucun filtre: récupère tout (30 derniers jours implicitement via ?comment=mikhmon)

  if (!annexe_id) {
    return res.status(400).json({ error: 'Paramètre annexe_id requis' });
  }

  // 1. Lire les credentials MikroTik depuis Supabase
  const { data: annexe, error: dbErr } = await supabase
    .from('annexes')
    .select('id, name, mikrotik_host, mikrotik_port, mikrotik_user, mikrotik_password')
    .eq('id', annexe_id)
    .single();

  if (dbErr || !annexe) {
    return res.status(404).json({ error: 'Annexe introuvable', detail: dbErr?.message });
  }
  if (!annexe.mikrotik_host || !annexe.mikrotik_user) {
    return res.status(400).json({ error: 'MikroTik non configuré pour cette annexe' });
  }

  // 2. Connexion RouterOS API
  const conn = new RouterOSAPI({
    host:     annexe.mikrotik_host,
    port:     annexe.mikrotik_port || 8728,
    user:     annexe.mikrotik_user,
    password: annexe.mikrotik_password || '',
    timeout:  8000,  // 8s timeout (Vercel limit 10s)
    keepalive: false,
  });

  let sales = [];
  try {
    await conn.connect();

    // 3. Construire le filtre
    const channel = conn.openChannel();
    let params = {};
    if (month) {
      params['?owner'] = month;          // "102026"
    } else if (day) {
      params['?source'] = day;           // "2026-10-15"
    } else {
      params['?comment'] = 'mikhmon';    // toutes les ventes
    }

    const rawItems = await conn.write('/system/script/print', params);
    await conn.close();

    // 4. Parser le champ name: "date-|-time-|-user-|-price-|-...-|-...-|-...-|-profile-|-comment"
    for (const item of rawItems) {
      const name = item.name || '';
      if (!name.includes('-|-')) continue;  // pas une vente mikhmon

      const parts = name.split('-|-');
      if (parts.length < 4) continue;

      const price = parseInt(parts[3], 10);
      if (isNaN(price)) continue;

      sales.push({
        date:     parts[0] || item.source || '',   // "YYYY-MM-DD"
        time:     parts[1] || '',
        username: parts[2] || '',
        price:    price,
        profile:  parts[7] || '',
        comment:  parts[8] || '',
        month:    item.owner  || '',               // "MMYYYY"
        day:      item.source || '',               // "YYYY-MM-DD"
      });
    }

    // 5. Agréger par jour pour la section investisseur
    const byDay = {};
    for (const s of sales) {
      const d = s.date;
      if (!byDay[d]) byDay[d] = { date: d, count: 0, total: 0 };
      byDay[d].count++;
      byDay[d].total += s.price;
    }

    return res.status(200).json({
      ok:       true,
      annexe:   annexe.name,
      count:    sales.length,
      sales:    sales,
      byDay:    Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date)),
    });

  } catch (err) {
    try { await conn.close(); } catch(_) {}
    return res.status(500).json({
      error:   'Erreur connexion MikroTik',
      detail:  err.message,
    });
  }
}

export const config = {
  api: { bodyParser: false }
};
