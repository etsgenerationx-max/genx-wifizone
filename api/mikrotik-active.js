// api/mikrotik-active.js — Vercel Serverless Function (v1.8.5)
// Donne le NOMBRE D'UTILISATEURS CONNECTÉS sur les routeurs MikroTik.
// Appelée par l'agent "surveillant-mikhmon" (relevés de 12 h et 22 h), PAS par le navigateur.
//
// ⚠️ Protection désactivée tant qu'AGENT_API_TOKEN n'est pas défini dans Vercel.
//    Pour l'activer, il suffit d'ajouter la variable : aucun changement de code n'est nécessaire.
//    (Décision de DOS du 29/10/2026 : jeton facultatif pour l'instant, sécurité traitée plus tard.)
//
// Sécurité :
//   - si AGENT_API_TOKEN est défini (non vide) : en-tête obligatoire  x-agent-token  = AGENT_API_TOKEN
//   - comparaison à temps constant ; sans jeton valide → 401, sans contacter ni Supabase ni routeur
//   - si AGENT_API_TOKEN est absent ou vide : requête acceptée sans jeton
//   - pas d'en-têtes CORS (fonction non destinée au navigateur)
//   - la réponse ne contient JAMAIS l'adresse, le port, l'identifiant ni le mot de passe du routeur
//
// Lecture seule : uniquement des commandes "print" sur le routeur, uniquement un SELECT dans Supabase.
//
// Appel : GET /api/mikrotik-active?zone=<id de succursale>   ou   ?zone=all

import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { RouterOSAPI } from 'node-routeros';

// Délais (limite Vercel Hobby : 30 s). Les routeurs sont lus en parallèle,
// donc le pire cas ≈ lecture base (5 s) + un routeur (8 s) + fermeture (2 s) ≈ 15 s.
const DELAI_BASE_MS      = 5000;
const DELAI_ROUTEUR_MS   = 8000;
const DELAI_FERMETURE_MS = 2000;

// ─── Utilitaires ────────────────────────────────────────────────────────────

// La protection par jeton est active seulement si AGENT_API_TOKEN est défini et non vide.
function protectionActive() {
  const attendu = process.env.AGENT_API_TOKEN;
  return typeof attendu === 'string' && attendu.length > 0;
}

// Vérifie le jeton de l'agent, à temps constant.
// On compare les empreintes SHA-256 (toujours 32 octets) pour que timingSafeEqual
// reçoive deux tampons de même longueur, sans révéler la longueur du vrai jeton.
function jetonValide(req) {
  const attendu = process.env.AGENT_API_TOKEN;
  if (typeof attendu !== 'string' || attendu.length === 0) return false;

  let recu = req.headers ? req.headers['x-agent-token'] : undefined;
  if (Array.isArray(recu)) recu = recu[0];
  if (typeof recu !== 'string' || recu.length === 0) return false;

  const a = crypto.createHash('sha256').update(attendu, 'utf8').digest();
  const b = crypto.createHash('sha256').update(recu, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

// Rejette la promesse si elle ne se termine pas dans le délai.
function avecDelai(promesse, ms, code) {
  let minuteur;
  const limite = new Promise((_, reject) => {
    minuteur = setTimeout(() => {
      const e = new Error(code);
      e.code = code;
      reject(e);
    }, ms);
  });
  return Promise.race([promesse, limite]).finally(() => clearTimeout(minuteur));
}

// Extraire le port si inclus dans l'hôte (ex: "v10.mikroot.com:3884") — même règle que mikrotik-ping/sales.
function hoteEtPort(hoteBrut, portBrut) {
  let host = String(hoteBrut || '').trim();
  let port = Number(portBrut) || 8728;
  if (host.includes(':')) {
    const parts = host.split(':');
    const portFromHost = parseInt(parts[1], 10);
    if (!isNaN(portFromHost)) {
      host = parts[0];
      port = portFromHost; // priorité au port dans l'hôte
    }
  }
  return { host, port };
}

// Message d'erreur clair, SANS adresse ni port : on parle de la zone par son nom.
function messageErreur(err, nomZone) {
  const msg   = String((err && err.message) || '');
  const code  = String((err && (err.code || err.errno)) || '');
  const texte = (code + ' ' + msg).toLowerCase();

  if (code === 'DELAI_DEPASSE')                                   return `Délai dépassé (${DELAI_ROUTEUR_MS / 1000} s) — routeur injoignable : ${nomZone}`;
  if (texte.includes('econnrefused'))                             return `Connexion refusée par le routeur : ${nomZone} (port API fermé ?)`;
  if (texte.includes('etimedout') || texte.includes('socktmout') || texte.includes('timeout') || texte.includes('timed out'))
                                                                  return `Délai dépassé — routeur injoignable : ${nomZone}`;
  if (texte.includes('enotfound') || texte.includes('eai_again')) return `Adresse du routeur introuvable : ${nomZone}`;
  if (texte.includes('ehostunreach') || texte.includes('enetunreach')) return `Routeur hors réseau : ${nomZone}`;
  if (texte.includes('cantlogin') || texte.includes('cannot log in') || texte.includes('wrong credentials') ||
      texte.includes('invalid user') || texte.includes('login failure'))
                                                                  return `Identifiant ou mot de passe MikroTik incorrect : ${nomZone}`;
  if (texte.includes('econnreset') || texte.includes('closed'))  return `Connexion interrompue par le routeur : ${nomZone}`;
  if (texte.includes('no such command'))                          return `Commande non disponible sur ce routeur : ${nomZone}`;
  // Message inconnu : on ne le recopie pas (il pourrait contenir l'adresse du routeur).
  return `Lecture du routeur impossible : ${nomZone}`;
}

// Ferme la connexion sans jamais bloquer ni lever d'erreur.
async function fermer(conn) {
  if (!conn) return;
  try { await avecDelai(Promise.resolve().then(() => conn.close()), DELAI_FERMETURE_MS, 'FERMETURE'); }
  catch (_) { /* déjà fermée ou injoignable : rien à faire */ }
}

// ─── Lecture d'un routeur ───────────────────────────────────────────────────

async function lireRouteur(s) {
  const zone = s.id;
  const nom  = s.name || s.id;

  if (!s.mikrotik_host || !String(s.mikrotik_host).trim()) {
    return { zone, nom, ok: false, msg: `MikroTik non configuré pour cette zone : ${nom}` };
  }
  if (!s.mikrotik_user || !String(s.mikrotik_user).trim()) {
    return { zone, nom, ok: false, msg: `Identifiant MikroTik non renseigné : ${nom}` };
  }

  const { host, port } = hoteEtPort(s.mikrotik_host, s.mikrotik_port);
  let conn = null;

  try {
    conn = new RouterOSAPI({
      host:      host,
      port:      port,
      user:      String(s.mikrotik_user).trim(),
      password:  s.mikrotik_password || '',
      timeout:   8,       // node-routeros : en SECONDES
      keepalive: false,
    });
    // Évite qu'un événement 'error' non écouté fasse planter la fonction.
    if (typeof conn.on === 'function') conn.on('error', () => {});

    const travail = (async () => {
      await conn.connect();
      // UNIQUEMENT des commandes de lecture (print).
      const hotspot  = await conn.write('/ip/hotspot/active/print', ['=.proplist=server']);
      const ppp      = await conn.write('/ppp/active/print',        ['=.proplist=.id']);
      const ressource = await conn.write('/system/resource/print',  ['=.proplist=uptime,cpu-load']);
      return { hotspot, ppp, ressource };
    })();
    travail.catch(() => {}); // si le délai gagne, l'erreur tardive ne doit pas remonter

    const { hotspot, ppp, ressource } = await avecDelai(travail, DELAI_ROUTEUR_MS, 'DELAI_DEPASSE');

    // Détail par serveur hotspot
    const liste = Array.isArray(hotspot) ? hotspot : [];
    const compte = {};
    for (const item of liste) {
      const serveur = (item && item.server) ? String(item.server) : '(sans serveur)';
      compte[serveur] = (compte[serveur] || 0) + 1;
    }
    const par_serveur = Object.keys(compte)
      .map(serveur => ({ serveur, connectes: compte[serveur] }))
      .sort((a, b) => b.connectes - a.connectes || a.serveur.localeCompare(b.serveur));

    const res0 = (Array.isArray(ressource) && ressource[0]) ? ressource[0] : {};
    const cpu  = parseInt(res0['cpu-load'], 10);

    return {
      zone,
      nom,
      ok:            true,
      hotspot_total: liste.length,
      par_serveur,
      pppoe_total:   Array.isArray(ppp) ? ppp.length : 0,
      uptime:        res0.uptime ? String(res0.uptime) : null,
      cpu:           isNaN(cpu) ? null : cpu,
    };
  } catch (err) {
    // Journal Vercel : identifiant de zone et code d'erreur seulement (jamais l'hôte).
    console.error('[mikrotik-active]', zone, (err && (err.code || err.errno)) || 'erreur');
    return { zone, nom, ok: false, msg: messageErreur(err, nom) };
  } finally {
    await fermer(conn);
  }
}

// ─── Fonction principale ────────────────────────────────────────────────────

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  // Pas d'en-têtes CORS : cette fonction n'est pas appelée depuis le navigateur.

  // 1. Sécurité — AVANT tout accès à Supabase ou au routeur
  //    (jeton exigé seulement si AGENT_API_TOKEN est défini dans Vercel)
  if (protectionActive() && !jetonValide(req)) {
    return res.status(401).json({ ok: false, msg: 'Non autorisé' });
  }

  // 2. Méthode
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ ok: false, msg: 'Méthode non autorisée' });
  }

  // 3. Paramètre zone
  let zoneParam = req.query ? req.query.zone : undefined;
  if (Array.isArray(zoneParam)) zoneParam = zoneParam[0];
  zoneParam = typeof zoneParam === 'string' ? zoneParam.trim() : '';
  if (!zoneParam) {
    return res.status(400).json({ ok: false, msg: 'Paramètre zone requis (identifiant de succursale, ou all)' });
  }
  if (zoneParam !== 'all' && !/^[A-Za-z0-9_-]{1,64}$/.test(zoneParam)) {
    return res.status(400).json({ ok: false, msg: 'Paramètre zone invalide' });
  }

  // 4. Lire les identifiants MikroTik dans la table succursales (comme mikrotik-sales.js)
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ ok: false, msg: 'Configuration serveur incomplète' });
  }
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY, // clé service (pas anon) pour lire mikrotik_password
    { auth: { persistSession: false } }
  );

  let succursales = [];
  try {
    let requete = supabase
      .from('succursales')
      .select('id, name, mikrotik_host, mikrotik_port, mikrotik_user, mikrotik_password');

    if (zoneParam === 'all') {
      requete = requete.not('mikrotik_host', 'is', null).order('name', { ascending: true });
    } else {
      requete = requete.eq('id', zoneParam);
    }

    const { data, error } = await avecDelai(requete, DELAI_BASE_MS, 'DELAI_BASE');
    if (error) throw error;
    succursales = Array.isArray(data) ? data : [];
  } catch (err) {
    console.error('[mikrotik-active] lecture base', (err && err.code) || 'erreur');
    return res.status(500).json({ ok: false, msg: 'Lecture de la base impossible' });
  }

  if (zoneParam === 'all') {
    succursales = succursales.filter(s => s.mikrotik_host && String(s.mikrotik_host).trim());
  } else if (succursales.length === 0) {
    return res.status(404).json({ ok: false, msg: 'Succursale introuvable' });
  }

  // 5. Lecture des routeurs en PARALLÈLE
  const resultats = await Promise.allSettled(succursales.map(s => lireRouteur(s)));
  const zones = resultats.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const s = succursales[i];
    return { zone: s.id, nom: s.name || s.id, ok: false, msg: `Lecture du routeur impossible : ${s.name || s.id}` };
  });

  return res.status(200).json({
    ok:    true,
    lu_a:  new Date().toISOString(),
    zones,
  });
}

export const config = {
  maxDuration: 30, // Vercel Hobby : 30 s maximum
};
