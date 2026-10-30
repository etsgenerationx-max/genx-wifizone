// api/mikrotik-active.js — Vercel Serverless Function (v1.8.6)
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

// Délais (limite Vercel maxDuration : 30 s). Les routeurs sont lus en parallèle.
// v1.8.6 : le VPN mikroot est lent, le 1er essai échoue souvent → 2 essais par routeur.
//   - lecture de la base          : 4 s maximum
//   - 1er essai                   : 12 s maximum
//   - 2e essai (si utile)         : 9 s maximum
//   - fermeture d'une connexion   : 1 s maximum
//   - BUDGET_ROUTEURS_MS          : tous les essais doivent être finis 25 s après le début de
//     l'appel (le 2e essai est raccourci si besoin) → avec la dernière fermeture, ≤ 26 s au total.
const DELAI_BASE_MS        = 4000;
const DELAI_ESSAI1_MS      = 12000;
const DELAI_ESSAI2_MS      = 9000;
const DELAI_ESSAI_MIN_MS   = 3000;   // en dessous, un essai ne vaut pas la peine
const DELAI_FERMETURE_MS   = 1000;
const BUDGET_ROUTEURS_MS   = 25000;

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
      e.delai_ms = ms;
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

// Classe une erreur. L'ordre compte : identifiants avant « timeout ».
function categorie(err) {
  const msg   = String((err && err.message) || '');
  const code  = String((err && (err.code || err.errno)) || '');
  const texte = (code + ' ' + msg).toLowerCase();

  if (code === 'DELAI_DEPASSE')                                        return 'delai';
  if (texte.includes('cantlogin') || texte.includes('cannot log in') || texte.includes('wrong credentials') ||
      texte.includes('invalid user') || texte.includes('login failure')) return 'identifiants';
  if (texte.includes('enotfound'))                                     return 'introuvable';
  if (texte.includes('no such command'))                               return 'commande';
  if (texte.includes('econnrefused'))                                  return 'refus';
  if (texte.includes('etimedout') || texte.includes('socktmout') || texte.includes('timeout') || texte.includes('timed out'))
                                                                       return 'delai';
  if (texte.includes('ehostunreach') || texte.includes('enetunreach') || texte.includes('eai_again')) return 'reseau';
  if (texte.includes('econnreset') || texte.includes('closed'))       return 'coupure';
  return 'autre';
}

// Un 2e essai ne sert à rien si les identifiants sont faux, si l'adresse n'existe pas,
// ou si le routeur ne connaît pas la commande.
function nouvelEssaiUtile(err) {
  const c = categorie(err);
  return c !== 'identifiants' && c !== 'introuvable' && c !== 'commande';
}

// Message d'erreur clair, SANS adresse ni port : on parle de la zone par son nom.
function messageErreur(err, nomZone) {
  switch (categorie(err)) {
    case 'delai':
      return (err && err.code === 'DELAI_DEPASSE' && err.delai_ms)
        ? `Délai dépassé (${Math.round(err.delai_ms / 1000)} s) — routeur injoignable : ${nomZone}`
        : `Délai dépassé — routeur injoignable : ${nomZone}`;
    case 'identifiants': return `Identifiant ou mot de passe MikroTik incorrect : ${nomZone}`;
    case 'introuvable':  return `Adresse du routeur introuvable : ${nomZone}`;
    case 'commande':     return `Commande non disponible sur ce routeur : ${nomZone}`;
    case 'refus':        return `Connexion refusée par le routeur : ${nomZone} (port API fermé ?)`;
    case 'reseau':       return `Routeur hors réseau : ${nomZone}`;
    case 'coupure':      return `Connexion interrompue par le routeur : ${nomZone}`;
    // Message inconnu : on ne le recopie pas (il pourrait contenir l'adresse du routeur).
    default:             return `Lecture du routeur impossible : ${nomZone}`;
  }
}

// Ferme la connexion sans jamais bloquer ni lever d'erreur.
// Attention (constaté dans le code de node-routeros) : close() ne fait RIEN si la
// connexion n'est pas encore établie ; le socket resterait ouvert. On le détruit donc
// de force s'il existe encore (champ interne « connector » de RouterOSAPI).
async function fermer(conn) {
  if (!conn) return;
  try { await avecDelai(Promise.resolve().then(() => conn.close()), DELAI_FERMETURE_MS, 'FERMETURE'); }
  catch (_) { /* déjà fermée ou injoignable : rien à faire */ }
  try { if (conn.connector && typeof conn.connector.destroy === 'function') conn.connector.destroy(); }
  catch (_) { /* déjà détruite */ }
}

// ─── Lecture d'un routeur ───────────────────────────────────────────────────

// Un essai complet : connexion + 3 lectures, limité à delaiMs. Connexion toujours fermée.
async function unEssai(s, host, port, delaiMs) {
  let conn = null;
  try {
    conn = new RouterOSAPI({
      host:      host,
      port:      port,
      user:      String(s.mikrotik_user).trim(),
      password:  s.mikrotik_password || '',
      // node-routeros : timeout en SECONDES (Connector.ts : socket.setTimeout(timeout * 1000)),
      // et c'est un délai d'INACTIVITÉ du socket, pas un délai total. On le met 1 s au-dessus
      // de notre minuteur : c'est notre minuteur (délai total de l'essai) qui décide.
      timeout:   Math.ceil(delaiMs / 1000) + 1,
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

    return await avecDelai(travail, delaiMs, 'DELAI_DEPASSE');
  } finally {
    await fermer(conn);
  }
}

// finRouteurs : instant (Date.now()) avant lequel tous les essais doivent être terminés.
async function lireRouteur(s, finRouteurs) {
  const debut = Date.now();
  const zone  = s.id;
  const nom   = s.name || s.id;

  if (!s.mikrotik_host || !String(s.mikrotik_host).trim()) {
    return { zone, nom, ok: false, msg: `MikroTik non configuré pour cette zone : ${nom}`, essais: 0, duree_ms: 0 };
  }
  if (!s.mikrotik_user || !String(s.mikrotik_user).trim()) {
    return { zone, nom, ok: false, msg: `Identifiant MikroTik non renseigné : ${nom}`, essais: 0, duree_ms: 0 };
  }

  const { host, port } = hoteEtPort(s.mikrotik_host, s.mikrotik_port);
  const plan = [DELAI_ESSAI1_MS, DELAI_ESSAI2_MS];
  let essais = 0;
  let donnees = null;
  let derniereErreur = null;

  for (let i = 0; i < plan.length; i++) {
    const delai = Math.min(plan[i], finRouteurs - Date.now());
    if (delai < DELAI_ESSAI_MIN_MS) break;          // plus assez de temps pour un essai utile
    essais++;
    try {
      donnees = await unEssai(s, host, port, delai);
      break;                                         // réussi
    } catch (err) {
      derniereErreur = err;
      // Journal Vercel : identifiant de zone, n° d'essai et code d'erreur seulement (jamais l'hôte).
      console.error('[mikrotik-active]', zone, 'essai', essais, (err && (err.code || err.errno)) || 'erreur');
      if (!nouvelEssaiUtile(err)) break;
    }
  }

  const duree_ms = Date.now() - debut;

  if (!donnees) {
    const e = derniereErreur || Object.assign(new Error('DELAI_DEPASSE'), { code: 'DELAI_DEPASSE' });
    let msg = messageErreur(e, nom);
    if (essais > 1) msg += ` (après ${essais} essais)`;
    return { zone, nom, ok: false, msg, essais, duree_ms };
  }

  try {
    const { hotspot, ppp, ressource } = donnees;

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
      essais,
      duree_ms,
    };
  } catch (err) {
    console.error('[mikrotik-active]', zone, 'lecture réponse', (err && err.code) || 'erreur');
    return { zone, nom, ok: false, msg: `Lecture du routeur impossible : ${nom}`, essais, duree_ms };
  }
}

// ─── Fonction principale ────────────────────────────────────────────────────

export default async function handler(req, res) {
  const t0 = Date.now(); // sert à garder le total sous 27 s
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

  // 5. Lecture des routeurs en PARALLÈLE (jusqu'à 2 essais chacun, tous finis avant t0 + 25 s)
  const finRouteurs = t0 + BUDGET_ROUTEURS_MS;
  const resultats = await Promise.allSettled(succursales.map(s => lireRouteur(s, finRouteurs)));
  const zones = resultats.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const s = succursales[i];
    return { zone: s.id, nom: s.name || s.id, ok: false, msg: `Lecture du routeur impossible : ${s.name || s.id}`, essais: 0, duree_ms: 0 };
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
