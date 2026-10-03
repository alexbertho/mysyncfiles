"use strict";
const verify = document.getElementById("verify");
const cancel = document.getElementById("cancel");
const message = document.getElementById("message");
const result = document.getElementById("result");
// CSP host sources cannot express an IPv6 literal; keep a strict IPv4 source.
const endpoints = ["http://127.0.0.1:47831/v1/status"];
let active;
let previous;
let expiryTimer;

class StatusFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}

// A local impostor or an upstream error cannot make the browser allocate an
// arbitrary response body. No raw errors or received HTML reach the page.
async function json(response) {
  if (!response.body) throw new StatusFailure("invalid_response");
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) throw new StatusFailure("invalid_response");
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder().decode(bytes));
  } finally { await reader.cancel().catch(() => {}); }
}

async function request(url, options, signal, local = false) {
  const response = await fetch(url, {
    cache: "no-store", redirect: "error", credentials: local ? "omit" : "same-origin",
    ...options, signal
  });
  return {response, data: await json(response)};
}

async function permissionDenied() {
  if (!navigator.permissions) return false;
  for (const name of ["loopback-network", "local-network-access"]) {
    try { return (await navigator.permissions.query({name})).state === "denied"; }
    catch (_) { /* Permission names are optional and browser dependent. */ }
  }
  return false;
}

function clearResult() {
  clearTimeout(expiryTimer);
  result.hidden = true;
  result.replaceChildren();
}

function showPresence(value, challengeId) {
  if (value.challenge_id !== challengeId || !Number.isSafeInteger(value.device_id) ||
      typeof value.device_name !== "string" || !value.status ||
      !Number.isSafeInteger(value.presence_expires_at) || !Number.isSafeInteger(value.verified_at)) {
    throw new StatusFailure("invalid_response");
  }
  const remaining = Math.min(120000, value.presence_expires_at * 1000 - Date.now());
  if (remaining <= 0) throw new StatusFailure("presence_expired");
  const daemon = {starting: "Démarrage", idle: "En attente", syncing: "Synchronisation", error: "Erreur"};
  const communication = {unknown: "Non observée", authenticated: "Authentifiée", failed: "Échec"};
  const time = value => value ? new Date(value * 1000).toLocaleString() : "Aucune";
  const values = [
    ["Appareil reconnu", value.device_name], ["Identifiant serveur", value.device_id],
    ["Version du client", value.status.client_version], ["Version de l’API locale", value.status.api_version],
    ["Daemon", daemon[value.status.daemon_state] || "Inconnu"],
    ["Communication serveur", communication[value.status.communication] || "Inconnue"],
    ["Statut observé", time(value.status.observed_at)],
    ["Dernière communication authentifiée", time(value.status.last_authenticated_at)],
    ["Présence vérifiée", time(value.verified_at)], ["Expiration", time(value.presence_expires_at)]
  ];
  for (const [label, text] of values) {
    const term = document.createElement("dt");
    const definition = document.createElement("dd");
    term.textContent = label;
    definition.textContent = String(text);
    result.append(term, definition);
  }
  result.hidden = false;
  message.textContent = "Machine reconnue — présence confirmée par le serveur.";
  previous = {id: challengeId, expires: Date.now() + remaining};
  expiryTimer = setTimeout(() => {
    clearResult(); previous = undefined;
    message.textContent = "La présence a expiré. Cliquez sur Vérifier pour l’actualiser.";
  }, remaining);
}

cancel.addEventListener("click", () => active?.abort());
verify.addEventListener("click", async () => {
  const controller = new AbortController();
  let userCancelled = false;
  active = {abort: () => { userCancelled = true; controller.abort(); }};
  verify.disabled = true;
  cancel.hidden = false;
  clearResult();
  let stage = "probe";
  let accessible = false;
  let timer = setTimeout(() => { controller.abort(); }, 30000);
  const waiting = setTimeout(() => {
    message.textContent = "En attente de l’accès local. Vérifiez les éventuelles demandes d’autorisation du navigateur.";
  }, 3000);
  message.textContent = "Recherche du client local…";
  try {
    let endpoint;
    for (const candidate of endpoints) {
      try {
        const probe = await request(candidate, {headers: {"X-MySync-Bridge": "1"}}, controller.signal, true);
        accessible = true;
        if (probe.response.status === 401 && probe.data.error === "challenge_required") {
          endpoint = candidate; break;
        }
      } catch (_) { if (controller.signal.aborted) throw new StatusFailure("cancelled"); }
    }
    if (!endpoint) throw new StatusFailure(accessible ? "local_unverified" : "local_unavailable");
    clearTimeout(waiting); clearTimeout(timer);
    timer = setTimeout(() => { controller.abort(); }, 10000);
    stage = "server";
    message.textContent = "Vérification de la présence auprès du serveur…";
    const body = previous && previous.expires > Date.now() ? {previous_challenge_id: previous.id} : {};
    const challenge = await request("/v1/web/status/challenges", {
      method: "POST", headers: {"X-MySync-Web": "1", "Content-Type": "application/json"}, body: JSON.stringify(body)
    }, controller.signal);
    if (!challenge.response.ok) throw new StatusFailure(challenge.data.error);
    const {challenge_id: id, ticket} = challenge.data;
    if (!/^[a-f0-9]{64}$/.test(id) || typeof ticket !== "string" || ticket.length > 2048) throw new StatusFailure("invalid_response");
    // Ignore local identity/status claims. Only the cookie-bound backend result
    // can recognize a device, even when another process owns the local port.
    let localFailed = false;
    try {
      const local = await request(endpoint, {headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": ticket}}, controller.signal, true);
      localFailed = !local.response.ok;
    } catch (_) { localFailed = true; }
    // A lost local acknowledgement may follow a committed proof. Make one
    // bounded result lookup, also after the exchange deadline, never a loop.
    if (userCancelled) throw new StatusFailure("cancelled");
    clearTimeout(timer);
    const lookup = new AbortController();
    const onCancel = () => lookup.abort();
    controller.signal.addEventListener("abort", onCancel, {once: true});
    active = {abort: () => { userCancelled = true; lookup.abort(); controller.abort(); }};
    timer = setTimeout(() => { lookup.abort(); }, 3000);
    let checked;
    try {
      checked = await request(`/v1/web/status/challenges/${id}`, {headers: {"X-MySync-Web": "1"}}, lookup.signal);
    } finally {
      controller.signal.removeEventListener("abort", onCancel);
    }
    if (checked.response.status === 202) throw new StatusFailure(localFailed ? "verification_failed" : "local_unverified");
    if (!checked.response.ok) throw new StatusFailure(checked.data.error);
    showPresence(checked.data, id);
  } catch (error) {
    const texts = {
      authentication_refused: "Challenge ou authentification refusés. Rechargez la page si la session a expiré.",
      challenge_expired: "Le challenge a expiré. Cliquez sur Vérifier pour recommencer.",
      presence_expired: "La présence a expiré. Cliquez sur Vérifier pour recommencer.",
      challenge_limit: "Trop de vérifications rapprochées. Attendez une minute.",
      local_unverified: "Réponse locale accessible, mais aucune machine vérifiée par le serveur.",
      verification_failed: "Client local accessible, mais preuve non confirmée. Vérifiez la connexion au serveur et l’approbation de l’appareil.",
      status_busy: "Le serveur est occupé. Réessayez plus tard."
    };
    if (userCancelled) message.textContent = "Vérification annulée.";
    else if (stage === "probe" && await permissionDenied()) message.textContent = "Permission d’accès local refusée par le navigateur.";
    else message.textContent = texts[error.code] || (stage === "probe"
      ? "Client inaccessible ou accès local bloqué. Vérifiez le daemon et les permissions du navigateur."
      : "Vérification serveur indisponible. Réessayez lorsque la connexion est rétablie.");
  } finally {
    clearTimeout(timer); clearTimeout(waiting);
    active = undefined;
    verify.disabled = false;
    cancel.hidden = true;
  }
});
