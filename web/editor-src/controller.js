"use strict";
import {createCode} from "./code.js";
// The source is always text. No eval, shell, external scripts or HTML from a file.
window.MySyncEditor = ({request, post, Failure, icon}) => {
  const $ = id => document.getElementById(id);
  const encoder = new TextEncoder();
  const params = new URLSearchParams(location.search), path = params.get("path") || "";
  const parent = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  const folder = params.has("directory") ? params.get("directory") : parent;
  const back = `/files?${new URLSearchParams({directory: folder})}`;
  const python = /\.py$/i.test(path), limit = 262144;
  const input = createCode({host: $("code-host"), isPython: python,
    onChange: changed, onSave: () => flush().catch(() => {}), onRun: () => $("editor-run").click()});
  const digest = async text => [...new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)))].map(b => b.toString(16).padStart(2, "0")).join("");
  let entry, savedText = "", eol = "\n", timer, saving, unconfirmed, lastEdit = 0, editAllowed = false, saveError, opening;
  let ready = false, detecting = false, starting = false, departing = false, job, polling, lastRunText, cleared = false, leaving = false, generation = 0;
  let controller = new AbortController();
  const dirty = () => entry && input.value !== savedText;
  const content = () => input.value.replace(/\n/g, eol);
  const errors = {
    files_edit_disabled: "L’édition n’est pas autorisée sur ce PC. Activez mysync web-files enable-edit, puis relancez le client.",
    files_edit_required: "L’autorisation d’édition a expiré. Réessayez pour vérifier cet appareil.",
    code_run_disabled: "L’exécution n’est pas autorisée sur ce PC. Activez mysync web-files enable-run, puis relancez le client.",
    files_read_disabled: "La lecture web doit être autorisée avec mysync web-files enable, puis le client relancé.",
    revision_changed: "Ce fichier a changé sur le serveur. Votre brouillon est conservé ici et dans .mysync-conflicts/ sur le serveur. Téléchargez-le avant de recharger la version courante.",
    conflict_storage_full: "Le conflit n’a pas pu être conservé sur le serveur. Téléchargez votre brouillon avant de quitter cette page.",
    isolation_unavailable: "Les protections locales sont indisponibles. Bubblewrap, prlimit et les limites systemd sont nécessaires sur ce PC.",
    tool_missing: python ? "Python 3 est absent sur ce PC." : "Aucun compilateur GCC ou Clang n’est disponible sur ce PC.",
    runner_authorization_refused: "Le client n’a pas confirmé l’autorisation ou la révision à exécuter. Vérifiez cet appareil et le fichier.",
    runner_busy: "Une exécution est déjà en cours sur ce PC. Attendez sa fin.",
    code_too_large: "L’éditeur accepte les fichiers jusqu’à 256 Kio. Téléchargez votre brouillon ou réduisez sa taille.",
    unsupported_file: "L’éditeur ouvre uniquement les fichiers Python (.py) et C (.c).",
    invalid_text: "Ce fichier n’est pas du texte UTF-8 pris en charge.",
    session_expired: "La session a expiré. Téléchargez votre brouillon avant de vérifier à nouveau cet appareil.",
    authentication_refused: "L’accès a été refusé. Téléchargez votre brouillon avant de vérifier à nouveau cet appareil.",
    local_rejected: "Le client local ne prend pas en charge cette autorisation ou utilise une autre clé serveur.",
    file_not_found: "Ce fichier n’est plus présent sur le serveur.",
    challenge_limit: "Trop de vérifications rapprochées. Attendez une minute et réessayez.",
    rate_limited: "Trop de vérifications rapprochées. Attendez une minute et réessayez."
  };
  const message = (error, fallback) => errors[error?.code] || fallback;
  function notice(text) {
    $("editor-error").textContent = text;
    $("editor-notice").hidden = !text;
    $("editor-draft").hidden = !dirty();
    $("editor-discard").hidden = true;
  }
  function controls() {
    $("editor-run").disabled = starting || departing || (!job && (!entry || !ready || Boolean(saveError)));
    $("editor-run").querySelector("span").textContent = job ? "Arrêter" : starting ? "Préparation…" : "Exécuter";
    $("editor-run").querySelector("use").setAttribute("href", `/atlas-icons.svg#${job ? "stop" : "play"}`);
    input.readOnly = !editAllowed || starting || departing;
    saveStatus();
  }
  function saveStatus() {
    const status = $("editor-save-state");
    status.textContent = saveError ? "Sauvegarde interrompue" : saving ? "Enregistrement…" : dirty() ? "Modifié" : !entry ? "Ouverture…" : !editAllowed ? "Lecture seule" : "Enregistré";
    status.dataset.state = saveError ? "error" : saving || dirty() ? "pending" : "saved";
    $("editor-eol").textContent = `UTF-8 · ${eol === "\r\n" ? "CRLF" : "LF"}`;
  }
  function highlight() {
    $("output-stale").hidden = lastRunText === undefined || lastRunText === input.value || cleared;
    saveStatus();
  }
  async function authorize(scope) {
    const signal = controller.signal, prefix = scope === "edit" ? "files_edit" : "code_run";
    try { await request(`/v1/web/editor/${scope}/session`, {signal}); return; }
    catch (error) { if (error.code !== `${prefix}_required`) throw error; }
    const challenge = await post(`/v1/web/editor/${scope}/challenges`, signal);
    if (!/^[a-f0-9]{64}$/.test(challenge.challenge_id) || typeof challenge.ticket !== "string" || challenge.ticket.length > 2048) throw new Failure("invalid_response");
    let localError;
    try {
      const local = await request("http://127.0.0.1:47831/v1/status", {local: true, signal, timeout: 10000,
        headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": challenge.ticket}});
      if (!local.response.ok) localError = local.data.error;
    } catch (_) { /* The server remains authoritative if a bridge reply is lost. */ }
    try { await request(`/v1/web/editor/${scope}/challenges/${challenge.challenge_id}`, {signal}); }
    catch (error) {
      if (error.code === "pending" && localError) throw new Failure(localError === "invalid_challenge" ? "local_rejected" : localError);
      throw error;
    }
  }
  async function loadSource() {
    const value = await request(`/v1/web/editor/file?${new URLSearchParams({path})}`, {signal: controller.signal, limit: 1600000});
    if (value.entry?.path !== path || value.entry.deleted || !Number.isSafeInteger(value.entry.revision) || value.entry.revision < 1 ||
      typeof value.content !== "string" || encoder.encode(value.content).length > limit || value.content.includes("\0") || await digest(value.content) !== value.entry.sha256) throw new Failure("invalid_response");
    return value;
  }
  async function open() {
    if (opening) return opening;
    if (entry && !controller.signal.aborted) return;
    controller = new AbortController(); const current = ++generation;
    opening = (async () => {
      try {
        if (!/\.(py|c)$/i.test(path)) throw new Failure("unsupported_file");
        const value = await loadSource();
        if (current !== generation) return;
        if (dirty()) { notice("Votre brouillon est conservé. Téléchargez-le avant de recharger le fichier."); return; }
        entry = value.entry; eol = value.content.includes("\r\n") ? "\r\n" : "\n";
        input.value = value.content; savedText = input.value; saveError = undefined; highlight();
        try { await authorize("edit"); editAllowed = true; notice(""); }
        catch (error) { notice(message(error, "L’édition n’a pas été autorisée. Vérifiez le client local, puis réessayez.")); }
        if (current !== generation) return;
        controls(); await detect();
      } catch (error) { if (current === generation) { notice(message(error, "Impossible d’ouvrir le fichier. Vérifiez la connexion et réessayez.")); $("editor-tool").textContent = "Client non vérifié"; } }
      finally { opening = undefined; controls(); }
    })();
    return opening;
  }
  function schedule() {
    clearTimeout(timer);
    if (dirty() && !saving && !saveError && editAllowed) timer = setTimeout(() => persist().catch(() => {}), Math.max(0, lastEdit + 100 - Date.now()));
  }
  function persist() {
    if (saving) return saving;
    if (!dirty()) return Promise.resolve();
    if (saveError || !editAllowed) return Promise.reject(saveError || new Failure("files_edit_required"));
    const text = input.value, code = content(), base = entry.revision, current = generation;
    saving = Promise.resolve().then(async () => {
      try {
        if (encoder.encode(code).length > limit) throw new Failure("code_too_large");
        saveStatus();
        const sha256 = await digest(code);
        unconfirmed = {text, code, base};
        const value = await request("/v1/web/editor/file", {method: "PUT", signal: controller.signal, headers: {"Content-Type": "application/json"},
          body: JSON.stringify({path, base_revision: base, content: code})});
        if (current !== generation) throw new Failure("session_expired");
        if (value.path !== path || value.sha256 !== sha256 || value.deleted || value.size !== encoder.encode(code).length || !Number.isSafeInteger(value.revision) || value.revision <= base) throw new Failure("invalid_response");
        entry = value; savedText = text; unconfirmed = undefined; notice("");
      } catch (error) {
        if (current === generation) {
          saveError = error;
          notice(message(error, "Sauvegarde non confirmée. Votre brouillon reste ici. Réessayez ou téléchargez-le avant de quitter."));
        }
        throw error;
      } finally { saving = undefined; controls(); schedule(); }
    });
    return saving;
  }
  async function flush() {
    clearTimeout(timer);
    if (saving) await saving;
    while (dirty()) await persist();
    if (saveError) throw saveError;
  }
  function changed() {
    lastEdit = Date.now(); highlight(); $("editor-discard").hidden = true;
    if (saveError) $("editor-draft").hidden = !dirty();
    schedule();
  }
  $("editor-retry").addEventListener("click", async () => {
    $("editor-retry").disabled = true;
    try {
      if (!entry) { await open(); return; }
      await authorize("edit"); editAllowed = true;
      if (saveError) {
        // Reconcile a lost acknowledgement without blindly overwriting a newer revision.
        const remote = await loadSource();
        if (remote.entry.revision !== entry.revision) {
          if (remote.content === content()) savedText = input.value;
          else if (unconfirmed && remote.content === unconfirmed.code && remote.entry.revision > unconfirmed.base) savedText = unconfirmed.text;
          else throw new Failure("revision_changed");
          entry = remote.entry; unconfirmed = undefined;
        }
        saveError = undefined;
      }
      notice(""); controls(); await flush();
    } catch (error) { saveError = error; notice(message(error, "Sauvegarde non confirmée. Téléchargez le brouillon avant de quitter.")); }
    finally { $("editor-retry").disabled = false; controls(); }
  });
  async function local(operation) {
    const signal = controller.signal;
    const issued = await request("/v1/web/editor/tickets", {method: "POST", signal, headers: {"Content-Type": "application/json"}, body: JSON.stringify(operation)});
    if (!/^[a-f0-9]{64}$/.test(issued.ticket)) throw new Failure("invalid_response");
    const value = await request("http://127.0.0.1:47831/v1/editor", {method: "POST", local: true, signal, timeout: 12000, limit: 450000,
      headers: {"X-MySync-Bridge": "1", "Content-Type": "application/json"}, body: JSON.stringify({ticket: issued.ticket})});
    if (!value.response.ok) throw new Failure(value.data.error || "runner_failed");
    return value.data;
  }
  async function detect() {
    if (detecting || job) return;
    detecting = true; ready = false; controls();
    $("editor-tool").textContent = "Détection en cours…"; $("editor-tool").classList.remove("available");
    $("runner-retry").hidden = true;
    try {
      await authorize("run");
      const value = await local({action: "tools"});
      if (typeof value.python !== "boolean" || typeof value.isolation !== "boolean" || ![null, "gcc", "clang"].includes(value.compiler)) throw new Failure("invalid_response");
      if (!value.isolation) throw new Failure("isolation_unavailable");
      if (python ? !value.python : !value.compiler) throw new Failure("tool_missing");
      $("editor-tool").textContent = python ? "Python 3 disponible" : `${value.compiler === "gcc" ? "GCC" : "Clang"} disponible`;
      $("editor-tool").classList.add("available"); ready = true;
      $("runner-message").textContent = "Exécutez ce fichier pour voir sa sortie ici.";
    } catch (error) {
      $("editor-tool").textContent = "Exécution indisponible";
      $("runner-message").textContent = message(error, "Le client local est inaccessible ou n’a pas confirmé ses outils. Vérifiez ses autorisations et réessayez.");
      $("runner-retry").hidden = false;
    } finally { detecting = false; controls(); }
  }
  const states = {running: "Exécution en cours…", finished: "Terminé", failed: "Échec", compile_failed: "Échec de la compilation", stopped: "Arrêté", timeout: "Durée maximale dépassée", output_limit: "Limite de sortie atteinte", authorization_expired: "Autorisation expirée — exécution arrêtée", isolation_failed: "L’isolation locale a échoué"};
  function render(value) {
    if (!job || value.job_id !== job.id || value.sha256 !== job.sha256 || !Object.hasOwn(states, value.state)) throw new Failure("invalid_response");
    let size = 0;
    for (const phase of [value.compilation, value.execution]) if (phase) {
      if (typeof phase.stdout !== "string" || typeof phase.stderr !== "string" || (phase.exit_code !== null && !Number.isSafeInteger(phase.exit_code)) ||
        (phase.duration_ms !== null && (!Number.isSafeInteger(phase.duration_ms) || phase.duration_ms < 0))) throw new Failure("invalid_response");
      size += encoder.encode(phase.stdout + phase.stderr).length;
    }
    if (size > 65536) throw new Failure("invalid_response");
    if (!cleared) {
      $("run-output").replaceChildren(); $("run-result").replaceChildren();
      for (const [key, label] of [["compilation", "Compilation"], ["execution", "Programme"]]) {
        const phase = value[key]; if (!phase) continue;
        if (key === "compilation" && (phase.stdout || phase.stderr)) { const title = document.createElement("h3"); title.textContent = label; $("run-output").append(title); }
        for (const [text, error] of [[phase.stdout, false], [phase.stderr, true]]) if (text) {
          const pre = document.createElement("pre"); pre.textContent = text; if (error) { pre.className = "run-stderr"; pre.setAttribute("aria-label", "Erreurs"); } $("run-output").append(pre);
        }
      }
      const state = document.createElement("p"); state.append(icon(value.state === "finished" ? "check" : value.state === "running" ? "spinner" : "warning"), document.createTextNode(states[value.state]));
      if (!["finished", "running"].includes(value.state)) state.className = "failed";
      $("run-result").append(state); $("run-result").hidden = false;
      const detail = text => { const p = document.createElement("p"); p.textContent = text; $("run-result").append(p); };
      const phase = value.execution || value.compilation;
      if (phase?.exit_code !== null && phase?.exit_code !== undefined) detail(`Code de retour : ${phase.exit_code}`);
      if (value.compilation?.duration_ms !== null && value.compilation?.duration_ms !== undefined) detail(`Durée de compilation : ${value.compilation.duration_ms} ms`);
      if (value.execution?.duration_ms !== null && value.execution?.duration_ms !== undefined) detail(`Durée d’exécution : ${value.execution.duration_ms} ms`);
    }
    if (value.state !== "running") { job = undefined; clearTimeout(polling); controls(); }
  }
  function poll() {
    clearTimeout(polling);
    if (!job) return;
    polling = setTimeout(async () => {
      try { const value = await local({action: "poll", job_id: job.id}); render(value); poll(); }
      catch (error) {
        job = undefined; ready = false; controls();
        $("runner-message").textContent = message(error, "La connexion au client est interrompue. Le lancement s’arrête automatiquement sans renouvellement de l’autorisation."); $("runner-retry").hidden = false;
      }
    }, 1000);
  }
  $("editor-run").addEventListener("click", async () => {
    if (job) {
      try { render(await local({action: "stop", job_id: job.id})); poll(); }
      catch (_) { $("runner-message").textContent = "Arrêt non confirmé. Le client s’arrête automatiquement sans renouvellement de l’autorisation."; clearTimeout(polling); job = undefined; ready = false; controls(); }
      return;
    }
    if (!ready || starting) return;
    starting = true; controls();
    try {
      await flush();
      lastRunText = input.value; cleared = false; $("output-stale").hidden = true;
      $("run-output").replaceChildren(); $("run-result").hidden = true;
      job = {id: crypto.randomUUID(), sha256: entry.sha256};
      const value = await local({action: "start", path, revision: entry.revision, sha256: entry.sha256, job_id: job.id});
      $("runner-message").textContent = ""; render(value); poll();
    } catch (error) {
      job = undefined;
      $("runner-message").textContent = message(error, "Le lancement n’a pas été confirmé. Aucune nouvelle exécution ne sera demandée automatiquement.");
    } finally { starting = false; controls(); }
  });
  $("runner-retry").addEventListener("click", detect);
  $("editor-clear").addEventListener("click", () => { cleared = true; $("run-output").replaceChildren(); $("run-result").hidden = true; $("output-stale").hidden = true; });
  $("editor-draft").addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([content()], {type: "text/plain;charset=utf-8"}));
    const link = document.createElement("a"); link.href = url; link.download = `brouillon-${path.split("/").pop()}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 60000);
    $("editor-discard").hidden = false;
  });
  $("editor-discard").addEventListener("click", () => { leaving = true; location.assign(back); });
  async function leave(destination, logout = false) {
    if (departing) return;
    departing = true; controls();
    try {
      await flush();
      if (job) { await local({action: "stop", job_id: job.id}); clearTimeout(polling); job = undefined; }
      leaving = true;
      if (logout) $("logout").click(); else location.assign(destination);
    } catch (_) { notice("Votre brouillon n’est pas confirmé. Téléchargez-le avant de quitter, ou réessayez la sauvegarde."); }
    finally { departing = false; controls(); }
  }
  document.addEventListener("click", event => {
    const link = event.target.closest('a[href^="/"]'), logout = event.target.closest("#logout");
    if (leaving || !link && !logout || link && (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey)) return;
    if (link || logout) { event.preventDefault(); event.stopImmediatePropagation(); leave(link?.href, Boolean(logout)); }
  }, true);
  addEventListener("beforeunload", event => { if (!leaving && (dirty() || saving || starting || job)) { event.preventDefault(); event.returnValue = ""; } });
  function lock() {
    generation++; clearTimeout(timer); clearTimeout(polling); controller.abort(); editAllowed = false; ready = false; job = undefined;
    const draft = dirty();
    if (draft) { saveError = new Failure("session_expired"); notice(errors.session_expired); }
    else { entry = undefined; input.value = ""; savedText = ""; highlight(); $("run-output").replaceChildren(); $("run-result").hidden = true; }
    controls(); return draft;
  }
  const splitter = $("editor-splitter");
  let percent = 65;
  const stacked = matchMedia("(max-width: 700px)");
  function split(value) {
    percent = Math.max(30, Math.min(80, value));
    const tracks = `minmax(0, ${percent}fr) 6px minmax(0, ${100-percent}fr)`;
    $("editor-panes").style.gridTemplateColumns = stacked.matches ? "minmax(0, 1fr)" : tracks;
    $("editor-panes").style.gridTemplateRows = stacked.matches ? tracks : "minmax(0, 1fr)";
    splitter.setAttribute("aria-valuenow", String(Math.round(percent)));
    splitter.setAttribute("aria-orientation", stacked.matches ? "horizontal" : "vertical");
    splitter.setAttribute("aria-label", stacked.matches ? "Hauteur de la colonne Code" : "Largeur de la colonne Code");
  }
  stacked.addEventListener("change", () => split(percent)); split(percent);
  splitter.addEventListener("pointerdown", event => { if (event.button === 0) { splitter.setPointerCapture(event.pointerId); event.preventDefault(); splitter.focus(); } });
  splitter.addEventListener("pointermove", event => { if (splitter.hasPointerCapture(event.pointerId)) { const box = $("editor-panes").getBoundingClientRect(); split(stacked.matches ? (event.clientY-box.y)/box.height*100 : (event.clientX-box.x)/box.width*100); } });
  splitter.addEventListener("pointerup", event => { if (splitter.hasPointerCapture(event.pointerId)) splitter.releasePointerCapture(event.pointerId); });
  splitter.addEventListener("keydown", event => { const arrows = stacked.matches ? ["ArrowUp", "ArrowDown"] : ["ArrowLeft", "ArrowRight"]; if ([...arrows, "Home", "End"].includes(event.key)) { event.preventDefault(); split(event.key === "Home" ? 30 : event.key === "End" ? 80 : percent + (event.key === arrows[0] ? -2 : 2)); } });
  $("editor-shortcuts").addEventListener("click", () => $("editor-help").showModal());
  $("editor-help-close").addEventListener("click", () => $("editor-help").close());
  $("editor-back").href = back;
  $("editor-name").textContent = path.split("/").pop() || "Fichier"; $("editor-name").title = path;
  $("editor-language").textContent = python ? "Python" : "C";
  document.title = `${path.split("/").pop() || "Éditeur"} · MySyncFiles`;
  for (const part of path.split("/")) { const span = document.createElement("span"); span.textContent = part; $("editor-path").append(span); }
  $("editor-path").title = path; $("editor-path").scrollLeft = $("editor-path").scrollWidth;
  return {open, lock};
};
