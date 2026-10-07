"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const icon = (name, className = "") => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("aria-hidden", "true");
    if (className) svg.setAttribute("class", className);
    const use = document.createElementNS(svg.namespaceURI, "use");
    use.setAttribute("href", `/atlas-icons.svg#${name}`);
    svg.append(use);
    return svg;
  };
  const setIcon = (id, name) => $(id).querySelector("use").setAttribute("href", `/atlas-icons.svg#${name}`);
  const preference = (key, value) => { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (_) {} };
  const systemTheme = matchMedia("(prefers-color-scheme: dark)");
  function theme(dark) {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    setIcon("theme-toggle", dark ? "sun" : "moon");
    $("theme-toggle").setAttribute("aria-label", dark ? "Passer au thème clair" : "Passer au thème sombre");
    $("theme-toggle").title = $("theme-toggle").getAttribute("aria-label");
  }
  theme(preference("mysync-theme") ? preference("mysync-theme") === "dark" : systemTheme.matches);
  $("theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme !== "dark";
    preference("mysync-theme", dark ? "dark" : "light"); theme(dark);
  });
  systemTheme.addEventListener("change", event => { if (!preference("mysync-theme")) theme(event.matches); });
  function sidebar(closed) {
    document.body.classList.toggle("sidebar-collapsed", closed);
    $("sidebar").hidden = closed;
    $("sidebar-toggle").setAttribute("aria-expanded", String(!closed));
    $("sidebar-toggle").setAttribute("aria-label", closed ? "Afficher le menu" : "Masquer le menu");
    $("sidebar-toggle").title = $("sidebar-toggle").getAttribute("aria-label");
    setIcon("sidebar-toggle", closed ? "right" : "left");
  }
  sidebar(preference("mysync-sidebar") === "closed" || (matchMedia("(max-width: 1100px)").matches && preference("mysync-sidebar") !== "open"));
  $("sidebar-toggle").addEventListener("click", () => {
    const closed = !document.body.classList.contains("sidebar-collapsed");
    sidebar(closed); preference("mysync-sidebar", closed ? "closed" : "open");
  });
  const statusPage = location.pathname === "/status";
  $(statusPage ? "status-nav" : "files-nav").setAttribute("aria-current", "page");
  $("status-panel").hidden = !statusPage;
  $("search-box").hidden = statusPage;
  $("toolbar-title").hidden = !statusPage;
  $("access").hidden = statusPage;
  document.title = `${statusPage ? "Statut local" : "Fichiers"} · MySyncFiles`;

  class Failure extends Error { constructor(code) { super(code); this.code = code; } }
  async function bytes(response, limit) {
    if (!response.body) throw new Failure("invalid_response");
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    try {
      for (;;) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) throw new Failure("invalid_response");
        chunks.push(value);
      }
      const value = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { value.set(chunk, offset); offset += chunk.length; }
      return value;
    } finally { await reader.cancel().catch(() => {}); }
  }
  async function request(url, {signal, local = false, limit = 4096, timeout = 15000, raw = false, ...options} = {}) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener("abort", abort, {once: true});
    const timer = setTimeout(abort, timeout);
    try {
      const response = await fetch(url, {cache: "no-store", redirect: "error", credentials: local ? "omit" : "same-origin", ...options,
        headers: local ? options.headers : {"X-MySync-Web": "1", ...options.headers}, signal: controller.signal});
      const body = await bytes(response, limit);
      if (raw && response.ok) return body;
      const data = JSON.parse(new TextDecoder().decode(body));
      if (!local && (!response.ok || response.status === 202)) throw new Failure(data.error || "invalid_response");
      return local ? {response, data} : data;
    } finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  const post = (url, signal) => request(url, {method: "POST", signal, headers: {"Content-Type": "application/json"}, body: "{}"});
  let session, expiry, countdown, listingRequest, verification, transfer;
  let upload, pickerContext, dragDepth = 0, dragCancelled = false;
  let directory = "", search = "", cursors = [""], pageIndex = 0, next;
  let displayedQuery, displayedEntries, retryView;
  let selected, selectedButton, menuEntry, menuButton, searchTimer, toastTimer;
  let epoch = 0;
  let channel;
  try { channel = new BroadcastChannel("mysync-files"); channel.onmessage = event => { if (event.data === "logout") lock("expired"); }; } catch (_) {}
  const menu = $("file-menu");
  const messages = {
    initial: ["Vérifier cet appareil", "Le client MySyncFiles doit être lancé sur ce PC. Le navigateur peut demander l’autorisation d’accéder à cet appareil.", "Vérifier cet appareil", "laptop"],
    expired: ["Session expirée", "Votre session de lecture est terminée. Vérifiez à nouveau cet appareil pour poursuivre la consultation des fichiers.", "Vérifier à nouveau", "clock"],
    denied: ["Permission d’accès local refusée", "Le navigateur a bloqué l’accès au client MySyncFiles sur ce PC. Autorisez l’accès à cet appareil dans les permissions du site, puis réessayez.", "Réessayer", "warning"],
    disabled: ["Lecture des fichiers non autorisée", "Autorisez la lecture web sur le client de cet appareil avec mysync web-files enable, puis relancez le daemon.", "Réessayer", "warning"],
    rejected: ["Vérification locale refusée", "Vérifiez que le client installé prend en charge la lecture web, puis redémarrez son service. Vérifiez aussi qu’il utilise le même serveur et que l’horloge du PC est correcte.", "Réessayer", "warning"],
    unavailable: ["Client local inaccessible", "Vérifiez que le daemon MySyncFiles est lancé, que le pont local est activé et que le navigateur autorise l’accès à cet appareil.", "Réessayer", "laptop"]
  };
  function access(state, message = "") {
    const [title, description, label, glyph] = messages[state] || messages.initial;
    $("access").dataset.state = state;
    $("access-title").textContent = title;
    $("access-description").textContent = description;
    $("file-verify").textContent = label;
    $("access-message").textContent = message;
    $("access-note").hidden = state === "expired" || state === "denied";
    $("access-help").hidden = state === "expired";
    setIcon("access-icon", glyph);
    $("access-icon").classList.remove("busy-icon");
    $("session-label").textContent = state === "expired" ? "Session expirée" : state === "denied" || state === "disabled" ? "Accès bloqué" : "Accès non vérifié";
    $("session-dot").className = `session-dot${state === "denied" || state === "disabled" ? " blocked" : ""}`;
  }
  function closeMenu(focus = false) {
    menu.hidden = true;
    menuButton?.setAttribute("aria-expanded", "false");
    if (focus && menuButton?.isConnected) menuButton.focus();
    menuEntry = undefined; menuButton = undefined;
  }
  function closeDetails(focus = false) {
    $("details").hidden = true;
    $("details-dismiss").hidden = true;
    document.querySelector(".file-list").inert = false;
    for (const id of ["detail-name", "detail-path", "detail-size", "detail-modified", "detail-revision", "detail-hash"]) $(id).textContent = "";
    document.querySelectorAll("tr.selected").forEach(row => row.classList.remove("selected"));
    selectedButton?.setAttribute("aria-expanded", "false");
    if (focus && selectedButton?.isConnected) selectedButton.focus();
    selected = undefined; selectedButton = undefined;
    updateUploadButton();
  }
  function hideToast() { clearTimeout(toastTimer); $("toast").hidden = true; $("toast-message").textContent = ""; }
  function lock(state = "initial", message = "") {
    epoch++;
    session = undefined;
    clearTimeout(expiry); clearInterval(countdown); clearTimeout(searchTimer);
    listingRequest?.abort(); verification?.abort(); transfer?.abort(); upload?.abort();
    clearDrop(); dragCancelled = false; pickerContext = undefined; $("upload-input").value = "";
    $("upload-status").hidden = true; $("upload-results").replaceChildren();
    $("upload-message").textContent = ""; $("upload-destination").textContent = "";
    listingRequest = undefined; displayedQuery = undefined; displayedEntries = undefined; retryView = undefined;
    listingBusy(false);
    closeMenu(); closeDetails(); hideToast();
    $("rows").replaceChildren(); $("breadcrumbs").replaceChildren();
    $("count").textContent = ""; $("listing-title").textContent = "Tous les fichiers";
    $("listing-title").removeAttribute("title");
    $("listing-message").textContent = ""; $("listing-message").hidden = true;
    $("search").value = ""; $("search").disabled = true; $("clear-search").hidden = true;
    $("explorer").hidden = true; $("access").hidden = statusPage;
    $("logout").hidden = true; $("session-time").textContent = "";
    $("refresh").hidden = true;
    directory = ""; search = ""; cursors = [""]; pageIndex = 0; next = undefined;
    $("file-verify").disabled = false; $("file-cancel").hidden = true;
    access(state, message);
  }
  function acceptSession(value) {
    if (!Number.isSafeInteger(value.expires_at) || typeof value.device_name !== "string" || value.device_name.length > 512 ||
        value.chunk_bytes !== 8388608 || value.download_limit !== 268435456) throw new Failure("invalid_response");
    const remaining = Math.min(1800000, value.expires_at * 1000 - Date.now());
    if (remaining <= 0) throw new Failure("session_expired");
    session = value;
    clearTimeout(expiry); clearInterval(countdown);
    expiry = setTimeout(() => lock("expired"), remaining);
    const tick = () => { $("session-time").textContent = `Session de lecture · ${Math.max(1, Math.ceil((value.expires_at * 1000 - Date.now()) / 60000))} min`; };
    tick(); countdown = setInterval(tick, 15000);
    $("session-dot").className = "session-dot verified";
    $("session-label").textContent = "Appareil reconnu";
    $("logout").hidden = false;
    if (!statusPage) { $("access").hidden = true; $("explorer").hidden = false; $("search").disabled = false; $("refresh").hidden = false; }
  }
  async function restore() {
    const current = epoch;
    try {
      const value = await request("/v1/web/files/session");
      if (epoch !== current) return;
      acceptSession(value);
      if (!statusPage) await load();
    } catch (_) { /* An anonymous browser sees only the access screen. */ }
  }
  async function denied() {
    if (!navigator.permissions) return false;
    for (const name of ["loopback-network", "local-network-access"]) {
      try { if ((await navigator.permissions.query({name})).state === "denied") return true; } catch (_) {}
    }
    return false;
  }
  $("file-verify").addEventListener("click", async () => {
    if (verification) return;
    const controller = new AbortController(); verification = controller;
    const current = epoch;
    let userCancelled = false, stage = "local";
    const cancel = () => { userCancelled = true; controller.abort(); };
    $("file-cancel").onclick = cancel;
    $("file-verify").disabled = true; $("file-verify").textContent = "Vérification…"; $("file-cancel").hidden = false;
    $("access-message").textContent = "Vérification en cours…";
    setIcon("access-icon", "spinner"); $("access-icon").classList.add("busy-icon");
    const waiting = setTimeout(() => { if (current === epoch) $("access-message").textContent = "En attente de l’accès local. Vérifiez les demandes d’autorisation du navigateur."; }, 3000);
    try {
      const localURL = "http://127.0.0.1:47831/v1/status";
      const probe = await request(localURL, {local: true, signal: controller.signal, timeout: 30000, headers: {"X-MySync-Bridge": "1"}});
      if (probe.response.status !== 401 || probe.data.error !== "challenge_required") throw new Failure("local_unverified");
      clearTimeout(waiting); stage = "server";
      await post("/v1/web/files/session", controller.signal);
      const challenge = await post("/v1/web/files/challenges", controller.signal);
      if (!/^[a-f0-9]{64}$/.test(challenge.challenge_id) || typeof challenge.ticket !== "string" || challenge.ticket.length > 2048) throw new Failure("invalid_response");
      $("access-message").textContent = "Vérification de l’autorisation de lecture…";
      let localError;
      try {
        const local = await request(localURL, {local: true, signal: controller.signal, timeout: 10000, headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": challenge.ticket}});
        if (!local.response.ok) localError = local.data.error;
      } catch (_) { /* A lost acknowledgement can follow a committed TPM proof. */ }
      if (controller.signal.aborted) throw new Failure("cancelled");
      let value;
      try { value = await request(`/v1/web/files/challenges/${challenge.challenge_id}`, {signal: controller.signal, timeout: 3000}); }
      catch (error) {
        if (error.code === "pending") {
          if (localError === "files_read_disabled") throw new Failure("files_read_disabled");
          if (localError === "invalid_challenge") throw new Failure("local_rejected");
        }
        throw error;
      }
      if (current !== epoch || controller.signal.aborted) return;
      acceptSession(value);
      await load();
    } catch (error) {
      if (current !== epoch) return;
      if (userCancelled) {
        access("initial", "Vérification annulée.");
        await post("/v1/web/files/logout").catch(() => {});
      } else if (stage === "local" && await denied()) access("denied");
      else if (error.code === "files_read_disabled") access("disabled");
      else if (error.code === "local_rejected") access("rejected");
      else if (stage === "local") access("unavailable");
      else access("initial", error.code === "challenge_limit" || error.code === "status_busy" ? "Trop de vérifications rapprochées. Attendez une minute avant de réessayer." : "Autorisation non confirmée par le serveur. Vérifiez la connexion, l’approbation de l’appareil et l’activation de la lecture web.");
    } finally {
      clearTimeout(waiting);
      if (verification === controller) verification = undefined;
      if (current === epoch) {
        $("file-verify").disabled = false; $("file-cancel").hidden = true;
        $("file-verify").textContent = "Réessayer";
        $("access-icon").classList.remove("busy-icon");
        if ($("access-icon").querySelector("use").getAttribute("href").endsWith("#spinner")) setIcon("access-icon", "laptop");
      }
    }
  });
  $("logout").addEventListener("click", async () => {
    lock("initial", "Déconnexion en cours…");
    $("file-verify").disabled = true;
    try { await post("/v1/web/files/logout"); channel?.postMessage("logout"); access("initial", "Vous êtes déconnecté."); }
    catch (_) { access("initial", "Déconnexion serveur non confirmée. Réessayez lorsque la connexion est rétablie."); $("logout").hidden = false; }
    finally { $("file-verify").disabled = false; }
  });
  const basename = path => path.split("/").pop();
  const kindIcon = entry => entry.kind === "directory" ? "directory" : /\.pdf$/i.test(entry.path) ? "pdf" : /\.(toml|json|lock|rs|js|ya?ml|xml)$/i.test(entry.path) ? "code" : "file";
  function size(value) {
    if (value === null) return "—";
    const units = ["o", "Ko", "Mo", "Go", "To", "Po"]; let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
    return `${new Intl.NumberFormat("fr-FR", {maximumFractionDigits: value < 10 && index ? 1 : 0}).format(value)} ${units[index]}`;
  }
  const dateFormat = new Intl.DateTimeFormat("fr-FR", {dateStyle: "short"});
  const hourFormat = new Intl.DateTimeFormat("fr-FR", {timeStyle: "short"});
  const fullDateFormat = new Intl.DateTimeFormat("fr-FR", {dateStyle: "long", timeStyle: "long"});
  function modifiedTime(value, full = false) {
    if (value == null) return document.createTextNode("—");
    const date = new Date(value * 1000);
    const time = document.createElement("time");
    time.dateTime = date.toISOString();
    time.title = `Enregistrée sur le serveur le ${fullDateFormat.format(date)}`;
    if (full) time.textContent = fullDateFormat.format(date);
    else {
      time.className = "modified-time";
      const day = document.createElement("span"); day.textContent = dateFormat.format(date);
      const hour = document.createElement("span"); hour.className = "modified-hour"; hour.textContent = hourFormat.format(date);
      time.append(day, " ", hour);
    }
    return time;
  }
  function highlighted(node, text) {
    const start = search ? text.toLocaleLowerCase("fr").indexOf(search.toLocaleLowerCase("fr")) : -1;
    if (start < 0) { node.textContent = text; return; }
    node.append(document.createTextNode(text.slice(0, start)));
    const mark = document.createElement("mark"); mark.textContent = text.slice(start, start + search.length);
    node.append(mark, document.createTextNode(text.slice(start + search.length)));
  }
  function breadcrumbs() {
    const root = $("breadcrumbs"); root.replaceChildren();
    const add = (name, path) => {
      if (root.childNodes.length) { const divider = document.createElement("span"); divider.textContent = "/"; divider.setAttribute("aria-hidden", "true"); root.append(divider); }
      const button = document.createElement("button"); button.type = "button"; button.textContent = name;
      button.title = path || "Tous les fichiers";
      button.addEventListener("click", () => navigate(path)); root.append(button);
    };
    add("Fichiers", "");
    if (search) { const label = document.createElement("span"); label.textContent = "/ Recherche"; root.append(label); }
    else { let path = ""; for (const part of directory.split("/").filter(Boolean)) { path += (path ? "/" : "") + part; add(part, path); } }
    root.lastElementChild.setAttribute("aria-current", "page");
    root.scrollLeft = root.scrollWidth;
  }
  function navigate(path) {
    clearTimeout(searchTimer);
    if (displayedQuery && path === directory && !search && !listingRequest && !retryView) return;
    $("search").value = ""; $("clear-search").hidden = true;
    load({directory: path, search: "", pageIndex: 0, cursors: [""]});
  }
  for (const link of [$("files-nav"), document.querySelector(".brand")]) link.addEventListener("click", event => {
    if (!statusPage && session && event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
      event.preventDefault(); navigate("");
    }
  });
  function validateEntry(entry) {
    return entry && ["directory", "file"].includes(entry.kind) && typeof entry.path === "string" && entry.path.length > 0 && entry.path.length <= 8192 &&
      (Number.isSafeInteger(entry.size) && entry.size >= 0 || entry.kind === "directory" && entry.size === null) &&
      (entry.updated_at == null || Number.isSafeInteger(entry.updated_at) && entry.updated_at >= 0 && entry.updated_at <= 8640000000000) &&
      (entry.kind === "directory" || (Number.isSafeInteger(entry.revision) && entry.revision > 0 && /^[a-f0-9]{64}$/.test(entry.sha256)));
  }
  const currentView = () => ({directory, search, pageIndex, cursors: [...cursors]});
  function listingBusy(busy) {
    clearDrop(); updateUploadButton();
    $("file-table").setAttribute("aria-busy", String(busy));
    $("refresh").setAttribute("aria-disabled", String(busy));
    $("previous-page").setAttribute("aria-disabled", String(busy)); $("next-page").setAttribute("aria-disabled", String(busy));
    if (!busy) { $("refresh").classList.remove("is-loading"); $("listing-status").textContent = ""; }
  }
  async function load(view = currentView()) {
    if (!session) return;
    listingRequest?.abort(); closeMenu();
    const controller = new AbortController(); listingRequest = controller;
    const current = epoch;
    retryView = view;
    listingBusy(true);
    if (!displayedQuery) { $("count").textContent = "Chargement des fichiers…"; $("empty").hidden = true; $("file-table").hidden = false; }
    const waiting = setTimeout(() => {
      if (listingRequest === controller && !controller.signal.aborted) {
        $("refresh").classList.add("is-loading"); $("listing-status").textContent = displayedQuery ? "Chargement des fichiers…" : "";
      }
    }, 180);
    try {
      const params = new URLSearchParams({directory: view.search ? "" : view.directory, search: view.search, after: view.cursors[view.pageIndex]});
      const query = params.toString();
      const value = await request(`/v1/web/files/entries?${params}`, {signal: controller.signal, limit: 12 * 1024 * 1024});
      if (current !== epoch || controller.signal.aborted) return;
      if (!Array.isArray(value.entries) || value.entries.length > 200 || !value.entries.every(validateEntry) || (value.next !== null && (typeof value.next !== "string" || value.next.length > 8194))) throw new Failure("invalid_response");
      const sameView = query === displayedQuery;
      const sameEntries = sameView && value.entries.length === displayedEntries.length && value.entries.every((entry, index) =>
        ["kind", "path", "size", "revision", "sha256", "updated_at"].every(key => entry[key] === displayedEntries[index][key]));
      const active = document.activeElement;
      const focusInListing = $("rows").contains(active) || $("breadcrumbs").contains(active);
      if (!sameView) closeDetails();
      ({directory, search, pageIndex, cursors} = view);
      next = value.next;
      retryView = undefined;
      $("search").value = search; $("clear-search").hidden = !search;
      if (!sameView) {
        breadcrumbs(); $("listing-title").textContent = search ? "Résultats de recherche" : directory ? basename(directory) : "Tous les fichiers";
        $("listing-title").title = search ? `Recherche : ${search}` : directory || "Tous les fichiers";
      }
      $("listing-message").hidden = true;
      const count = value.entries.length;
      $("count").textContent = `${count}${next ? "+" : ""} ${search ? `fichier${count === 1 ? "" : "s"} trouvé${count === 1 ? "" : "s"}` : `élément${count === 1 ? "" : "s"}`}${pageIndex ? ` · page ${pageIndex + 1}` : ""}`;
      if (!sameEntries) {
        const rows = document.createDocumentFragment();
        for (const entry of value.entries) {
          const row = document.createElement("tr");
          if (search) row.classList.add("search-row");
          const nameCell = document.createElement("td");
          const button = document.createElement("button"); button.type = "button"; button.className = "entry-button"; button.title = entry.path;
          if (entry.kind === "file") { button.setAttribute("aria-controls", "details"); button.setAttribute("aria-expanded", "false"); }
          const text = document.createElement("span"); text.className = "entry-text";
          const name = document.createElement("span"); name.className = "entry-name"; highlighted(name, basename(entry.path)); text.append(name);
          if (search) { const path = document.createElement("span"); path.className = "entry-path"; highlighted(path, entry.path); text.append(path); }
          button.append(icon(kindIcon(entry), `file-icon ${kindIcon(entry)}`), text);
          button.addEventListener("click", () => entry.kind === "directory" ? navigate(entry.path) : details(entry, button));
          row.addEventListener("click", event => { if (!event.target.closest("button") && !getSelection()?.toString()) button.click(); });
          nameCell.append(button); row.append(nameCell);
          const sizeCell = document.createElement("td"); sizeCell.textContent = size(entry.size);
          if (entry.kind === "directory") sizeCell.className = "folder-meta";
          const modifiedCell = document.createElement("td"); modifiedCell.append(modifiedTime(entry.updated_at));
          row.append(sizeCell, modifiedCell);
          const actions = document.createElement("td");
          if (entry.kind === "file") {
            const more = document.createElement("button"); more.type = "button"; more.className = "more-button";
            more.setAttribute("aria-label", `Actions pour ${basename(entry.path)}`); more.setAttribute("aria-haspopup", "menu"); more.setAttribute("aria-expanded", "false"); more.setAttribute("aria-controls", "file-menu"); more.append(icon("more"));
            more.addEventListener("click", () => openMenu(entry, more)); actions.append(more);
          }
          row.append(actions); rows.append(row);
        }
        $("rows").replaceChildren(rows);
        if (selected) {
          const index = value.entries.findIndex(entry => entry.kind === "file" && entry.path === selected.path);
          if (index < 0) closeDetails();
          else details(value.entries[index], $("rows").children[index].querySelector(".entry-button"), false);
        }
      }
      displayedQuery = query;
      if (!sameEntries) displayedEntries = value.entries;
      $("file-table").hidden = !count;
      $("empty").hidden = Boolean(count);
      $("empty-title").textContent = search ? "Aucun résultat" : "Aucun fichier pour le moment";
      $("empty-description").textContent = search ? "Essayez un autre nom ou un autre chemin de fichier." : "Vos fichiers apparaîtront ici après la première synchronisation.";
      $("empty-reset").hidden = !search;
      $("previous-page").hidden = pageIndex === 0; $("next-page").hidden = !next;
      if (!sameView && (focusInListing || active?.closest(".pagination") && active.hidden)) $("listing-title").focus({preventScroll: true});
    } catch (error) {
      if (controller.signal.aborted || current !== epoch) return;
      if (error.code === "session_expired" || error.code === "authentication_refused") { lock("expired"); return; }
      if (!displayedQuery) $("count").textContent = "Liste indisponible";
      $("listing-message").hidden = false;
      $("listing-message").textContent = `Impossible de charger les fichiers.${displayedQuery ? " La liste précédente est conservée." : ""} Réessayez avec le bouton d’actualisation en haut de la page.`;
    } finally {
      clearTimeout(waiting);
      if (listingRequest === controller) { listingRequest = undefined; listingBusy(false); }
    }
  }
  function details(entry, button, focus = true) {
    closeMenu(); closeDetails(); selected = entry; selectedButton = button;
    button.closest("tr")?.classList.add("selected");
    button.setAttribute("aria-expanded", "true");
    $("detail-name").textContent = basename(entry.path); $("detail-path").textContent = entry.path;
    $("detail-size").textContent = size(entry.size); $("detail-revision").textContent = entry.revision; $("detail-hash").textContent = entry.sha256;
    $("detail-modified").replaceChildren(modifiedTime(entry.updated_at, true));
    $("detail-icon").setAttribute("class", `detail-icon ${kindIcon(entry)}`); setIcon("detail-icon", kindIcon(entry));
    $("details").hidden = false;
    detailsLayout();
    if (focus) { document.querySelector(".details-content").scrollTop = 0; $("details").focus({preventScroll: true}); }
  }
  function detailsLayout() {
    const overlay = !$("details").hidden && matchMedia("(max-width: 1100px)").matches;
    document.querySelector(".file-list").inert = overlay;
    $("details-dismiss").hidden = !overlay;
    clearDrop(); updateUploadButton();
  }
  function openMenu(entry, button) {
    if (menuButton === button) { closeMenu(true); return; }
    closeMenu(); menuEntry = entry; menuButton = button;
    menu.hidden = false; button.setAttribute("aria-expanded", "true");
    const rect = button.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(innerWidth - menu.offsetWidth - 8, rect.right - menu.offsetWidth))}px`;
    menu.style.top = `${Math.max(8, rect.bottom + menu.offsetHeight + 8 > innerHeight ? rect.top - menu.offsetHeight - 4 : rect.bottom + 4)}px`;
    menu.querySelector("button").focus();
  }
  menu.addEventListener("keydown", event => {
    const buttons = [...menu.querySelectorAll("button")];
    const index = buttons.indexOf(document.activeElement);
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      buttons[event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
    } else if (event.key === "Tab") { event.preventDefault(); closeMenu(true); }
  });
  menu.addEventListener("click", async event => {
    const action = event.target.closest("button")?.dataset.action;
    const entry = menuEntry, button = menuButton;
    if (!entry || !action) return;
    closeMenu(true);
    if (action === "details") details(entry, button.closest("tr").querySelector(".entry-button"));
    if (action === "download") download(entry);
    if (action === "copy") {
      const current = epoch;
      try { await navigator.clipboard.writeText(entry.path); if (current === epoch && session) toast("Chemin copié."); }
      catch (_) { if (current === epoch && session) { details(entry, button.closest("tr").querySelector(".entry-button")); toast("Copie indisponible. Le chemin complet est affiché dans les détails."); } }
    }
  });
  document.addEventListener("pointerdown", event => { if (!menu.contains(event.target) && !menuButton?.contains(event.target)) closeMenu(); });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    if (!menu.hidden) { closeMenu(true); event.preventDefault(); }
    else if (!$("details").hidden) { closeDetails(true); event.preventDefault(); }
    else if (matchMedia("(max-width: 760px)").matches && !$("sidebar").hidden) { sidebar(true); $("sidebar-toggle").focus(); }
  });
  addEventListener("resize", () => {
    closeMenu(true);
    detailsLayout();
  });
  addEventListener("scroll", () => closeMenu(), true);
  $("details-close").addEventListener("click", () => closeDetails(true));
  $("details-dismiss").addEventListener("click", () => closeDetails(true));
  $("detail-download").addEventListener("click", () => { if (selected) download(selected); });
  $("refresh").addEventListener("click", () => { if (!listingRequest) { clearTimeout(searchTimer); load(retryView || currentView()); } });
  $("next-page").addEventListener("click", () => { if (next && !listingRequest) load({...currentView(), pageIndex: pageIndex + 1, cursors: [...cursors.slice(0, pageIndex + 1), next]}); });
  $("previous-page").addEventListener("click", () => { if (pageIndex && !listingRequest) load({...currentView(), pageIndex: pageIndex - 1}); });
  const searchChanged = () => {
    if (!session) return;
    clearTimeout(searchTimer); listingRequest?.abort(); closeMenu();
    const view = {directory, search: $("search").value.trim(), pageIndex: 0, cursors: [""]};
    $("clear-search").hidden = !$("search").value;
    retryView = view;
    clearDrop(); updateUploadButton();
    searchTimer = setTimeout(() => load(view), 180);
  };
  $("search").addEventListener("input", searchChanged);
  for (const id of ["clear-search", "empty-reset"]) $(id).addEventListener("click", () => { $("search").value = ""; searchChanged(); $("search").focus(); });
  function toast(message, ongoing = false) {
    clearTimeout(toastTimer); $("toast-message").textContent = message; $("toast").hidden = false;
    $("download-cancel").hidden = !ongoing; $("toast-close").hidden = ongoing;
    if (!ongoing) toastTimer = setTimeout(hideToast, 8000);
  }
  $("toast-close").addEventListener("click", hideToast);
  $("download-cancel").addEventListener("click", () => transfer?.abort());
  async function download(entry) {
    if (!session) return;
    if (upload) { toast("Attendez la fin de l’envoi ou annulez-le avant de télécharger."); return; }
    if (transfer) { toast("Un téléchargement est déjà en préparation.", true); return; }
    if (entry.size > session.download_limit) { toast("Ce fichier dépasse la limite web de 256 Mio. Retrouvez-le dans votre dossier synchronisé."); return; }
    const controller = new AbortController(); transfer = controller;
    updateUploadButton();
    const current = epoch; const limit = session.chunk_bytes;
    toast(`Préparation du téléchargement · ${basename(entry.path)}`, true);
    try {
      const data = new Uint8Array(entry.size);
      let offset = 0;
      do {
        const query = new URLSearchParams({path: entry.path, revision: String(entry.revision), offset: String(offset)});
        const part = await request(`/v1/web/files/chunk?${query}`, {signal: controller.signal, raw: true, limit, timeout: 30000});
        if (part.length !== Math.min(limit, entry.size - offset)) throw new Failure("invalid_response");
        data.set(part, offset); offset += part.length;
        toast(`Préparation du téléchargement · ${entry.size ? Math.floor(offset / entry.size * 100) : 100} %`, true);
      } while (offset < entry.size);
      const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(byte => byte.toString(16).padStart(2, "0")).join("");
      if (digest !== entry.sha256) throw new Failure("integrity_failed");
      await request("/v1/web/files/session", {signal: controller.signal});
      if (controller.signal.aborted || current !== epoch || !session) return;
      const url = URL.createObjectURL(new Blob([data], {type: "application/octet-stream"}));
      const link = document.createElement("a"); link.href = url; link.download = basename(entry.path); document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(`Téléchargement lancé · ${basename(entry.path)}`);
    } catch (error) {
      if (current !== epoch || !session) return;
      if (error.code === "session_expired" || error.code === "authentication_refused") { lock("expired"); return; }
      toast(controller.signal.aborted ? "Téléchargement annulé." : error.code === "revision_changed" ? "Ce fichier a changé. Actualisez la liste avant de réessayer." : error.code === "integrity_failed" ? "Le fichier reçu ne correspond pas à son empreinte. Téléchargement interrompu." : "Téléchargement interrompu. Vérifiez la connexion et réessayez.");
    } finally { if (transfer === controller) transfer = undefined; updateUploadButton(); }
  }
  function canUpload() {
    return !statusPage && session?.upload_limit === 268435456 && !upload && !transfer &&
      Boolean(displayedQuery) && !search && !$("search").value.trim() && !listingRequest && !retryView && !document.querySelector(".file-list").inert;
  }
  function updateUploadButton() {
    $("upload-add").disabled = !canUpload();
    $("upload-add").title = search || $("search").value.trim() ? "Ouvrez un dossier pour ajouter des fichiers" :
      session && !session.upload_limit ? "L’envoi nécessite une mise à jour du serveur" : "Ajouter des fichiers au dossier ouvert";
  }
  function clearDrop() { dragDepth = 0; $("drop-overlay").hidden = true; }
  function fileDrag(event) { return [...(event.dataTransfer?.types || [])].includes("Files"); }
  const dropTarget = $("drop-target");
  // Prevent the browser from navigating to a dropped file, even outside the target.
  document.addEventListener("dragover", event => {
    if (!fileDrag(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = canUpload() && !dragCancelled && dropTarget.contains(event.target) ? "copy" : "none";
  });
  document.addEventListener("drop", event => { if (fileDrag(event)) event.preventDefault(); clearDrop(); dragCancelled = false; });
  document.addEventListener("dragend", () => { clearDrop(); dragCancelled = false; });
  document.addEventListener("dragleave", event => { if (!event.relatedTarget && (event.target === document.documentElement || event.target === document)) { clearDrop(); dragCancelled = false; } });
  dropTarget.addEventListener("dragenter", event => {
    if (!fileDrag(event) || !canUpload() || dragCancelled) return;
    event.preventDefault(); dragDepth++;
    closeMenu();
    $("drop-description").textContent = directory ? `Ils seront ajoutés au dossier ${basename(directory)}` : "Ils seront ajoutés à Tous les fichiers";
    $("drop-path").textContent = `Fichiers${directory ? ` / ${directory.split("/").join(" / ")}` : ""}`;
    $("drop-overlay").hidden = false;
  });
  dropTarget.addEventListener("dragleave", event => {
    if (fileDrag(event) && --dragDepth <= 0) clearDrop();
  });
  dropTarget.addEventListener("drop", event => {
    if (!fileDrag(event)) return;
    event.preventDefault();
    const allowed = canUpload() && !dragCancelled;
    clearDrop();
    if (!allowed) return;
    const items = [...(event.dataTransfer.items || [])].filter(item => item.kind === "file");
    if (items.some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
      toast("Déposez des fichiers uniquement. L’envoi de dossiers n’est pas pris en charge."); return;
    }
    sendFiles([...event.dataTransfer.files], directory);
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !$("drop-overlay").hidden) { event.preventDefault(); event.stopImmediatePropagation(); clearDrop(); dragCancelled = true; }
  }, true);
  $("upload-add").addEventListener("click", () => {
    if (!canUpload()) return;
    pickerContext = {directory, epoch}; $("upload-input").value = ""; $("upload-input").click();
  });
  $("upload-input").addEventListener("change", event => {
    const files = [...event.target.files], context = pickerContext;
    event.target.value = ""; pickerContext = undefined;
    if (!files.length || !context || context.epoch !== epoch) return;
    if (!canUpload() || directory !== context.directory) { toast("Le dossier a changé. Sélectionnez à nouveau vos fichiers."); return; }
    sendFiles(files, context.directory);
  });
  $("upload-cancel").addEventListener("click", () => upload?.abort());
  $("upload-close").addEventListener("click", () => { $("upload-status").hidden = true; $("upload-results").replaceChildren(); });
  const uploadErrors = {
    file_exists: "Ce nom existe déjà. Le fichier existant a été conservé ; renommez le fichier à envoyer.",
    path_conflict: "Un fichier ou dossier occupe déjà ce chemin.",
    invalid_upload: "Nom ou taille de fichier non pris en charge.",
    integrity_failed: "Le contenu reçu ne correspond pas à son empreinte. Réessayez.",
    upload_limit: "Trop d’envois en attente. Réessayez après leur expiration.",
    files_write_disabled: "L’envoi n’est pas autorisé sur cet appareil.",
    files_read_disabled: "La lecture web doit être autorisée sur cet appareil.",
    local_rejected: "Le client local doit être mis à jour pour prendre en charge l’envoi.",
    pending: "L’autorisation d’envoi n’a pas été confirmée. Vérifiez le client local et réessayez.",
    files_write_required: "L’autorisation d’envoi a expiré. Réessayez.",
    invalid_response: "Réponse du serveur invalide. Actualisez la liste avant de réessayer."
  };
  async function authorizeUpload(signal) {
    try { await request("/v1/web/files/write/session", {signal}); return; }
    catch (error) { if (error.code !== "files_write_required") throw error; }
    const challenge = await post("/v1/web/files/write/challenges", signal);
    if (!/^[a-f0-9]{64}$/.test(challenge.challenge_id) || typeof challenge.ticket !== "string" || challenge.ticket.length > 2048) throw new Failure("invalid_response");
    let localError;
    try {
      const local = await request("http://127.0.0.1:47831/v1/status", {local: true, signal, timeout: 30000,
        headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": challenge.ticket}});
      if (!local.response.ok) localError = local.data.error;
    } catch (_) { /* Check the server even when the bridge acknowledgement is lost. */ }
    if (signal.aborted) throw new Failure("cancelled");
    try { await request(`/v1/web/files/write/challenges/${challenge.challenge_id}`, {signal}); }
    catch (error) {
      if (error.code === "pending" && ["files_write_disabled", "files_read_disabled"].includes(localError)) throw new Failure(localError);
      if (error.code === "pending" && localError === "invalid_challenge") throw new Failure("local_rejected");
      throw error;
    }
  }
  async function sendFiles(files, destination) {
    if (!canUpload() || !files.length) return;
    if (files.length > 50) { toast("Ajoutez au maximum 50 fichiers à la fois."); return; }
    const current = epoch, controller = new AbortController(); upload = controller; clearDrop(); updateUploadButton();
    const {signal} = controller, limit = session.upload_limit, chunkBytes = session.chunk_bytes;
    let sent = 0, rejected = 0, activeId, committing = false;
    const live = () => current === epoch && Boolean(session);
    const check = () => { if (!live() || signal.aborted) throw new Failure("cancelled"); };
    const result = (name, message, error) => {
      const row = document.createElement("li"); row.textContent = `${name} — ${message}`;
      if (error) row.className = "upload-error";
      $("upload-results").append(row); $("upload-results").hidden = false;
    };
    $("upload-status").hidden = false; $("upload-results").replaceChildren(); $("upload-results").hidden = true;
    $("upload-help").hidden = true; $("upload-close").hidden = true; $("upload-cancel").hidden = false;
    $("upload-progress").hidden = false; $("upload-progress").value = 0;
    $("upload-destination").textContent = `Vers ${destination ? `Fichiers / ${destination}` : "Tous les fichiers"}`;
    $("upload-message").textContent = "Vérification de l’autorisation d’envoi…";
    try {
      await authorizeUpload(signal); check();
      for (let index = 0; index < files.length; index++) {
        check(); const file = files[index];
        const path = `${destination ? destination + "/" : ""}${file.name}`;
        const bytes = new TextEncoder();
        if (!file.name || /[/\\\0]/.test(file.name) || [".", "..", ".mysync-conflicts", ".mysync-staging"].includes(file.name) || bytes.encode(file.name).length > 255 || bytes.encode(path).length > 4096 || file.size > limit) {
          rejected++; result(file.name, file.size > limit ? "Limite de 256 Mio par fichier dépassée." : "Nom de fichier non pris en charge.", true); continue;
        }
        try {
          $("upload-message").textContent = `Préparation · ${index + 1}/${files.length} · ${file.name}`;
          $("upload-progress").value = 0;
          // Only one file is hashed at a time; the bounded buffer is released
          // before transferring 8 MiB slices from the original File.
          const sha256 = [...new Uint8Array(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()))].map(byte => byte.toString(16).padStart(2, "0")).join("");
          check();
          const started = await request("/v1/web/files/uploads", {method: "POST", signal,
            headers: {"Content-Type": "application/json"}, body: JSON.stringify({path, size: file.size, sha256})});
          if (!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(started.id) || started.offset !== 0) throw new Failure("invalid_response");
          activeId = started.id;
          let offset = 0;
          while (offset < file.size) {
            check();
            const end = Math.min(offset + chunkBytes, file.size);
            $("upload-message").textContent = `Envoi · ${index + 1}/${files.length} · ${file.name}`;
            const part = await request(`/v1/web/files/uploads/${activeId}?offset=${offset}`, {method: "PUT", signal, timeout: 30000,
              headers: {"Content-Type": "application/octet-stream"}, body: file.slice(offset, end)});
            if (part.id !== activeId || part.offset !== end) throw new Failure("invalid_response");
            offset = end; $("upload-progress").value = Math.floor(offset / file.size * 100);
          }
          check(); committing = true;
          $("upload-message").textContent = `Confirmation · ${file.name}`;
          const entry = await post(`/v1/web/files/uploads/${activeId}/commit`, signal);
          if (entry.path !== path || entry.sha256 !== sha256 || entry.size !== file.size || entry.deleted || !Number.isSafeInteger(entry.revision) || entry.revision <= 0) throw new Failure("invalid_response");
          activeId = undefined; committing = false; check(); sent++;
          $("upload-progress").value = 100; result(file.name, "Envoyé", false);
        } catch (error) {
          if (signal.aborted || !live() || ["session_expired", "authentication_refused", "files_write_required"].includes(error.code)) throw error;
          rejected++; result(file.name, committing ? "Envoi non confirmé. Actualisez la liste avant de réessayer." : uploadErrors[error.code] || "Envoi interrompu. Vérifiez la connexion et réessayez.", true);
        } finally {
          if (activeId && live()) await request(`/v1/web/files/uploads/${activeId}`, {method: "DELETE", timeout: 5000}).catch(() => {});
          activeId = undefined;
        }
        committing = false;
      }
      check();
      $("upload-message").textContent = `${sent} fichier${sent === 1 ? "" : "s"} envoyé${sent === 1 ? "" : "s"}${rejected ? ` · ${rejected} non envoyé${rejected === 1 ? "" : "s"}` : ""}`;
    } catch (error) {
      if (!live()) return;
      if (["session_expired", "authentication_refused"].includes(error.code)) { lock("expired"); return; }
      $("upload-message").textContent = signal.aborted ? (committing ? "Envoi interrompu pendant la confirmation. Vérifiez la liste." : `Envoi annulé · ${sent} fichier${sent === 1 ? "" : "s"} déjà envoyé${sent === 1 ? "" : "s"}`) : uploadErrors[error.code] || "Envoi interrompu. Vérifiez la connexion et réessayez.";
      $("upload-help").hidden = !["files_write_disabled", "files_read_disabled", "local_rejected"].includes(error.code);
    } finally {
      if (upload === controller) upload = undefined;
      if (live()) {
        $("upload-cancel").hidden = true; $("upload-close").hidden = false; $("upload-progress").hidden = true;
        updateUploadButton();
        // Refresh the view currently open, never redirect back to a stale target.
        if (!listingRequest && !retryView) await load();
      }
    }
  }
  // Never restore private names from the back-forward cache without a fresh
  // server authorization. Only theme/navigation preferences use local storage.
  addEventListener("pagehide", () => lock());
  addEventListener("pageshow", event => { if (event.persisted) restore(); });
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && session && session.expires_at * 1000 <= Date.now()) lock("expired"); });
  restore();
})();
