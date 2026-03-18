const state = {
  authenticated: false,
  operator: "",
  status: null,
  profile: null,
  terminals: [],
  configuredVessel: null,
  upstreamNav: null,
  wan: null,
  logs: { events: [], commands: [] },
  currentView: "overview",
};

const els = {
  accessMode: document.getElementById("access-mode"),
  antennaForm: document.getElementById("antenna-form"),
  antennaStatus: document.getElementById("antenna-status"),
  ber: document.getElementById("ber"),
  cNo: document.getElementById("cNo"),
  carrierState: document.getElementById("carrier-state"),
  clock: document.getElementById("clock"),
  commandBody: document.getElementById("command-body"),
  connectionBanner: document.getElementById("connection-banner"),
  consoleCommand: document.getElementById("console-command"),
  consoleForm: document.getElementById("console-form"),
  consoleOutput: document.getElementById("console-output"),
  eventsBody: document.getElementById("events-body"),
  firmware: document.getElementById("firmware"),
  gps: document.getElementById("gps"),
  heading: document.getElementById("heading"),
  loginCard: document.getElementById("login-card"),
  loginForm: document.getElementById("login-form"),
  loginStatus: document.getElementById("login-status"),
  logoutButton: document.getElementById("logout-button"),
  networkForm: document.getElementById("network-form"),
  networkStatus: document.getElementById("network-status"),
  pageTitle: document.getElementById("page-title"),
  pitch: document.getElementById("pitch"),
  profileName: document.getElementById("profileName"),
  roll: document.getElementById("roll"),
  rxDbm: document.getElementById("rxDbm"),
  satelliteName: document.getElementById("satelliteName"),
  terminalBody: document.getElementById("terminal-body"),
  trackingMode: document.getElementById("trackingMode"),
  txDbm: document.getElementById("txDbm"),
  uploadFile: document.getElementById("upload-file"),
  uploadForm: document.getElementById("upload-form"),
  uploadStatus: document.getElementById("upload-status"),
  uptime: document.getElementById("uptime"),
  vesselImo: document.getElementById("vessel-imo"),
  vesselName: document.getElementById("vessel-name"),
};

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.view));
});

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.loginForm);
  const response = await fetchJson("/api/login", {
    method: "POST",
    body: JSON.stringify({
      username: form.get("username"),
      password: form.get("password"),
    }),
  });

  if (!response.ok) {
    els.loginStatus.textContent = "Login failed. Use admin / 1234.";
    return;
  }

  els.loginStatus.textContent = "Operator session opened.";
  await refresh();
});

els.logoutButton.addEventListener("click", async () => {
  await fetchJson("/api/logout", { method: "POST" });
  els.loginStatus.textContent = "Session closed. Read-only mode restored.";
  await refresh();
});

els.antennaForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.antennaForm);
  const response = await fetchJson("/api/config/antenna", {
    method: "POST",
    body: JSON.stringify({
      profileName: form.get("profileName"),
      satelliteName: form.get("satelliteName"),
      trackingMode: form.get("trackingMode"),
    }),
  });

  els.antennaStatus.textContent = response.ok
    ? "Antenna profile stored in decoy state."
    : "Authentication required for profile writes.";
  await refresh();
});

els.networkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.networkForm);
  const response = await fetchJson("/api/config/network", {
    method: "POST",
    body: JSON.stringify({
      targetIp: form.get("targetIp"),
      mask: form.get("mask"),
      gateway: form.get("gateway"),
    }),
  });

  els.networkStatus.textContent = response.ok
    ? "Network settings accepted and logged."
    : "Authentication required for network writes.";
  await refresh();
});

els.consoleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const command = els.consoleCommand.value.trim();
  if (!command) {
    return;
  }

  const response = await fetchJson("/api/command", {
    method: "POST",
    body: JSON.stringify({ command }),
  });

  if (response.ok) {
    els.consoleOutput.textContent = response.output.join("\n");
    els.consoleCommand.value = "";
  } else {
    els.consoleOutput.textContent = "authentication required";
  }

  await refresh();
});

els.uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.uploadStatus.classList.remove("success", "error");
  const file = els.uploadFile.files?.[0];
  if (!file) {
    els.uploadStatus.textContent = "Select a package file first.";
    els.uploadStatus.classList.add("error");
    return;
  }

  const response = await fetchJson("/api/upload", {
    method: "POST",
    body: JSON.stringify({
      filename: file.name,
      size: file.size,
      mime: file.type || "application/octet-stream",
    }),
  });

  els.uploadStatus.textContent = response.ok
    ? response.message
    : "Authentication file upload failed.";
  els.uploadStatus.classList.add(response.ok ? "success" : "error");

  if (response.ok) {
    els.uploadFile.value = "";
  }

  await refresh();
});

function switchView(view) {
  state.currentView = view;
  document.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
  els.pageTitle.textContent = ({
    overview: "Terminal Overview",
    antenna: "Antenna Control",
    network: "Network Services",
    events: "Alarm Register",
    console: "Maintenance Console",
  })[view];
  document.getElementById("breadcrumb-view").textContent = ({
    overview: "Overview",
    antenna: "Antenna",
    network: "Network",
    events: "Events",
    console: "Console",
  })[view];
}

async function refresh() {
  if (window.location.protocol === "file:") {
    els.connectionBanner.hidden = false;
    return;
  }

  const response = await fetchJson("/api/status");
  if (!response.httpOk) {
    els.connectionBanner.hidden = false;
    return;
  }

  els.connectionBanner.hidden = true;
  state.authenticated = response.authenticated;
  state.operator = response.operator;
  state.status = response.status;
  state.profile = response.profile;
  state.terminals = response.terminals;
  state.configuredVessel = response.configuredVessel;
  state.upstreamNav = response.upstreamNav;
  state.wan = response.wan;
  state.logs = response.logs;
  render();
}

function render() {
  const scrapedName = state.upstreamNav?.status === "live" ? state.upstreamNav.vesselName : "";
  els.vesselName.textContent = scrapedName || "Honeypot";
  els.vesselImo.textContent = `IMO: ${state.configuredVessel?.imo || "--"}`;
  els.accessMode.textContent = state.authenticated ? `Operator: ${state.operator}` : "Guest";
  els.logoutButton.hidden = !state.authenticated;
  els.loginCard.classList.toggle("collapsed", state.authenticated);
  els.loginCard.style.display = state.authenticated ? "none" : "grid";

  els.rxDbm.textContent = `${state.status.rxDbm} dBm`;
  els.txDbm.textContent = `${state.status.txDbm} dBm`;
  els.cNo.textContent = `${state.status.cNo} dB`;
  els.ber.textContent = state.status.ber;
  els.gps.textContent = state.status.gps;
  els.heading.textContent = `${state.status.heading} deg`;
  els.pitch.textContent = `${state.status.pitch} deg`;
  els.roll.textContent = `${state.status.roll} deg`;
  els.carrierState.textContent = state.terminals[0]?.status || "Tracking";

  els.profileName.textContent = state.profile.profileName;
  els.satelliteName.textContent = state.profile.satelliteName;
  els.trackingMode.textContent = state.profile.trackingMode;
  els.firmware.textContent = state.profile.firmware;
  els.uptime.textContent = `${state.profile.uptimeHours} h`;

  els.antennaForm.profileName.value = state.profile.profileName;
  els.antennaForm.satelliteName.value = state.profile.satelliteName;
  els.antennaForm.trackingMode.value = state.profile.trackingMode;

  els.networkForm.targetIp.value = state.wan.targetIp;
  els.networkForm.mask.value = state.wan.mask;
  els.networkForm.gateway.value = state.wan.gateway;

  els.terminalBody.innerHTML = state.terminals.map((terminal) => `
    <tr>
      <td>${escapeHtml(terminal.name)}</td>
      <td>${escapeHtml(terminal.status)}</td>
      <td>${escapeHtml(String(terminal.temperature))} C</td>
      <td>${escapeHtml(String(terminal.azimuth))} deg</td>
      <td>${escapeHtml(String(terminal.elevation))} deg</td>
    </tr>
  `).join("");

  els.eventsBody.innerHTML = state.logs.events.map((event) => `
    <tr>
      <td class="mono">${escapeHtml(event.ts)}</td>
      <td><span class="severity ${escapeHtml(event.level)}">${escapeHtml(event.level)}</span></td>
      <td class="mono">${escapeHtml(event.code)}</td>
      <td>${escapeHtml(event.message)}</td>
    </tr>
  `).join("");

  els.commandBody.innerHTML = state.logs.commands.map((entry) => `
    <tr>
      <td class="mono">${escapeHtml(entry.ts)}</td>
      <td>${escapeHtml(entry.operator)}</td>
      <td>${escapeHtml(entry.action)}</td>
      <td>${escapeHtml(entry.detail)}</td>
    </tr>
  `).join("");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  try {
    const payload = await response.json();
    if (payload && typeof payload === "object") {
      payload.httpOk = response.ok;
    }
    return payload;
  } catch {
    return { ok: false, httpOk: false };
  }
}

function updateClock() {
  els.clock.textContent = new Date().toLocaleString("en-GB", {
    hour12: false,
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
}

updateClock();
setInterval(updateClock, 1000);
switchView("overview");
refresh();
setInterval(refresh, 5000);
