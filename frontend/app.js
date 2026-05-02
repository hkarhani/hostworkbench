const state = {
  hosts: [],
  groups: [],
  toastTimer: null,
};

const hostColumns = ["hostIP", "registered", "groups"];

const apiKeyForm = document.querySelector("#api-key-form");
const generateForm = document.querySelector("#generate-form");
const groupForm = document.querySelector("#group-form");
const clearHostsButton = document.querySelector("#clear-hosts");
const keyOutput = document.querySelector("#api-key-output");
const keyStatus = document.querySelector("#key-status");
const eventStatus = document.querySelector("#event-status");
const groupStatus = document.querySelector("#group-status");
const hostsTable = document.querySelector("#hosts-table");
const groupsGrid = document.querySelector("#groups-grid");
const hostCount = document.querySelector("#host-count");
const changedCount = document.querySelector("#changed-count");
const groupCount = document.querySelector("#group-count");
const membershipCount = document.querySelector("#membership-count");
const lastRefresh = document.querySelector("#last-refresh");
const toast = document.querySelector("#toast");

function showToast(message, isError = false) {
  window.clearTimeout(state.toastTimer);
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.hidden = false;
  state.toastTimer = window.setTimeout(() => {
    toast.hidden = true;
  }, 3200);
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const detail = data?.detail || response.statusText;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function formatValue(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function renderApiKey(data) {
  if (!data?.apiKey) {
    keyOutput.hidden = true;
    keyOutput.textContent = "";
    keyStatus.textContent = "Ready";
    return;
  }

  keyOutput.hidden = false;
  keyOutput.textContent = data.apiKey;
  keyStatus.textContent = data.keyPrefix || "Saved";
}

function createCell(host, field) {
  const td = document.createElement("td");
  const change = host.fieldChanges?.[field];
  if (field === "hostIP") {
    td.className = "ip-cell";
  }
  if (change) {
    td.classList.add("changed-cell");
  }

  const value = document.createElement("span");
  value.className = "value";
  if (typeof host[field] === "boolean") {
    value.className = `bool ${host[field] ? "true" : "false"}`;
  }
  if (Array.isArray(host[field])) {
    value.className = "chip-list";
    if (host[field].length) {
      host[field].forEach((item) => {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.textContent = item;
        value.appendChild(chip);
      });
    } else {
      value.textContent = "None";
    }
    td.appendChild(value);
  } else {
    value.textContent = formatValue(host[field]);
    td.appendChild(value);
  }

  if (change) {
    const note = document.createElement("small");
    note.className = "change-note";
    note.textContent = `${change.operation || "changed"} ${formatDate(change.changedAt)} via ${
      change.source || "api"
    }`;
    td.appendChild(note);
  }

  return td;
}

function renderHosts() {
  const hosts = state.hosts;
  const columns = hostColumns;
  const thead = hostsTable.querySelector("thead");
  const tbody = hostsTable.querySelector("tbody");
  thead.replaceChildren();
  tbody.replaceChildren();

  if (!hosts.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "empty-state";
    cell.colSpan = 1;
    cell.textContent = "No hosts yet.";
    row.appendChild(cell);
    tbody.appendChild(row);
    hostCount.textContent = "0";
    changedCount.textContent = "0";
    return;
  }

  const headerRow = document.createElement("tr");
  columns.forEach((column) => {
    const th = document.createElement("th");
    th.textContent = column;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);

  hosts.forEach((host) => {
    const row = document.createElement("tr");
    columns.forEach((column) => {
      row.appendChild(createCell(host, column));
    });
    tbody.appendChild(row);
  });

  hostCount.textContent = String(hosts.length);
  changedCount.textContent = String(hosts.filter((host) => Object.keys(host.fieldChanges || {}).length).length);
}

function renderGroups() {
  const groups = state.groups;
  groupsGrid.replaceChildren();

  groupCount.textContent = String(groups.length);
  groupStatus.textContent = `${groups.length} groups`;
  const memberships = groups.reduce((total, group) => total + (group.members?.length || 0), 0);
  membershipCount.textContent = `${memberships} memberships`;

  if (!groups.length) {
    const empty = document.createElement("div");
    empty.className = "empty-group-state";
    empty.textContent = "No groups yet.";
    groupsGrid.appendChild(empty);
    return;
  }

  groups.forEach((group) => {
    const article = document.createElement("article");
    article.className = "group-card";

    const header = document.createElement("div");
    header.className = "group-card-header";

    const title = document.createElement("h3");
    title.textContent = group.name;
    header.appendChild(title);

    const count = document.createElement("span");
    count.className = "status-pill";
    count.textContent = `${group.members?.length || 0} hosts`;
    header.appendChild(count);

    const members = document.createElement("div");
    members.className = "member-list";
    if (group.members?.length) {
      group.members.forEach((member) => {
        const chip = document.createElement("span");
        chip.className = "member-chip";
        chip.textContent = member;
        members.appendChild(chip);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "muted-text";
      empty.textContent = "No members";
      members.appendChild(empty);
    }

    article.appendChild(header);
    article.appendChild(members);
    groupsGrid.appendChild(article);
  });
}

async function loadHosts() {
  state.hosts = await fetchJson("/internal/hosts");
  lastRefresh.textContent = formatDate(new Date().toISOString());
  renderHosts();
}

async function loadGroups() {
  state.groups = await fetchJson("/internal/groups");
  renderGroups();
}

async function loadDashboard() {
  await Promise.all([loadHosts(), loadGroups()]);
}

async function loadApiKey() {
  const data = await fetchJson("/internal/api-keys/current");
  renderApiKey(data);
}

apiKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const label = document.querySelector("#key-label").value.trim() || "Host Workbench Demo Client";
  keyStatus.textContent = "Working";
  try {
    const data = await fetchJson("/internal/api-keys", {
      method: "POST",
      body: JSON.stringify({ label }),
    });
    renderApiKey(data);
    await navigator.clipboard?.writeText(data.apiKey);
    showToast("API key ready and copied");
  } catch (error) {
    keyStatus.textContent = "Error";
    showToast(error.message, true);
  }
});

generateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const subnet = document.querySelector("#subnet").value.trim();
  const count = Number(document.querySelector("#count").value);
  try {
    const data = await fetchJson("/internal/hosts/generate", {
      method: "POST",
      body: JSON.stringify({ subnet, count }),
    });
    await loadDashboard();
    showToast(`Generated ${data.generated} hosts`);
  } catch (error) {
    showToast(error.message, true);
  }
});

groupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const nameInput = document.querySelector("#group-name");
  const name = nameInput.value.trim();
  if (!name) {
    showToast("Enter a group name", true);
    return;
  }

  try {
    const data = await fetchJson("/internal/groups", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    nameInput.value = "";
    await loadGroups();
    showToast(`Group ${data.name} is ready`);
  } catch (error) {
    showToast(error.message, true);
  }
});

clearHostsButton.addEventListener("click", async () => {
  if (!window.confirm("Clear all host data while keeping the current API key?")) {
    return;
  }

  try {
    const data = await fetchJson("/internal/hosts", { method: "DELETE" });
    await loadDashboard();
    await loadApiKey();
    showToast(`Cleared ${data.deletedHosts} hosts`);
  } catch (error) {
    showToast(error.message, true);
  }
});

function startEvents() {
  const events = new EventSource("/internal/events");
  events.addEventListener("ready", () => {
    eventStatus.textContent = "Live";
    eventStatus.className = "status-pill live";
  });
  events.addEventListener("hosts_changed", async () => {
    await loadDashboard();
  });
  events.onerror = () => {
    eventStatus.textContent = "Reconnecting";
    eventStatus.className = "status-pill warn";
  };
}

Promise.all([loadDashboard(), loadApiKey()]).catch((error) => showToast(error.message, true));
startEvents();
