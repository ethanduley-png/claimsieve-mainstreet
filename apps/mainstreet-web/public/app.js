const views = ["today", "ask", "inbox", "tasks", "notes", "approvals", "activity"];
const state = {
  businesses: [],
  tenantId: null,
  session: null,
};

const $ = (id) => document.getElementById(id);

function setView(name) {
  if (!views.includes(name)) return;
  for (const view of views) {
    $(`view-${view}`).hidden = view !== name;
  }
  for (const button of document.querySelectorAll("[data-view]")) {
    button.classList.toggle("active", button.dataset.view === name);
  }
}

function showOnly(id) {
  for (const viewId of ["loading-view", "signed-out-view", "no-business-view", "app-view"]) {
    $(viewId).hidden = viewId !== id;
  }
}

async function api(path, options = {}, tenantId = state.tenantId) {
  const headers = new Headers(options.headers ?? {});
  if (tenantId) {
    headers.set("x-mainstreet-tenant", tenantId);
  }
  if (options.body !== undefined && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  return fetch(path, {
    ...options,
    headers,
    credentials: "include",
    cache: "no-store",
    body:
      options.body !== undefined && typeof options.body !== "string"
        ? JSON.stringify(options.body)
        : options.body,
  });
}

async function jsonOrEmpty(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

function renderBusinessPicker() {
  const select = $("business-select");
  select.replaceChildren();
  for (const business of state.businesses) {
    const option = document.createElement("option");
    option.value = business.tenantId;
    option.textContent = business.tenantId;
    option.selected = business.tenantId === state.tenantId;
    select.append(option);
  }
  select.disabled = state.businesses.length < 2;
}

function renderToday(items) {
  const list = $("today-list");
  list.replaceChildren();
  if (!Array.isArray(items) || items.length === 0) {
    const empty = document.createElement("article");
    empty.className = "work-card calm";
    const title = document.createElement("h2");
    title.textContent = "Nothing urgent right now";
    const body = document.createElement("p");
    body.textContent = "MainStreet will surface work here as your connected systems come online.";
    empty.append(title, body);
    list.append(empty);
    return;
  }
  for (const item of items) {
    const card = document.createElement("article");
    card.className = "work-card";
    const title = document.createElement("h2");
    title.textContent = String(item.title ?? "Needs attention");
    const meta = document.createElement("p");
    meta.textContent = String(item.summary ?? item.id ?? "");
    card.append(title, meta);
    list.append(card);
  }
}

async function loadTenant() {
  const [sessionResponse, todayResponse] = await Promise.all([
    api("/v1/session"),
    api("/v1/today"),
  ]);
  if (sessionResponse.status === 401) {
    showOnly("signed-out-view");
    return;
  }
  if (!sessionResponse.ok || !todayResponse.ok) {
    throw new Error("Unable to load business");
  }
  state.session = await jsonOrEmpty(sessionResponse);
  const today = await jsonOrEmpty(todayResponse);
  $("role-badge").textContent = state.session.role ?? "";
  renderToday(today.items);
  showOnly("app-view");
  $("logout-link").hidden = false;
}

async function bootstrap() {
  try {
    const response = await api("/v1/businesses", {}, null);
    if (response.status === 401) {
      showOnly("signed-out-view");
      return;
    }
    if (!response.ok) {
      throw new Error("Unable to load memberships");
    }
    const payload = await jsonOrEmpty(response);
    state.businesses = Array.isArray(payload.businesses) ? payload.businesses : [];
    if (state.businesses.length === 0) {
      showOnly("no-business-view");
      $("logout-link").hidden = false;
      return;
    }

    const remembered = sessionStorage.getItem("mainstreet.tenant");
    const allowed = state.businesses.some((business) => business.tenantId === remembered);
    state.tenantId = allowed ? remembered : state.businesses[0].tenantId;
    sessionStorage.setItem("mainstreet.tenant", state.tenantId);
    renderBusinessPicker();
    await loadTenant();
  } catch {
    showOnly("signed-out-view");
  }
}

$("business-select").addEventListener("change", async (event) => {
  const requested = event.target.value;
  if (!state.businesses.some((business) => business.tenantId === requested)) {
    return;
  }
  state.tenantId = requested;
  sessionStorage.setItem("mainstreet.tenant", state.tenantId);
  showOnly("loading-view");
  await loadTenant();
});

for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => setView(button.dataset.view));
}

$("assistant-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = $("assistant-text").value.trim();
  if (!text) return;
  const result = $("assistant-result");
  result.hidden = false;
  result.textContent = "Preparing proposal…";
  const response = await api("/v1/assistant/requests", {
    method: "POST",
    body: { text },
  });
  const payload = await jsonOrEmpty(response);
  if (response.status === 202 && payload.executionAuthority === false) {
    result.textContent = "Request prepared. Any consequential action still requires the governed authorization path.";
    return;
  }
  result.textContent = "MainStreet could not prepare that request.";
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}

bootstrap();
