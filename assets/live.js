const DATA_URL = "./data/hall-of-shame.json";

const state = {
  generatedAt: null,
  repos: [],
  findings: [],
  providerOptions: [],
};

const pagination = {
  page: 1,
  pageSize: 25,
};

const elements = {
  search: document.querySelector("#live-search"),
  provider: document.querySelector("#live-provider"),
  severity: document.querySelector("#live-severity"),
  list: document.querySelector("#live-list"),
  empty: document.querySelector("#live-empty"),
  meta: document.querySelector("#live-meta"),
  pager: document.querySelector("#live-pager"),
  pagerMeta: document.querySelector("#live-pager-meta"),
  pagerPrev: document.querySelector("#live-prev"),
  pagerNext: document.querySelector("#live-next"),
};

const severityOrder = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function maskSecret(secret) {
  const raw = String(secret || "").trim();
  if (!raw) {
    return "redacted";
  }
  if (raw.length <= 8) {
    return `${raw.slice(0, 2)}${"*".repeat(Math.max(raw.length - 4, 2))}${raw.slice(-2)}`;
  }
  return `${raw.slice(0, 4)}${"*".repeat(Math.min(raw.length - 8, 24))}${raw.slice(-4)}`;
}

function deriveSeverity(totalSecrets, uniqueTypes, commitFindings) {
  const score = totalSecrets * 12 + uniqueTypes * 8 + commitFindings * 10;
  if (score >= 110) {
    return "critical";
  }
  if (score >= 70) {
    return "high";
  }
  if (score >= 35) {
    return "medium";
  }
  return "low";
}

function buildFinding(rawFinding) {
  const file = rawFinding.file || "unknown";
  const source = file.startsWith("Commit ") ? "commit" : (rawFinding.source || "file");
  const preview = rawFinding.preview || maskSecret(rawFinding.secret);

  return {
    file,
    line: Number(rawFinding.line) || 0,
    type: rawFinding.type || "Unknown Secret",
    preview,
    source,
  };
}

function normalizeRepo(rawRepo, index) {
  const findings = Array.isArray(rawRepo.findings) ? rawRepo.findings.map(buildFinding) : [];
  const typeCounts = rawRepo.typeCounts && typeof rawRepo.typeCounts === "object" ? rawRepo.typeCounts : null;
  const filesAffected = rawRepo.filesAffected || new Set(findings.map((finding) => finding.file)).size;
  const uniqueTypes =
    rawRepo.uniqueTypes || (typeCounts ? Object.keys(typeCounts).length : new Set(findings.map((finding) => finding.type)).size);
  const commitFindings = rawRepo.commitFindings || findings.filter((finding) => finding.source === "commit").length;
  const totalSecrets = Number(rawRepo.totalSecrets ?? rawRepo.total_secrets ?? findings.length) || findings.length;
  const severity = rawRepo.severity || deriveSeverity(totalSecrets, uniqueTypes, commitFindings);

  return {
    repo: rawRepo.repo || rawRepo.name || `unknown-repo-${index + 1}`,
    url: rawRepo.url || "#",
    status: rawRepo.status || "leaked",
    severity,
    totalSecrets,
    uniqueTypes,
    filesAffected,
    commitFindings,
    scanTimeSeconds: Number(rawRepo.scanTimeSeconds ?? rawRepo.time_taken ?? 0) || 0,
    exposureScore: Number(rawRepo.exposureScore) || totalSecrets * 12 + uniqueTypes * 8 + commitFindings * 10,
    typeCounts,
    findings,
  };
}

function normalizePayload(payload) {
  if (Array.isArray(payload)) {
    return {
      generatedAt: null,
      repos: payload.map(normalizeRepo).filter((repo) => repo.status === "leaked"),
    };
  }

  const rawRepos = Array.isArray(payload?.repos) ? payload.repos : [];
  return {
    generatedAt: payload?.generatedAt || null,
    repos: rawRepos.map(normalizeRepo).filter((repo) => repo.status === "leaked"),
  };
}

function formatGeneratedAt(value) {
  if (!value) {
    return "Sample data";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return escapeHtml(value);
  }

  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function extractOwner(repo) {
  if (repo.url && repo.url.includes("github.com/")) {
    const [, after] = repo.url.split("github.com/");
    const [owner] = after.split("/");
    if (owner) {
      return owner;
    }
  }
  if (repo.repo && repo.repo.includes("/")) {
    return repo.repo.split("/")[0];
  }
  return "unknown";
}

function buildProviderOptions(findings) {
  const providers = new Set();
  findings.forEach((finding) => providers.add(finding.type));
  return [...providers].sort((a, b) => a.localeCompare(b));
}

function buildFindings(repos) {
  return repos.flatMap((repo) =>
    repo.findings.map((finding) => ({
      repo: repo.repo,
      url: repo.url,
      owner: extractOwner(repo),
      severity: repo.severity,
      type: finding.type,
      file: finding.file,
      line: finding.line,
      preview: finding.preview,
      source: finding.source,
    }))
  );
}

function getFilters() {
  return {
    query: elements.search.value.trim().toLowerCase(),
    provider: elements.provider.value,
    severity: elements.severity.value,
  };
}

function matchesFilters(item, filters) {
  if (filters.provider !== "all" && item.type !== filters.provider) {
    return false;
  }

  if (filters.severity !== "all" && item.severity !== filters.severity) {
    return false;
  }

  if (!filters.query) {
    return true;
  }

  const haystack = [item.repo, item.owner, item.type, item.file, item.preview]
    .join(" ")
    .toLowerCase();

  return haystack.includes(filters.query);
}

function updatePager(total, startIndex, endIndex) {
  if (!elements.pager || !elements.pagerMeta || !elements.pagerPrev || !elements.pagerNext) {
    return;
  }

  if (!total) {
    elements.pager.hidden = true;
    return;
  }

  elements.pager.hidden = false;
  const totalPages = Math.max(1, Math.ceil(total / pagination.pageSize));
  const safeEnd = Math.min(endIndex, total);
  elements.pagerMeta.textContent = `Showing ${startIndex + 1}-${safeEnd} of ${total} | Page ${pagination.page} of ${totalPages}`;
  elements.pagerPrev.disabled = pagination.page <= 1;
  elements.pagerNext.disabled = pagination.page >= totalPages;
}

function renderList() {
  const filters = getFilters();
  const filtered = state.findings
    .filter((item) => matchesFilters(item, filters))
    .sort((left, right) => {
      const severityDiff = (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
      if (severityDiff !== 0) {
        return severityDiff;
      }
      return left.repo.localeCompare(right.repo);
    });

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / pagination.pageSize));
  if (pagination.page > totalPages) {
    pagination.page = totalPages;
  }

  if (!total) {
    elements.list.innerHTML = "";
    elements.empty.hidden = false;
    updatePager(0, 0, 0);
    return;
  }

  elements.empty.hidden = true;
  const startIndex = (pagination.page - 1) * pagination.pageSize;
  const endIndex = startIndex + pagination.pageSize;
  const pageItems = filtered.slice(startIndex, endIndex);

  elements.list.innerHTML = pageItems
    .map((item) => {
      const safeUrl = item.url && item.url !== "#" ? item.url : "#";
      const line = item.line ? `:${item.line}` : "";
      return `
        <div class="list-row">
          <div class="list-main">
            <div class="list-title">
              <a class="repo-link" href="${escapeHtml(safeUrl)}" target="_blank" rel="noreferrer">${escapeHtml(
        item.repo
      )}</a>
              <span class="tag severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
              <span class="tag muted">${escapeHtml(item.type)}</span>
            </div>
            <div class="list-meta">${escapeHtml(item.file)}${line} · ${escapeHtml(item.source)}</div>
          </div>
          <code class="preview">${escapeHtml(item.preview)}</code>
        </div>
      `;
    })
    .join("");

  updatePager(total, startIndex, endIndex);
}

function populateProviderFilter(providers) {
  elements.provider.innerHTML = [
    '<option value="all">All providers</option>',
    ...providers.map((provider) => `<option value="${escapeHtml(provider)}">${escapeHtml(provider)}</option>`),
  ].join("");
}

async function loadDataset() {
  try {
    const response = await fetch(DATA_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const normalized = normalizePayload(payload);

    state.generatedAt = normalized.generatedAt;
    state.repos = normalized.repos;
    state.findings = buildFindings(state.repos);

    elements.meta.textContent = `Updated ${formatGeneratedAt(state.generatedAt)}`;

    state.providerOptions = buildProviderOptions(state.findings);
    populateProviderFilter(state.providerOptions);
    renderList();
  } catch (error) {
    elements.meta.textContent = "No data";
    elements.list.innerHTML = "";
    elements.empty.hidden = false;
  }
}

function handleFilterChange() {
  pagination.page = 1;
  renderList();
}

["input", "change"].forEach((eventName) => {
  elements.search.addEventListener(eventName, handleFilterChange);
  elements.provider.addEventListener(eventName, handleFilterChange);
  elements.severity.addEventListener(eventName, handleFilterChange);
});

if (elements.pagerPrev && elements.pagerNext) {
  elements.pagerPrev.addEventListener("click", () => {
    if (pagination.page > 1) {
      pagination.page -= 1;
      renderList();
    }
  });

  elements.pagerNext.addEventListener("click", () => {
    pagination.page += 1;
    renderList();
  });
}

loadDataset();
