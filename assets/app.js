const DATA_URL = "./data/hall-of-shame.json";

const state = {
  sourceName: "unknown",
  generatedAt: null,
  repos: [],
  providerOptions: [],
};

const elements = {
  search: document.querySelector("#search-input"),
  severity: document.querySelector("#severity-filter"),
  provider: document.querySelector("#provider-filter"),
  source: document.querySelector("#source-filter"),
  sort: document.querySelector("#sort-select"),
  grid: document.querySelector("#repo-grid"),
  empty: document.querySelector("#empty-state"),
  providerList: document.querySelector("#provider-list"),
  datasetMeta: document.querySelector("#dataset-meta"),
  statusBanner: document.querySelector("#status-banner"),
  stats: {
    repos: document.querySelector('[data-stat="repos"]'),
    secrets: document.querySelector('[data-stat="secrets"]'),
    types: document.querySelector('[data-stat="types"]'),
    commitHits: document.querySelector('[data-stat="commitHits"]'),
  },
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
  const topTypes = Array.isArray(rawRepo.topTypes)
    ? rawRepo.topTypes
    : typeCounts
      ? Object.keys(typeCounts).slice(0, 4)
      : [...new Set(findings.map((finding) => finding.type))].slice(0, 4);

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
    exposureScore:
      Number(rawRepo.exposureScore) || totalSecrets * 12 + uniqueTypes * 8 + commitFindings * 10,
    topTypes,
    typeCounts,
    findings: findings.slice(0, 3),
  };
}

function normalizePayload(payload) {
  if (Array.isArray(payload)) {
    return {
      sourceName: "raw-import",
      generatedAt: null,
      repos: payload.map(normalizeRepo).filter((repo) => repo.status === "leaked"),
    };
  }

  const rawRepos = Array.isArray(payload?.repos) ? payload.repos : [];
  return {
    sourceName: payload?.source || "sanitized-export",
    generatedAt: payload?.generatedAt || null,
    repos: rawRepos.map(normalizeRepo).filter((repo) => repo.status === "leaked"),
  };
}

function sortRepos(repos, sortValue) {
  const sorted = [...repos];

  sorted.sort((left, right) => {
    if (sortValue === "repo") {
      return left.repo.localeCompare(right.repo);
    }
    if (sortValue === "scan") {
      return left.scanTimeSeconds - right.scanTimeSeconds;
    }
    if (sortValue === "secrets") {
      return right.totalSecrets - left.totalSecrets || right.exposureScore - left.exposureScore;
    }
    return right.exposureScore - left.exposureScore || right.totalSecrets - left.totalSecrets;
  });

  return sorted;
}

function buildProviderCounts(repos) {
  const counts = new Map();

  repos.forEach((repo) => {
    if (repo.typeCounts) {
      Object.entries(repo.typeCounts).forEach(([type, count]) => {
        counts.set(type, (counts.get(type) || 0) + Number(count || 0));
      });
      return;
    }

    repo.findings.forEach((finding) => {
      counts.set(finding.type, (counts.get(finding.type) || 0) + 1);
    });
  });

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}

function formatGeneratedAt(value) {
  if (!value) {
    return "sample data";
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

function renderStats(repos) {
  if (!elements.stats.repos) {
    return;
  }
  const providerCounts = buildProviderCounts(repos);
  const totals = repos.reduce(
    (accumulator, repo) => {
      accumulator.secrets += repo.totalSecrets;
      accumulator.commitHits += repo.commitFindings;
      return accumulator;
    },
    { secrets: 0, commitHits: 0 }
  );

  elements.stats.repos.textContent = String(repos.length);
  elements.stats.secrets.textContent = String(totals.secrets);
  elements.stats.types.textContent = String(providerCounts.length);
  elements.stats.commitHits.textContent = String(totals.commitHits);
}

function renderProviderList(repos) {
  if (!elements.providerList) {
    return;
  }
  const providerCounts = buildProviderCounts(repos);
  const top = providerCounts.slice(0, 8);
  const maxCount = top[0]?.[1] || 1;

  if (!top.length) {
    elements.providerList.innerHTML = "<p class=\"dataset-meta\">No provider counts available.</p>";
    return;
  }

  elements.providerList.innerHTML = top
    .map(
      ([name, count]) => `
        <div class="provider-row">
          <div class="provider-head">
            <span class="provider-name">${escapeHtml(name)}</span>
            <span class="dataset-meta">${count}</span>
          </div>
          <div class="provider-bar" aria-hidden="true">
            <div class="provider-fill" style="width: ${(count / maxCount) * 100}%"></div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderRepoCard(repo) {
  const findingsMarkup = repo.findings
    .map(
      (finding) => `
        <li class="finding-item">
          <span class="finding-type">${escapeHtml(finding.type)}</span>
          <code>${escapeHtml(finding.preview)}</code>
          <div class="finding-meta">
            ${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ""} | ${escapeHtml(finding.source)}
          </div>
        </li>
      `
    )
    .join("");

  const safeUrl = repo.url && repo.url !== "#" ? repo.url : "#";

  return `
    <article class="repo-card">
      <div class="repo-header">
        <div>
          <div class="repo-title">
            <h3><a href="${escapeHtml(safeUrl)}" target="_blank" rel="noreferrer">${escapeHtml(repo.repo)}</a></h3>
            <span class="tag severity-${escapeHtml(repo.severity)}">${escapeHtml(repo.severity)}</span>
          </div>
          <p class="repo-meta">${escapeHtml(repo.topTypes.join(" | "))}</p>
        </div>
        <p class="dataset-meta">Score ${repo.exposureScore}</p>
      </div>

      <div class="metric-row">
        <div class="metric">
          <span class="metric-label">Secrets</span>
          <strong>${repo.totalSecrets}</strong>
        </div>
        <div class="metric">
          <span class="metric-label">Types</span>
          <strong>${repo.uniqueTypes}</strong>
        </div>
        <div class="metric">
          <span class="metric-label">Files</span>
          <strong>${repo.filesAffected}</strong>
        </div>
        <div class="metric">
          <span class="metric-label">Commit Hits</span>
          <strong>${repo.commitFindings}</strong>
        </div>
        <div class="metric">
          <span class="metric-label">Scan Time</span>
          <strong>${repo.scanTimeSeconds.toFixed(2)}s</strong>
        </div>
      </div>

      <ul class="finding-list">
        ${findingsMarkup}
      </ul>
    </article>
  `;
}

function getFilters() {
  return {
    query: elements.search.value.trim().toLowerCase(),
    severity: elements.severity.value,
    provider: elements.provider.value,
    source: elements.source.value,
    sort: elements.sort.value,
  };
}

function matchesFilters(repo, filters) {
  if (filters.severity !== "all" && repo.severity !== filters.severity) {
    return false;
  }

  if (filters.provider !== "all" && !repo.findings.some((finding) => finding.type === filters.provider)) {
    if (!repo.typeCounts || !Object.prototype.hasOwnProperty.call(repo.typeCounts, filters.provider)) {
      return false;
    }
  }

  if (filters.source !== "all" && !repo.findings.some((finding) => finding.source === filters.source)) {
    return false;
  }

  if (!filters.query) {
    return true;
  }

  const haystack = [
    repo.repo,
    repo.topTypes.join(" "),
    ...repo.findings.flatMap((finding) => [finding.file, finding.type, finding.preview]),
  ]
    .join(" ")
    .toLowerCase();

  return haystack.includes(filters.query);
}

function renderBoard() {
  const filters = getFilters();
  const filtered = sortRepos(
    state.repos.filter((repo) => matchesFilters(repo, filters)),
    filters.sort
  );

  renderStats(filtered);
  renderProviderList(filtered);

  if (!filtered.length) {
    elements.grid.innerHTML = "";
    elements.empty.hidden = false;
    return;
  }

  elements.empty.hidden = true;
  elements.grid.innerHTML = filtered.map(renderRepoCard).join("");
}

function populateProviderFilter(repos) {
  const providers = buildProviderCounts(repos).map(([name]) => name);
  state.providerOptions = providers;
  elements.provider.innerHTML = [
    '<option value="all">All providers</option>',
    ...providers.map((provider) => `<option value="${escapeHtml(provider)}">${escapeHtml(provider)}</option>`),
  ].join("");
}

function showStatus(message) {
  elements.statusBanner.hidden = false;
  elements.statusBanner.textContent = message;
}

async function loadDataset() {
  try {
    const response = await fetch(DATA_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const normalized = normalizePayload(payload);

    state.sourceName = normalized.sourceName;
    state.generatedAt = normalized.generatedAt;
    state.repos = normalized.repos;

    elements.datasetMeta.textContent = `Updated ${formatGeneratedAt(state.generatedAt)}`;

    populateProviderFilter(state.repos);
    renderBoard();

    if (!state.repos.length) {
      showStatus("No leaked repos.");
      return;
    }

    showStatus("Masked previews only.");
  } catch (error) {
    elements.datasetMeta.textContent = "Dataset unavailable";
    showStatus("No data file.");
    renderStats([]);
    renderProviderList([]);
    elements.grid.innerHTML = "";
    elements.empty.hidden = false;
  }
}

["input", "change"].forEach((eventName) => {
  elements.search.addEventListener(eventName, renderBoard);
  elements.severity.addEventListener(eventName, renderBoard);
  elements.provider.addEventListener(eventName, renderBoard);
  elements.source.addEventListener(eventName, renderBoard);
  elements.sort.addEventListener(eventName, renderBoard);
});

loadDataset();
