const DATA_URL = "./data/hall-of-shame.json";
const SCAN_URL = "./data/scan-history.json";

const elements = {
  meta: document.querySelector("#leaderboard-meta"),
  providers: document.querySelector("#leaderboard-providers"),
  repos: document.querySelector("#leaderboard-repos"),
  owners: document.querySelector("#leaderboard-owners"),
  stats: {
    secrets: document.querySelector("#stat-secrets"),
    leakedRepos: document.querySelector("#stat-leaked-repos"),
    providers: document.querySelector("#stat-providers"),
    scanned: document.querySelector("#stat-scanned"),
  },
  mix: {
    total: document.querySelector("#mix-total"),
    critical: document.querySelector("#mix-critical"),
    high: document.querySelector("#mix-high"),
    medium: document.querySelector("#mix-medium"),
    low: document.querySelector("#mix-low"),
    counts: {
      critical: document.querySelector("#mix-count-critical"),
      high: document.querySelector("#mix-count-high"),
      medium: document.querySelector("#mix-count-medium"),
      low: document.querySelector("#mix-count-low"),
    },
  },
};

const numberFormatter = new Intl.NumberFormat();

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function normalizeRepo(rawRepo, index) {
  const findings = Array.isArray(rawRepo.findings) ? rawRepo.findings : [];
  const typeCounts = rawRepo.typeCounts && typeof rawRepo.typeCounts === "object" ? rawRepo.typeCounts : null;
  const uniqueTypes =
    rawRepo.uniqueTypes || (typeCounts ? Object.keys(typeCounts).length : new Set(findings.map((finding) => finding.type)).size);
  const commitFindings = rawRepo.commitFindings || findings.filter((finding) => (finding.file || "").startsWith("Commit ")).length;
  const totalSecrets = Number(rawRepo.totalSecrets ?? rawRepo.total_secrets ?? findings.length) || findings.length;
  const severity = rawRepo.severity || deriveSeverity(totalSecrets, uniqueTypes, commitFindings);

  return {
    repo: rawRepo.repo || rawRepo.name || `unknown-repo-${index + 1}`,
    url: rawRepo.url || "#",
    status: rawRepo.status || "leaked",
    severity,
    totalSecrets,
    uniqueTypes,
    commitFindings,
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

  return [...counts.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}

function buildOwnerCounts(repos) {
  const counts = new Map();
  repos.forEach((repo) => {
    const owner = extractOwner(repo);
    counts.set(owner, (counts.get(owner) || 0) + 1);
  });
  return [...counts.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}

function formatCount(value) {
  return numberFormatter.format(Number(value) || 0);
}

function renderRankList(items, element, formatter) {
  if (!element) {
    return;
  }
  const max = items.reduce((current, item) => Math.max(current, Number(item.count) || 0), 1);
  element.innerHTML = items
    .map((item, index) => {
      const label = formatter ? formatter(item) : escapeHtml(item.name);
      const count = Number(item.count) || 0;
      const width = Math.max(8, Math.round((count / max) * 100));
      return `
        <li class="rank-row">
          <div class="rank-left">
            <span class="rank-badge">${index + 1}</span>
            <span class="rank-name">${label}</span>
          </div>
          <div class="rank-right">
            <span class="rank-count">${formatCount(count)}</span>
            <div class="rank-bar" aria-hidden="true">
              <span style="width: ${width}%"></span>
            </div>
          </div>
        </li>
      `;
    })
    .join("");
}

async function loadDataset() {
  try {
    const response = await fetch(DATA_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const normalized = normalizePayload(payload);

    const scanPayload = await fetch(SCAN_URL, { cache: "no-store" })
      .then((scanResponse) => (scanResponse.ok ? scanResponse.json() : null))
      .catch(() => null);

    const scannedRepos = Array.isArray(scanPayload?.repos) ? scanPayload.repos.length : null;

    elements.meta.textContent = `Updated ${formatGeneratedAt(normalized.generatedAt)}${
      scannedRepos ? ` · ${formatCount(scannedRepos)} repos scanned` : ""
    }`;

    const providerCounts = buildProviderCounts(normalized.repos).map(([name, count]) => ({ name, count }));
    const repoCounts = normalized.repos
      .slice()
      .sort((left, right) => right.totalSecrets - left.totalSecrets || right.exposureScore - left.exposureScore)
      .slice(0, 10)
      .map((repo) => ({ name: repo.repo, count: repo.totalSecrets, href: repo.url }));
    const ownerCounts = buildOwnerCounts(normalized.repos).map(([name, count]) => ({ name, count }));

    const totalSecrets = normalized.repos.reduce((sum, repo) => sum + repo.totalSecrets, 0);
    const leakedRepos = normalized.repos.filter((repo) => repo.totalSecrets > 0).length;
    const providerTotal = providerCounts.length;

    if (elements.stats.secrets) {
      elements.stats.secrets.textContent = formatCount(totalSecrets);
    }
    if (elements.stats.leakedRepos) {
      elements.stats.leakedRepos.textContent = formatCount(leakedRepos);
    }
    if (elements.stats.providers) {
      elements.stats.providers.textContent = formatCount(providerTotal);
    }
    if (elements.stats.scanned) {
      elements.stats.scanned.textContent = scannedRepos ? formatCount(scannedRepos) : "—";
    }

    const severityTotals = normalized.repos.reduce(
      (accumulator, repo) => {
        const key = accumulator[repo.severity] !== undefined ? repo.severity : "low";
        accumulator[key] += repo.totalSecrets;
        return accumulator;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );
    const mixTotal = Object.values(severityTotals).reduce((sum, value) => sum + value, 0);

    if (elements.mix.total) {
      elements.mix.total.textContent = `${formatCount(mixTotal)} secrets`;
    }

    ["critical", "high", "medium", "low"].forEach((level) => {
      const value = severityTotals[level];
      const percent = mixTotal ? (value / mixTotal) * 100 : 0;
      if (elements.mix[level]) {
        elements.mix[level].style.width = `${percent}%`;
      }
      const countEl = elements.mix.counts[level];
      if (countEl) {
        countEl.textContent = formatCount(value);
      }
    });

    renderRankList(providerCounts.slice(0, 10), elements.providers);
    renderRankList(repoCounts, elements.repos, (item) => {
      const url = item.href && item.href !== "#" ? item.href : "#";
      return `<a class="repo-link" href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(
        item.name
      )}</a>`;
    });
    renderRankList(ownerCounts.slice(0, 10), elements.owners);
  } catch (error) {
    elements.meta.textContent = "No data";
    elements.providers.innerHTML = "";
    elements.repos.innerHTML = "";
    elements.owners.innerHTML = "";
    if (elements.stats.secrets) {
      elements.stats.secrets.textContent = "—";
    }
    if (elements.stats.leakedRepos) {
      elements.stats.leakedRepos.textContent = "—";
    }
    if (elements.stats.providers) {
      elements.stats.providers.textContent = "—";
    }
    if (elements.stats.scanned) {
      elements.stats.scanned.textContent = "—";
    }
    if (elements.mix.total) {
      elements.mix.total.textContent = "0 secrets";
    }
  }
}

loadDataset();
