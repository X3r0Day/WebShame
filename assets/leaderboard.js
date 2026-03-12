const DATA_URL = "./data/hall-of-shame.json";

const elements = {
  meta: document.querySelector("#leaderboard-meta"),
  providers: document.querySelector("#leaderboard-providers"),
  repos: document.querySelector("#leaderboard-repos"),
  owners: document.querySelector("#leaderboard-owners"),
};

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

function renderRankList(items, element, formatter) {
  element.innerHTML = items
    .map(([name, count]) => {
      const label = formatter ? formatter(name) : escapeHtml(name);
      return `
        <li class="rank-item">
          <span>${label}</span>
          <span class="rank-count">${count}</span>
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

    elements.meta.textContent = `Updated ${formatGeneratedAt(normalized.generatedAt)}`;

    const providerCounts = buildProviderCounts(normalized.repos).slice(0, 10);
    const repoCounts = normalized.repos
      .slice()
      .sort((left, right) => right.totalSecrets - left.totalSecrets || right.exposureScore - left.exposureScore)
      .slice(0, 10)
      .map((repo) => [repo.repo, repo.totalSecrets, repo.url]);
    const ownerCounts = buildOwnerCounts(normalized.repos).slice(0, 10);

    renderRankList(providerCounts, elements.providers);
    renderRankList(
      repoCounts.map(([name, count]) => [name, count]),
      elements.repos,
      (name) => {
        const repo = repoCounts.find(([repoName]) => repoName === name);
        const url = repo?.[2] && repo[2] !== "#" ? repo[2] : "#";
        return `<a class="repo-link" href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(
          name
        )}</a>`;
      }
    );
    renderRankList(ownerCounts, elements.owners);
  } catch (error) {
    elements.meta.textContent = "No data";
    elements.providers.innerHTML = "";
    elements.repos.innerHTML = "";
    elements.owners.innerHTML = "";
  }
}

loadDataset();
