// ThreatScope frontend. All dynamic text is inserted with textContent (URLs are untrusted).
const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

$("form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const url = $("url").value.trim();
  $("error").hidden = true;
  if (!url) return showError("Enter a URL or domain to analyze.");
  $("go").disabled = true; $("loading").hidden = false; $("results").hidden = true;
  try {
    const res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Analysis failed.");
    render(data);
  } catch (e) {
    showError(e instanceof TypeError ? "Could not reach the ThreatScope server. Is app.py running?" : e.message);
  } finally { $("go").disabled = false; $("loading").hidden = true; }
});

function showError(msg) { $("error").textContent = msg; $("error").hidden = false; }

function render(d) {
  const lv = d.level.toLowerCase();
  $("risk").className = "card risk " + lv;
  $("level").textContent = d.level + " RISK";
  $("domain").textContent = d.parts.domain;
  $("norm").textContent = d.normalized_url;
  $("note").textContent = d.note; $("note").hidden = !d.note;
  $("why").textContent = d.explanation;
  $("score").textContent = d.score;
  const arc = $("arc"); arc.style.strokeDashoffset = 326.7;
  requestAnimationFrame(() => requestAnimationFrame(() => arc.style.strokeDashoffset = 326.7 * (1 - d.score / 100)));

  $("grid").replaceChildren(...d.checks.map(c => {
    const card = el("div", "card chk " + c.status);
    const top = el("div", "top"); top.append(el("h3", null, c.name), el("span", "badge", c.status));
    card.append(top, el("p", null, c.detail));
    return card;
  }));

  const t = d.intel, box = $("intel");
  box.className = "card intel " + (t.status === "listed" ? "DANGER" : t.status === "not_listed" ? "SAFE" : "WARN");
  const title = { listed: "Listed as malicious (externally verified)", not_listed: "Not listed in URLhaus",
                  not_configured: "Threat intelligence unavailable", unreachable: "Threat intelligence unavailable" }[t.status];
  box.replaceChildren(el("b", null, title), el("p", null, t.message));
  if (t.details) box.append(el("p", null, `Threat: ${t.details.threat || "n/a"} · Status: ${t.details.url_status || "n/a"} · Added: ${t.details.date_added || "n/a"}`));

  $("recs").replaceChildren(...d.recommendations.map(r => el("li", null, r)));
  $("results").hidden = false;
}
