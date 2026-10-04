(function () {
  "use strict";

  var DATA = window.USE_CASES || [];
  var SEVERITIES = ["Critical", "High", "Medium", "Low"];
  var SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  var TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
  ];
  // ATT&CK v19.2 tactics each technique belongs to (used for the coverage grid).
  var TECH_TACTICS = {
    "T1036.005": ["Stealth"],
    "T1046": ["Discovery"],
    "T1053.007": ["Execution", "Persistence", "Privilege Escalation"],
    "T1059.004": ["Execution"],
    "T1059.013": ["Execution"],
    "T1068": ["Privilege Escalation"],
    "T1069": ["Discovery"],
    "T1070": ["Stealth"],
    "T1078": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1078.001": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1095": ["Command and Control"],
    "T1098.006": ["Persistence", "Privilege Escalation"],
    "T1105": ["Command and Control"],
    "T1133": ["Persistence", "Initial Access"],
    "T1190": ["Initial Access"],
    "T1195.002": ["Initial Access"],
    "T1204.003": ["Execution"],
    "T1485": ["Impact"],
    "T1489": ["Impact"],
    "T1496.001": ["Impact"],
    "T1525": ["Persistence"],
    "T1528": ["Credential Access"],
    "T1543.005": ["Persistence", "Privilege Escalation"],
    "T1547.006": ["Persistence", "Privilege Escalation"],
    "T1550.001": ["Lateral Movement"],
    "T1552.001": ["Credential Access"],
    "T1552.005": ["Credential Access"],
    "T1552.007": ["Credential Access"],
    "T1572": ["Command and Control"],
    "T1609": ["Execution"],
    "T1610": ["Execution"],
    "T1611": ["Privilege Escalation"],
    "T1612": ["Stealth"],
    "T1613": ["Discovery"],
    "T1649": ["Credential Access"],
    "T1685": ["Defense Impairment"],
    "T1685.002": ["Defense Impairment"],
    "T1686.001": ["Defense Impairment"]
  };

  var $ = function (sel) { return document.querySelector(sel); };
  var els = {
    q: $("#q"), list: $("#ucList"), empty: $("#empty"), count: $("#resultCount"),
    chips: $("#sevChips"), cat: $("#fCategory"), src: $("#fSource"), tac: $("#fTactic"),
    conf: $("#fConf"), sort: $("#fSort"), stats: $("#stats"), grid: $("#mitreGrid"), toast: $("#toast"),
    expandAll: $("#expandAll")
  };

  var state = { q: "", sev: new Set(), cat: "", src: "", tac: "", conf: 0, sort: "id" };
  var open = new Set();

  /* ---------- helpers ---------- */
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function uniq(arr) { return Array.from(new Set(arr)); }
  function sevClass(s) { return "sev-" + s.toLowerCase(); }
  function confBand(c) { return c >= 80 ? "hi" : c >= 60 ? "md" : "lo"; }
  function confLabel(c) { return c >= 80 ? "High" : c >= 60 ? "Medium" : "Low"; }
  function mitreUrl(id) { return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/"; }
  function logText(log) { return typeof log === "string" ? log : JSON.stringify(log, null, 2); }
  function logOneLine(log) { return typeof log === "string" ? log : JSON.stringify(log); }

  function highlightJson(json) {
    return esc(json).replace(
      /(&quot;(?:\\.|[^&\\]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      function (m, str, colon, bool, num) {
        if (str) return colon ? '<span class="j-key">' + str + "</span>" + colon : '<span class="j-str">' + str + "</span>";
        if (bool) return '<span class="j-bool">' + bool + "</span>";
        return '<span class="j-num">' + num + "</span>";
      }
    );
  }

  function markTerms(text, terms) {
    var html = esc(text);
    if (!terms.length) return html;
    var pattern = terms.map(function (t) { return esc(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|");
    return html.replace(new RegExp("(" + pattern + ")", "gi"), "<mark>$1</mark>");
  }

  // Precompute a lowercase search haystack for each use case.
  DATA.forEach(function (u) {
    u._hay = [
      u.id, u.name, u.category, u.severity, String(u.confidence), confLabel(u.confidence),
      u.logSources.join(" "), u.tactics.join(" "),
      u.mitre.map(function (m) { return m.id + " " + m.name; }).join(" "),
      u.description, u.detection, u.falsePositives, logOneLine(u.sampleLog)
    ].join(" \u0001 ").toLowerCase();
  });

  /* ---------- filter options ---------- */
  function fillSelect(sel, values) {
    values.forEach(function (v) {
      var o = document.createElement("option");
      o.value = v; o.textContent = v;
      sel.appendChild(o);
    });
  }
  fillSelect(els.cat, uniq(DATA.map(function (u) { return u.category; })).sort());
  fillSelect(els.src, uniq([].concat.apply([], DATA.map(function (u) { return u.logSources; }))).sort());
  fillSelect(els.tac, TACTIC_ORDER.filter(function (t) {
    return DATA.some(function (u) { return u.tactics.indexOf(t) !== -1; });
  }));

  SEVERITIES.forEach(function (s) {
    var n = DATA.filter(function (u) { return u.severity === s; }).length;
    var b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.dataset.sev = s;
    b.setAttribute("aria-pressed", "false");
    b.innerHTML = '<span class="dot ' + sevClass(s) + '"></span>' + s + ' <span class="n">' + n + "</span>";
    b.addEventListener("click", function () {
      if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
      b.setAttribute("aria-pressed", String(state.sev.has(s)));
      update();
    });
    els.chips.appendChild(b);
  });

  /* ---------- stats ---------- */
  (function renderStats() {
    var techs = uniq([].concat.apply([], DATA.map(function (u) { return u.mitre.map(function (m) { return m.id; }); })));
    var tactics = uniq([].concat.apply([], DATA.map(function (u) { return u.tactics; })));
    var sources = uniq([].concat.apply([], DATA.map(function (u) { return u.logSources; })));
    var avg = Math.round(DATA.reduce(function (a, u) { return a + u.confidence; }, 0) / DATA.length);
    var count = function (s) { return DATA.filter(function (u) { return u.severity === s; }).length; };
    var items = [
      ["", DATA.length, "Use cases"],
      ["crit", count("Critical"), "Critical"],
      ["high", count("High"), "High"],
      ["med", count("Medium"), "Medium"],
      ["", techs.length, "ATT&CK techniques"],
      ["", tactics.length, "ATT&CK tactics"],
      ["", sources.length, "Log sources"],
      ["", avg, "Avg. confidence"]
    ];
    els.stats.innerHTML = items.map(function (i) {
      return '<div class="stat ' + i[0] + '"><b>' + i[1] + "</b><span>" + esc(i[2]) + "</span></div>";
    }).join("");
  })();

  /* ---------- MITRE grid ---------- */
  (function renderMitre() {
    var byTactic = {};
    DATA.forEach(function (u) {
      u.mitre.forEach(function (m) {
        (TECH_TACTICS[m.id] || u.tactics).forEach(function (t) {
          byTactic[t] = byTactic[t] || {};
          var e = byTactic[t][m.id] = byTactic[t][m.id] || { id: m.id, name: m.name, ucs: new Set() };
          e.ucs.add(u.id);
        });
      });
    });
    els.grid.innerHTML = TACTIC_ORDER.filter(function (t) { return byTactic[t]; }).map(function (t) {
      var techs = Object.keys(byTactic[t]).map(function (k) { return byTactic[t][k]; })
        .sort(function (a, b) { return b.ucs.size - a.ucs.size || a.id.localeCompare(b.id); });
      return '<div class="tactic"><h3>' + esc(t) + "<span>" + techs.length + " tech.</span></h3>" +
        techs.map(function (e) {
          var heat = e.ucs.size >= 5 ? 3 : e.ucs.size >= 3 ? 2 : 1;
          return '<button type="button" class="tech heat-' + heat + '" data-tech="' + e.id + '" title="' +
            esc(e.name) + " — " + Array.from(e.ucs).join(", ") + '"><span><code>' + e.id + "</code> " +
            esc(e.name.replace(/^.*?: /, "")) + '</span><span class="cnt">' + e.ucs.size + "</span></button>";
        }).join("") + "</div>";
    }).join("");
    els.grid.addEventListener("click", function (ev) {
      var b = ev.target.closest(".tech");
      if (!b) return;
      resetFilters(true);
      els.q.value = state.q = b.dataset.tech;
      update();
      document.getElementById("library").scrollIntoView();
    });
  })();

  /* ---------- filtering ---------- */
  function terms() {
    return state.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  }

  function filtered() {
    var t = terms();
    var out = DATA.filter(function (u) {
      if (state.sev.size && !state.sev.has(u.severity)) return false;
      if (state.cat && u.category !== state.cat) return false;
      if (state.src && u.logSources.indexOf(state.src) === -1) return false;
      if (state.tac && u.tactics.indexOf(state.tac) === -1) return false;
      if (u.confidence < state.conf) return false;
      return t.every(function (w) { return u._hay.indexOf(w) !== -1; });
    });
    var cmp = {
      id: function (a, b) { return a.id.localeCompare(b.id); },
      name: function (a, b) { return a.name.localeCompare(b.name); },
      severity: function (a, b) { return SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.confidence - a.confidence; },
      confidence: function (a, b) { return b.confidence - a.confidence || SEV_RANK[a.severity] - SEV_RANK[b.severity]; }
    }[state.sort];
    return out.sort(cmp);
  }

  /* ---------- rendering ---------- */
  var CARET = '<svg class="caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';

  function rowHtml(u, t) {
    var isOpen = open.has(u.id);
    var logIsJson = typeof u.sampleLog !== "string";
    var log = logText(u.sampleLog);
    return '<li class="uc' + (isOpen ? " open" : "") + '" id="' + u.id + '">' +
      '<div class="uc-row" data-id="' + u.id + '">' +
        '<div class="uc-top">' +
          '<div class="uc-main">' +
            '<p class="uc-kicker">' + u.id + " · " + esc(u.category) + "</p>" +
            '<h3 class="uc-title"><button type="button" class="uc-name" aria-expanded="' + isOpen + '" aria-controls="d-' + u.id + '">' +
              markTerms(u.name, t) + "</button></h3>" +
            '<p class="uc-desc">' + markTerms(u.description, t) + "</p>" +
          "</div>" +
          '<span class="sev ' + sevClass(u.severity) + '">' + u.severity + "</span>" +
        "</div>" +
        '<div class="uc-meta">' +
          '<p><b>Log sources to monitor:</b> <span>' + u.logSources.map(esc).join(", ") + "</span></p>" +
          '<p><b>MITRE ATT&amp;CK:</b> ' + u.mitre.map(function (m) {
            return '<span class="tech-ref" title="' + esc(m.name) + '">' + m.id + "</span> <span>" + esc(m.name) + "</span>";
          }).join('<span class="sep"> · </span>') + "</p>" +
          '<div class="uc-foot">' +
            '<span class="conf ' + confBand(u.confidence) + '"><b>Confidence:</b> <span class="bar"><i style="width:' + u.confidence + '%"></i></span>' +
              u.confidence + "/100 · " + confLabel(u.confidence) + "</span>" +
            '<span class="more">' + CARET + (isOpen ? "Hide" : "Show") + " detection &amp; sample log</span>" +
          "</div>" +
        "</div>" +
      "</div>" +
      '<div class="uc-detail" id="d-' + u.id + '"' + (isOpen ? "" : " hidden") + ">" +
        "<div><h4>Tactics</h4><p>" + u.tactics.map(esc).join(", ") + "</p>" +
          '<h4 style="margin-top:14px">MITRE ATT&amp;CK</h4><ul class="mitre-links">' +
          u.mitre.map(function (m) {
            return '<li><a href="' + mitreUrl(m.id) + '" target="_blank" rel="noopener"><code>' + m.id + "</code><span>" + esc(m.name) + "</span></a></li>";
          }).join("") + "</ul></div>" +
        "<div><h4>False positives</h4><p>" + esc(u.falsePositives) + "</p></div>" +
        '<div class="full"><h4>Detection logic <button type="button" class="btn small" data-copy="detection" data-id="' + u.id + '">Copy</button></h4>' +
          '<pre class="code wrap-lines">' + esc(u.detection) + "</pre></div>" +
        '<div class="full"><h4>Sample log' + (logIsJson ? " (JSON)" : "") + ' <button type="button" class="btn small" data-copy="log" data-id="' + u.id + '">Copy</button></h4>' +
          '<pre class="code' + (logIsJson ? "" : " wrap-lines") + '">' + (logIsJson ? highlightJson(log) : esc(log)) + "</pre></div>" +
      "</div></li>";
  }

  function render() {
    var rows = filtered();
    var t = terms();
    els.list.innerHTML = rows.map(function (u) { return rowHtml(u, t); }).join("");
    els.empty.hidden = rows.length !== 0;
    els.count.textContent = rows.length === DATA.length
      ? "Showing all " + DATA.length + " use cases"
      : "Showing " + rows.length + " of " + DATA.length + " use cases";
    els.expandAll.textContent = rows.length && rows.every(function (u) { return open.has(u.id); }) ? "Collapse all" : "Expand all";
  }

  /* ---------- URL state ---------- */
  function writeUrl() {
    var p = new URLSearchParams();
    if (state.q) p.set("q", state.q);
    if (state.sev.size) p.set("sev", Array.from(state.sev).join(","));
    if (state.cat) p.set("cat", state.cat);
    if (state.src) p.set("src", state.src);
    if (state.tac) p.set("tactic", state.tac);
    if (state.conf) p.set("conf", state.conf);
    if (state.sort !== "id") p.set("sort", state.sort);
    var qs = p.toString();
    try { history.replaceState(null, "", location.pathname + (qs ? "?" + qs : "") + location.hash); } catch (e) {}
  }
  function readUrl() {
    var p = new URLSearchParams(location.search);
    state.q = p.get("q") || "";
    (p.get("sev") || "").split(",").forEach(function (s) { if (SEV_RANK[s] !== undefined) state.sev.add(s); });
    state.cat = p.get("cat") || ""; state.src = p.get("src") || ""; state.tac = p.get("tactic") || "";
    state.conf = Number(p.get("conf")) || 0; state.sort = p.get("sort") || "id";
    els.q.value = state.q; els.cat.value = state.cat; els.src.value = state.src; els.tac.value = state.tac;
    els.conf.value = String(state.conf); els.sort.value = state.sort;
    if (els.conf.value !== String(state.conf)) state.conf = 0;
    Array.prototype.forEach.call(els.chips.children, function (b) { b.setAttribute("aria-pressed", String(state.sev.has(b.dataset.sev))); });
  }

  function update() { render(); writeUrl(); }

  function resetFilters(silent) {
    state = { q: "", sev: new Set(), cat: "", src: "", tac: "", conf: 0, sort: state.sort };
    els.q.value = ""; els.cat.value = ""; els.src.value = ""; els.tac.value = ""; els.conf.value = "0";
    Array.prototype.forEach.call(els.chips.children, function (b) { b.setAttribute("aria-pressed", "false"); });
    if (!silent) update();
  }

  /* ---------- events ---------- */
  var debounce;
  els.q.addEventListener("input", function () {
    clearTimeout(debounce);
    debounce = setTimeout(function () { state.q = els.q.value; update(); }, 120);
  });
  els.cat.addEventListener("change", function () { state.cat = els.cat.value; update(); });
  els.src.addEventListener("change", function () { state.src = els.src.value; update(); });
  els.tac.addEventListener("change", function () { state.tac = els.tac.value; update(); });
  els.conf.addEventListener("change", function () { state.conf = Number(els.conf.value); update(); });
  els.sort.addEventListener("change", function () { state.sort = els.sort.value; update(); });
  $("#reset").addEventListener("click", function () { resetFilters(); });
  $("#reset2").addEventListener("click", function () { resetFilters(); });

  els.list.addEventListener("click", function (ev) {
    var copyBtn = ev.target.closest("[data-copy]");
    if (copyBtn) {
      var u = DATA.find(function (x) { return x.id === copyBtn.dataset.id; });
      copy(copyBtn.dataset.copy === "log" ? logText(u.sampleLog) : u.detection);
      return;
    }
    if (ev.target.closest("a")) return;
    var row = ev.target.closest(".uc-row");
    if (!row) return;
    var id = row.dataset.id;
    var li = row.parentNode;
    var detail = li.querySelector(".uc-detail");
    var nowOpen = !open.has(id);
    if (nowOpen) open.add(id); else open.delete(id);
    li.classList.toggle("open", nowOpen);
    detail.hidden = !nowOpen;
    row.querySelector(".uc-name").setAttribute("aria-expanded", String(nowOpen));
    row.querySelector(".more").lastChild.textContent = (nowOpen ? "Hide" : "Show") + " detection & sample log";
  });

  els.expandAll.addEventListener("click", function () {
    var rows = filtered();
    var allOpen = rows.every(function (u) { return open.has(u.id); });
    rows.forEach(function (u) { if (allOpen) open.delete(u.id); else open.add(u.id); });
    render();
  });

  document.addEventListener("keydown", function (ev) {
    if (ev.key === "/" && document.activeElement !== els.q && !/input|select|textarea/i.test(document.activeElement.tagName)) {
      ev.preventDefault(); els.q.focus();
    } else if (ev.key === "Escape" && document.activeElement === els.q && els.q.value) {
      els.q.value = state.q = ""; update();
    }
  });

  /* ---------- copy / export ---------- */
  var toastTimer;
  function toast(msg) {
    els.toast.textContent = msg; els.toast.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { els.toast.classList.remove("show"); }, 1600);
  }
  function copy(text) {
    var done = function () { toast("Copied to clipboard"); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(ta);
  }
  function download(name, type, content) {
    var blob = new Blob([content], { type: type });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  function csvCell(v) { v = String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }

  $("#exportCsv").addEventListener("click", function () {
    var header = ["ID", "Use Case Name", "Category", "Severity", "Confidence Score", "Log Sources", "MITRE Tactics",
      "MITRE Techniques", "Description", "Detection Logic", "False Positives", "Sample Log"];
    var lines = [header.join(",")].concat(filtered().map(function (u) {
      return [u.id, u.name, u.category, u.severity, u.confidence, u.logSources.join("; "), u.tactics.join("; "),
        u.mitre.map(function (m) { return m.id + " " + m.name; }).join("; "), u.description, u.detection,
        u.falsePositives, logOneLine(u.sampleLog)].map(csvCell).join(",");
    }));
    download("kubernetes-siem-use-cases.csv", "text/csv;charset=utf-8", "﻿" + lines.join("\r\n"));
  });
  $("#exportJson").addEventListener("click", function () {
    var rows = filtered().map(function (u) {
      var c = {}; Object.keys(u).forEach(function (k) { if (k.charAt(0) !== "_") c[k] = u[k]; }); return c;
    });
    download("kubernetes-siem-use-cases.json", "application/json", JSON.stringify(rows, null, 2));
  });

  /* ---------- init ---------- */
  readUrl();
  if (location.hash && /^#KSU-\d{3}$/.test(location.hash)) open.add(location.hash.slice(1));
  render();
  if (open.size) { var el = document.getElementById(location.hash.slice(1)); if (el) el.scrollIntoView(); }
})();
