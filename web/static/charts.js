/**
 * charts.js  ·  Shared Chart.js utilities for the Honeypot Dashboard
 * ─────────────────────────────────────────────────────────────────────
 * Exports (on window.HPC):
 *   HPC.CAT_COLORS          – category → hex colour map
 *   HPC.SEV_COLORS          – severity → hex colour map
 *   HPC.scoreColor(n)       – returns CSS color for a 0-100 score
 *   HPC.escHtml(s)          – XSS-safe escape
 *   HPC.fmtTs(iso)          – "HH:MM:SS" from ISO string
 *   HPC.makeDoughnut(ctx, data, labels) – returns Chart
 *   HPC.makeTimeline(ctx)   – returns empty line Chart
 *   HPC.updateTimeline(chart, rows) – feed [{hour,cnt}] rows
 *   HPC.makeStackedBar(ctx) – stacked bar for severity timeline
 *   HPC.updateStackedBar(chart, rows) – feed [{hour,severity,cnt}]
 *   HPC.makeRadar(ctx, labels, data) – threat category radar
 *   HPC.makeSessionTimeline(ctx) – per-session threat timeline
 *   HPC.updateSessionTimeline(chart, rows)
 *   HPC.makeCmdBar(ctx, data, labels) – horizontal bar for commands
 *   HPC.setDefaults()       – call once on page load
 */

(function () {
  "use strict";

  /* ── palette ── */
  const CAT_COLORS = {
    RECON:       "#58a6ff",
    LATERAL:     "#bc8cff",
    EXFIL:       "#d29922",
    PERSISTENCE: "#ffa657",
    PRIVESC:     "#f85149",
    CRED_HUNT:   "#3fb950",
    MALWARE:     "#ff7b72",
    BRUTE_FORCE: "#e3b341",
    UNKNOWN:     "#8b949e",
  };

  const SEV_COLORS = {
    critical: "#f85149",
    high:     "#d29922",
    medium:   "#e3b341",
    low:      "#3fb950",
  };

  const GRID   = "#21262d";
  const LABEL  = "#8b949e";
  const BG     = "#161b22";

  /* ── helpers ── */
  function scoreColor(n) {
    if (n >= 70) return "#f85149";
    if (n >= 40) return "#d29922";
    return "#3fb950";
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Format any ISO timestamp → HH:MM:SS in IST
  // Handles both "2026-02-26T16:05:43+05:30" and "2026-02-26T10:35:43Z"
  function fmtTs(iso) {
    if (!iso) return "";
    try {
      // new Date() handles both +05:30 and Z suffixes natively
      const d = new Date(iso);
      if (isNaN(d.getTime())) return iso.substring(11, 19) || "";
      return d.toLocaleTimeString("en-IN", {
        timeZone: "Asia/Kolkata",
        hour12:   false,
        hour:     "2-digit",
        minute:   "2-digit",
        second:   "2-digit",
      });
    } catch { return iso.substring(11, 19) || ""; }
  }

  /* ── Chart.js global defaults ── */
  function setDefaults() {
    Chart.defaults.color            = LABEL;
    Chart.defaults.borderColor      = GRID;
    Chart.defaults.font.family      = '-apple-system,BlinkMacSystemFont,"Segoe UI",monospace';
    Chart.defaults.font.size        = 11;
    Chart.defaults.plugins.legend.labels.color = LABEL;
    Chart.defaults.plugins.tooltip.backgroundColor = "#0d1117";
    Chart.defaults.plugins.tooltip.borderColor      = "#30363d";
    Chart.defaults.plugins.tooltip.borderWidth      = 1;
    Chart.defaults.plugins.tooltip.titleColor       = "#e6edf3";
    Chart.defaults.plugins.tooltip.bodyColor        = "#8b949e";
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * DOUGHNUT  –  threat categories
   * ───────────────────────────────────────────────────────────────────────── */
  function makeDoughnut(ctx, data = [], labels = []) {
    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: labels.map(l => (CAT_COLORS[l] || "#8b949e") + "cc"),
          borderColor:     labels.map(l =>  CAT_COLORS[l] || "#8b949e"),
          borderWidth:     2,
          hoverOffset:     6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "right",
            labels: { padding: 12, boxWidth: 12, font: { size: 11 } },
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.raw}`,
            },
          },
        },
      },
    });
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * LINE TIMELINE  –  threats over 24 h
   * ───────────────────────────────────────────────────────────────────────── */
  function makeTimeline(ctx) {
    return new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label:           "Threats",
          data:            [],
          borderColor:     "#f85149",
          backgroundColor: "rgba(248,81,73,.12)",
          fill:            true,
          tension:         0.4,
          pointRadius:     3,
          pointBackgroundColor: "#f85149",
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks:{ maxTicksLimit:8 }, grid:{ color: GRID } },
          y: { beginAtZero:true, ticks:{}, grid:{ color: GRID } },
        },
        plugins: { legend:{ display:false } },
      },
    });
  }

  function updateTimeline(chart, rows) {
    chart.data.labels               = rows.map(r => (r.hour||"").substring(11,16));
    chart.data.datasets[0].data     = rows.map(r => r.cnt);
    chart.update("none");
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * STACKED BAR  –  severity breakdown over 24 h
   * ───────────────────────────────────────────────────────────────────────── */
  const SEV_ORDER = ["critical","high","medium","low"];

  function makeStackedBar(ctx) {
    const datasets = SEV_ORDER.map(sev => ({
      label:           sev.charAt(0).toUpperCase() + sev.slice(1),
      data:            [],
      backgroundColor: (SEV_COLORS[sev] || "#666") + "cc",
      borderColor:      SEV_COLORS[sev] || "#666",
      borderWidth:     1,
    }));
    return new Chart(ctx, {
      type: "bar",
      data: { labels: [], datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { stacked:true, grid:{ color: GRID }, ticks:{ maxTicksLimit:8 } },
          y: { stacked:true, beginAtZero:true, grid:{ color: GRID } },
        },
        plugins: {
          legend: { position:"bottom", labels:{ boxWidth:10, padding:10 } },
        },
      },
    });
  }

  function updateStackedBar(chart, rows) {
    // Collect unique hours
    const hours = [...new Set(rows.map(r => r.hour))].sort();
    chart.data.labels = hours;
    SEV_ORDER.forEach((sev, i) => {
      chart.data.datasets[i].data = hours.map(h => {
        const found = rows.find(r => r.hour === h && r.severity === sev);
        return found ? found.cnt : 0;
      });
    });
    chart.update("none");
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * RADAR  –  category threat surface
   * ───────────────────────────────────────────────────────────────────────── */
  const RADAR_CATS = ["RECON","LATERAL","EXFIL","PERSISTENCE","PRIVESC","CRED_HUNT","MALWARE"];

  function makeRadar(ctx, labels = RADAR_CATS, data = new Array(RADAR_CATS.length).fill(0)) {
    return new Chart(ctx, {
      type: "radar",
      data: {
        labels,
        datasets: [{
          label:           "Threat Surface",
          data,
          backgroundColor: "rgba(88,166,255,.15)",
          borderColor:     "#58a6ff",
          borderWidth:     2,
          pointBackgroundColor: labels.map(l => CAT_COLORS[l] || "#8b949e"),
          pointRadius:     4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            beginAtZero:    true,
            angleLines:     { color: GRID },
            grid:           { color: GRID },
            pointLabels:    { color: LABEL, font:{ size:10 } },
            ticks:          { display:false },
          },
        },
        plugins: { legend:{ display:false } },
      },
    });
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * SESSION MINI-TIMELINE  –  threats per minute for one session
   * ───────────────────────────────────────────────────────────────────────── */
  function makeSessionTimeline(ctx) {
    return new Chart(ctx, {
      type: "bar",
      data: { labels:[], datasets:[] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { stacked:true, grid:{ color: GRID }, ticks:{ maxTicksLimit:12 } },
          y: { stacked:true, beginAtZero:true, grid:{ color: GRID } },
        },
        plugins: {
          legend: { position:"bottom", labels:{ boxWidth:10, padding:8 } },
        },
      },
    });
  }

  function updateSessionTimeline(chart, rows) {
    const mins = [...new Set(rows.map(r => r.minute))].sort();
    const cats = [...new Set(rows.map(r => r.category))];
    chart.data.labels   = mins;
    chart.data.datasets = cats.map(cat => ({
      label:           cat,
      data:            mins.map(m => {
        const f = rows.find(r => r.minute === m && r.category === cat);
        return f ? f.cnt : 0;
      }),
      backgroundColor: (CAT_COLORS[cat] || "#8b949e") + "cc",
      borderColor:      CAT_COLORS[cat] || "#8b949e",
      borderWidth:     1,
    }));
    chart.update("none");
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * HORIZONTAL BAR  –  top commands
   * ───────────────────────────────────────────────────────────────────────── */
  function makeCmdBar(ctx, data = [], labels = []) {
    return new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label:           "Executions",
          data,
          backgroundColor: "#58a6ff55",
          borderColor:     "#58a6ff",
          borderWidth:     1,
          borderRadius:    3,
        }],
      },
      options: {
        indexAxis:   "y",
        responsive:  true,
        maintainAspectRatio: false,
        scales: {
          x: { beginAtZero:true, grid:{ color: GRID } },
          y: { ticks:{ font:{ family:"monospace", size:11 } }, grid:{ display:false } },
        },
        plugins: { legend:{ display:false } },
      },
    });
  }

  /* ── export ── */
  window.HPC = {
    CAT_COLORS,
    SEV_COLORS,
    scoreColor,
    escHtml,
    fmtTs,
    setDefaults,
    makeDoughnut,
    makeTimeline,
    updateTimeline,
    makeStackedBar,
    updateStackedBar,
    makeRadar,
    makeSessionTimeline,
    updateSessionTimeline,
    makeCmdBar,
  };
})();
