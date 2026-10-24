/* Dukiwi Shield — pilotage du centre de sécurité : historique du score, journal de sécurité unifié, rapport exportable. */
'use strict';

// ─── Historique du score (courbe, une valeur par jour) ─────────────────────
function fmtDay(d) { try { return new Date(d + 'T12:00:00').toLocaleDateString(lang, { day: 'numeric', month: 'short' }); } catch (e) { return d; } }
let historyRange = 90;
function renderScoreHistory() {
    const el = $('scoreHistory');
    if (!el) return;
    const all = ((secData.checklist || {}).history || []).filter(h => typeof h.s === 'number');
    const cutoff = new Date(Date.now() - historyRange * 86400e3).toISOString().slice(0, 10);
    const pts = all.filter(h => h.d >= cutoff);
    const ranges = [30, 90, 365].map(r => `<button class="seg-btn${r === historyRange ? ' active' : ''}" onclick="historyRange=${r}; renderScoreHistory()">${t('history.range.' + r)}</button>`).join('');
    let chart;
    if (pts.length < 2) {
        chart = `<p class="text-muted history-empty">${t('history.empty')}</p>`;
    } else {
        const W = 640, H = 170, L = 34, Rm = 10, T = 12, B = 24;
        const t0 = new Date(pts[0].d).getTime(), t1 = new Date(pts[pts.length - 1].d).getTime() || t0 + 1;
        const x = d => L + (W - L - Rm) * ((new Date(d).getTime() - t0) / Math.max(1, t1 - t0));
        const y = s => T + (H - T - B) * (1 - s / 100);
        const grid = [0, 50, 100].map(v => `<line class="hist-grid" x1="${L}" x2="${W - Rm}" y1="${y(v)}" y2="${y(v)}"/><text class="hist-axis" x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`).join('');
        const path = pts.map((p, i) => `${i ? 'L' : 'M'}${x(p.d).toFixed(1)},${y(p.s).toFixed(1)}`).join(' ');
        const last = pts[pts.length - 1];
        const fmt = fmtDay;
        chart = `<div class="hist-wrap"><svg class="hist-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${escapeHtml(t('history.title'))}"
                onmousemove="historyHover(event)" onmouseleave="historyHover(null)">
            ${grid}
            <text class="hist-axis" x="${L}" y="${H - 6}">${escapeHtml(fmt(pts[0].d))}</text>
            <text class="hist-axis" x="${W - Rm}" y="${H - 6}" text-anchor="end">${escapeHtml(fmt(last.d))}</text>
            <path class="hist-line" d="${path}"/>
            <circle class="hist-last" cx="${x(last.d)}" cy="${y(last.s)}" r="4.5"/>
            <text class="hist-label" x="${Math.min(x(last.d), W - Rm - 4)}" y="${y(last.s) - 10}" text-anchor="end">${last.s}</text>
            <line class="hist-cross" id="histCross" x1="0" x2="0" y1="${T}" y2="${H - B}" visibility="hidden"/>
            <circle class="hist-dot" id="histDot" r="5" visibility="hidden"/>
        </svg><div class="hist-tip" id="histTip" hidden></div></div>`;
        window._histGeom = { pts, x, y, W, L, Rm };
    }
    const rows = all.slice(-60).reverse().map(h => `<tr><td>${escapeHtml(fmtDay(h.d))}</td><td>${h.s}</td><td>${escapeHtml(h.g || '')}</td></tr>`).join('');
    el.innerHTML = `<div class="hist-head"><h5 class="sub-title">${t('history.title')}</h5><div class="seg">${ranges}</div></div>${chart}
        ${all.length ? `<details class="hist-table"><summary>${t('history.table')}</summary><table><thead><tr><th>${t('history.date')}</th><th>${t('history.score')}</th><th>${t('history.grade')}</th></tr></thead><tbody>${rows}</tbody></table></details>` : ''}`;
}

function historyHover(ev) {
    const g = window._histGeom, cross = $('histCross'), dot = $('histDot'), tip = $('histTip');
    if (!g || !cross) return;
    if (!ev) { cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); tip.hidden = true; return; }
    const svg = ev.currentTarget, r = svg.getBoundingClientRect();
    const px = (ev.clientX - r.left) * (g.W / r.width);
    let best = g.pts[0], bd = Infinity;
    g.pts.forEach(p => { const d = Math.abs(g.x(p.d) - px); if (d < bd) { bd = d; best = p; } });
    const cx = g.x(best.d), cy = g.y(best.s);
    cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', cx); dot.setAttribute('cy', cy); dot.setAttribute('visibility', 'visible');
    tip.hidden = false;
    tip.innerHTML = `<strong>${best.s}</strong> ${escapeHtml(best.g || '')}<br><span>${escapeHtml(fmtDay(best.d))}</span>`;
    const left = (cx / g.W) * r.width;
    tip.style.left = `${Math.max(8, Math.min(r.width - 120, left + 10))}px`;
    tip.style.top = `${(cy / 170) * r.height - 10}px`;
}

// ─── Journal de sécurité unifié ────────────────────────────────────────────
let journalData = { days: 30, events: [] };
const journalFilter = { days: 30, cat: '', sev: '', q: '' };
const JOURNAL_CATS = ['scan', 'behaviour', 'integrity', 'firewall', 'network', 'honeypot', 'privacy', 'usb', 'updates', 'hardening', 'approvals', 'accounts', 'backup', 'mail', 'settings', 'system'];

function loadJournal(days) {
    journalFilter.days = days || journalFilter.days;
    sendToBackend({ action: 'get_security_data', type: 'journal', days: journalFilter.days });
}

function journalFiltered() {
    const q = journalFilter.q.trim().toLowerCase();
    return (journalData.events || []).filter(e => (!journalFilter.cat || e.cat === journalFilter.cat) && (!journalFilter.sev || e.sev === journalFilter.sev)
        && (!q || (e.text || '').toLowerCase().includes(q)));
}

function renderJournal() {
    const box = $('journalBox');
    if (!box) return;
    const sel = (id, opts, cur) => `<select class="lang-select" id="${id}">${opts.map(([v, l]) => `<option value="${v}"${v === cur ? ' selected' : ''}>${escapeHtml(l)}</option>`).join('')}</select>`;
    const list = journalFiltered();
    const sevLabel = s => t('journal.sev.' + s);
    box.innerHTML = `<div class="journal-filters">
            ${sel('jDays', [7, 30, 90, 365].map(d => [String(d), t('journal.period.' + d)]), String(journalFilter.days))}
            ${sel('jCat', [['', t('journal.cat.all')], ...JOURNAL_CATS.map(c => [c, t('journal.cat.' + c)])], journalFilter.cat)}
            ${sel('jSev', [['', t('journal.sev.all')], ['danger', sevLabel('danger')], ['warn', sevLabel('warn')], ['info', sevLabel('info')]], journalFilter.sev)}
            <input type="search" class="input-field" id="jQ" placeholder="${escapeHtml(t('journal.search'))}" value="${escapeHtml(journalFilter.q)}">
        </div>
        <div class="journal-bar"><span class="text-muted">${t('journal.count', { n: formatNumber(list.length) })}</span>
            <span><button class="btn btn-secondary btn-sm" onclick="exportJournal('csv')">${t('journal.export_csv')}</button>
            <button class="btn btn-secondary btn-sm" onclick="exportJournal('json')">${t('journal.export_json')}</button></span></div>
        <div class="journal-list">${list.length ? list.slice(0, 500).map(e => `<div class="journal-row sev-${e.sev}">
            <span class="journal-time">${escapeHtml(formatDateTime(e.t))}</span>
            <span class="scope-badge ${e.sev === 'danger' ? 'prio-badge prio-critical' : e.sev === 'warn' ? 'prio-badge prio-medium' : 'scope-system'}">${escapeHtml(sevLabel(e.sev))}</span>
            <span class="scope-badge scope-user">${escapeHtml(t('journal.cat.' + e.cat) !== 'journal.cat.' + e.cat ? t('journal.cat.' + e.cat) : e.cat)}</span>
            <span class="journal-text">${escapeHtml(e.text)}</span></div>`).join('') : `<p class="text-muted">${t('journal.none')}</p>`}</div>`;
    $('jDays').onchange = e => loadJournal(parseInt(e.target.value, 10));
    $('jCat').onchange = e => { journalFilter.cat = e.target.value; renderJournal(); };
    $('jSev').onchange = e => { journalFilter.sev = e.target.value; renderJournal(); };
    $('jQ').oninput = e => { journalFilter.q = e.target.value; const pos = e.target.selectionStart; renderJournal(); const q = $('jQ'); q.focus(); q.setSelectionRange(pos, pos); };
}

function exportJournal(fmt) {
    const list = journalFiltered();
    const stamp = new Date().toISOString().slice(0, 10);
    let content;
    if (fmt === 'json') content = JSON.stringify(list, null, 2);
    else {
        const q = s => `"${String(s == null ? '' : s).replace(/"/g, '""')}"`;
        content = ['time,severity,category,source,text', ...list.map(e => [e.t, e.sev, e.cat, e.src, e.text].map(q).join(','))].join('\n') + '\n';
    }
    sendToBackend({ action: 'save_text', filename: `dukiwi-shield-journal-${stamp}.${fmt}`, content });
}

// ─── Rapport de sécurité (PDF ou HTML) ─────────────────────────────────────
let pendingReport = null;
function exportReport(fmt) {
    pendingReport = fmt;
    sendToBackend({ action: 'get_security_data', type: 'journal', days: 30 });   // journal à jour, puis rapport
}

function buildReportHtml() {
    const c = secData.checklist || {}, v = (secData.vulns || {}).counts || {}, integ = secData.integrity || {};
    const st = lastStatus || {}, ds = st.distro || {};
    const e = s => escapeHtml(s == null ? '' : String(s));
    const statusTxt = s => t('report.status.' + (s || 'unknown'));
    const items = (c.items || []).slice().sort((a, b) => ({ fail: 0, warn: 1, unknown: 2, ok: 3, na: 4 }[a.status] - { fail: 0, warn: 1, unknown: 2, ok: 3, na: 4 }[b.status]));
    const hist = (c.history || []).slice(-12);
    const events = (journalData.events || []).filter(x => x.sev !== 'info').slice(0, 80);
    const high = (secData.vulns && secData.vulns.by_priority) ? (secData.vulns.by_priority.critical || 0) + (secData.vulns.by_priority.high || 0) : 0;
    return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><title>${e(t('report.title'))}</title><style>
        body{font:13px/1.5 "Segoe UI",system-ui,sans-serif;color:#111827;margin:28px 34px}h1{font-size:22px;margin:0}h2{font-size:15px;margin:22px 0 8px;border-bottom:1px solid #d1d5db;padding-bottom:4px}
        .meta{color:#4b5563;margin:4px 0 0}.score{display:flex;gap:18px;align-items:center}.big{font-size:40px;font-weight:700}.grade{font-size:18px;color:#374151}
        table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top}th{background:#f3f4f6;font-weight:600}
        .s-ok{color:#047857}.s-warn{color:#b45309}.s-fail{color:#b91c1c}.s-na,.s-unknown{color:#6b7280}.foot{margin-top:26px;color:#6b7280;font-size:11px}
        @page{size:A4;margin:14mm}</style></head><body>
        <h1>Dukiwi Shield — ${e(t('report.title'))}</h1>
        <p class="meta">${e(t('report.generated', { date: formatDateTime(new Date().toISOString()) }))}</p>
        <table style="margin-top:12px"><tr><th>${e(t('report.computer'))}</th><td>${e(st.hostname || '')}</td></tr>
            <tr><th>${e(t('report.system'))}</th><td>${e(ds.pretty || '')}${st.kernel ? ' · ' + e(st.kernel) : ''}</td></tr>
            <tr><th>${e(t('report.version'))}</th><td>${e(st.version || '')}</td></tr></table>
        <h2>${e(t('report.score_title'))}</h2>
        <div class="score"><span class="big">${e(c.score != null ? c.score : '—')}</span><span class="grade">${e(c.grade || '')}</span>
            <span class="meta">${c.checked_at ? e(formatDateTime(c.checked_at)) : ''}</span></div>
        ${hist.length > 1 ? `<table style="margin-top:8px"><tr>${hist.map(h => `<th style="white-space:nowrap">${e(fmtDay(h.d))}</th>`).join('')}</tr><tr>${hist.map(h => `<td>${e(h.s)}</td>`).join('')}</tr></table>` : ''}
        <h2>${e(t('report.checklist'))}</h2>
        <table><tr><th>${e(t('report.item'))}</th><th>${e(t('report.state'))}</th><th>${e(t('report.detail'))}</th></tr>
        ${items.map(i => `<tr><td>${e(t('check.' + i.key + '.title'))}</td><td class="s-${e(i.status)}">${e(statusTxt(i.status))}</td><td>${e(i.detail_key ? t(i.detail_key, i.detail_params || {}) : (i.detail || ''))}</td></tr>`).join('')}</table>
        <h2>${e(t('report.vulns'))}</h2><p>${e(t('report.vulns_line', { unfixed: v.unfixed || 0, high, pending: v.kernel_pending || 0 }))}</p>
        <h2>${e(t('report.integrity'))}</h2><p>${e(t('report.integrity_line', { date: integ.checked_at ? formatDateTime(integ.checked_at) : '—', n: integ.warnings || 0 }))}</p>
        <h2>${e(t('report.journal'))}</h2>
        ${events.length ? `<table><tr><th>${e(t('history.date'))}</th><th>${e(t('report.state'))}</th><th>${e(t('report.detail'))}</th></tr>${events.map(x => `<tr><td>${e(formatDateTime(x.t))}</td><td>${e(t('journal.sev.' + x.sev))} · ${e(t('journal.cat.' + x.cat))}</td><td>${e(x.text)}</td></tr>`).join('')}</table>` : `<p>${e(t('report.journal_none'))}</p>`}
        <p class="foot">${e(t('report.footer'))}</p></body></html>`;
}

function onJournalData(data) {
    journalData = data || { events: [] };
    renderJournal();
    if (pendingReport) {
        const fmt = pendingReport; pendingReport = null;
        const stamp = new Date().toISOString().slice(0, 10);
        const html = buildReportHtml();
        if (fmt === 'pdf') sendToBackend({ action: 'save_report_pdf', filename: `dukiwi-shield-rapport-${stamp}.pdf`, html });
        else sendToBackend({ action: 'save_text', filename: `dukiwi-shield-rapport-${stamp}.html`, content: html });
    }
}
