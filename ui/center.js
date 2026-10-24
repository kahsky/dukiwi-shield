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

// ═══ 2.3.0 : DNS filtré, isoler l'ordinateur, chiffrement du dossier personnel, bac à sable ═══════════
let dnsData = null;
let encData = null;

/** Appelé à chaque statut : bandeau d'isolement, page Isoler, état du bac à sable. */
function onCenterStatus(st) {
    renderIsolation((st && st.isolated) || null);
    const b = $('sandboxBadge'), btn = $('btnSandboxInstall');
    if (b) { b.textContent = t(st && st.firejail ? 'settings.sandbox.ready' : 'settings.sandbox.missing'); b.className = `badge ${st && st.firejail ? 'badge-green' : 'badge-amber'}`; }
    if (btn) btn.hidden = !!(st && st.firejail);
}

function renderIsolation(info) {
    const banner = $('isolatedBanner'), box = $('isolateBox');
    if (banner) {
        banner.hidden = !info;
        if (info) $('isolatedText').textContent = t('isolate.banner', { time: formatDateTime(info.at), n: (info.suspended || []).length });
    }
    if (!box) return;
    if (!info) {
        box.innerHTML = `<button class="btn btn-danger" onclick="confirmIsolate(true)">${escapeHtml(t('isolate.button'))}</button>`;
        return;
    }
    const procs = (info.suspended || []).map(p => `<li><b>${escapeHtml(p.comm)}</b> (pid ${p.pid}) — ${escapeHtml(p.exe)} · ${escapeHtml(t('isolate.reason.' + p.reason))}</li>`).join('');
    box.innerHTML = `<p class="isolate-on">${escapeHtml(t('isolate.active', { time: formatDateTime(info.at), method: t('isolate.method.' + info.method) }))}</p>
        ${procs ? `<p>${escapeHtml(t('isolate.suspended_list'))}</p><ul class="isolate-procs">${procs}</ul>` : `<p class="text-muted">${escapeHtml(t('isolate.none_suspended'))}</p>`}
        ${info.scan ? `<p class="text-muted">${escapeHtml(t('isolate.scan_started'))}</p>` : ''}
        <button class="btn btn-primary" onclick="confirmIsolate(false)">${escapeHtml(t('isolate.restore'))}</button>`;
}

async function confirmIsolate(on) {
    const ok = await appConfirm(on
        ? { title: t('isolate.confirm_title'), message: t('isolate.confirm_msg'), ok: t('isolate.button'), cancel: t('modal.cancel'), danger: true }
        : { title: t('isolate.restore_title'), message: t('isolate.restore_msg'), ok: t('isolate.restore'), cancel: t('modal.cancel') });
    if (ok) sendToBackend({ action: 'isolate', on });
}

function loadDnsFilter() { sendToBackend({ action: 'get_security_data', type: 'dns_filter' }); }

function onDnsFilterData(d) {
    dnsData = d || {};
    const badge = $('dnsBadge'), box = $('dnsBox');
    if (!box) return;
    const on = dnsData.active, susp = dnsData.suspended && dnsData.setting;
    badge.textContent = t(on ? 'dns.badge.on' : susp ? 'dns.badge.suspended' : 'dns.badge.off');
    badge.className = `badge ${on ? 'badge-green' : susp ? 'badge-blue' : 'badge-amber'}`;
    const opt = (v, k) => `<option value="${v}"${(dnsData.setting || '') === v ? ' selected' : ''}>${escapeHtml(t(k))}</option>`;
    const err = dnsData.error ? `<p class="dns-error">${escapeHtml(t('dns.error.' + dnsData.error))}</p>` : '';
    box.innerHTML = !dnsData.usable && !on
        ? `<p class="text-muted">${escapeHtml(t('dns.error.' + (dnsData.reason || 'resolved_missing')))}</p>`
        : `<label class="setting-row"><span>${escapeHtml(t('dns.provider'))}</span><select id="dnsProvider" class="lang-select">${opt('', 'dns.provider.off')}${opt('quad9', 'dns.provider.quad9')}${opt('cloudflare', 'dns.provider.cloudflare')}</select></label>
           ${err}${susp ? `<p class="text-muted">${escapeHtml(t('dns.suspended_note'))}</p>` : ''}
           <p class="text-muted">${escapeHtml(t('dns.note'))}</p>`;
    const sel = $('dnsProvider');
    if (sel) sel.onchange = e => { sendToBackend({ action: 'set_settings', system: { filtered_dns: e.target.value } }); setTimeout(loadDnsFilter, 6000); };
}

function loadEncryption(refresh = false) { sendToBackend({ action: 'get_security_data', type: 'home_encryption', refresh }); }

/** Assistant fscrypt : état, vérifications, puis étapes à suivre (commandes à copier). Rien n'est fait automatiquement. */
function onEncryptionData(d) {
    encData = d || {};
    const box = $('encryptionBox');
    if (!box) return;
    if (encData.disk_encrypted) { box.innerHTML = `<p class="enc-ok">✓ ${escapeHtml(t('encryption.disk_done'))}</p>`; return; }
    const users = encData.users || [];
    const ecr = users.some(u => u.method === 'ecryptfs') ? `<p class="text-muted">${escapeHtml(t('encryption.ecryptfs_note'))}</p>` : '';
    if (users.length && users.every(u => u.encrypted)) { box.innerHTML = `<p class="enc-ok">✓ ${escapeHtml(t('encryption.all_done'))}</p>${ecr}`; return; }
    const row = (ok, key, params = {}) => `<li class="${ok === true ? 'ok' : ok === false ? 'bad' : 'na'}">${ok === true ? '✓' : ok === false ? '✗' : '–'} ${escapeHtml(t(key, params))}</li>`;
    const checks = [
        row(encData.fs_supported, 'encryption.check.fs', { fs: encData.fs || '?' }),
        encData.fs === 'ext4' ? row(encData.encrypt_feature, 'encryption.check.feature') : '',
        row(encData.fscrypt, 'encryption.check.fscrypt'), row(encData.pam, 'encryption.check.pam'),
        encData.ecryptfs && !users.some(u => u.method === 'ecryptfs') ? row(false, 'encryption.check.ecryptfs') : '',
        ...users.map(u => row(u.encrypted ? true : (u.space_ok ? null : false), u.encrypted ? 'encryption.check.user_done' : u.space_ok ? 'encryption.check.user_todo' : 'encryption.check.user_space',
            { user: u.user, size: formatSize(u.size), free: formatSize(encData.free) })),
    ].join('');
    if (!encData.fs_supported) { box.innerHTML = `<ul class="enc-checks">${checks}</ul><p class="text-muted">${escapeHtml(t('encryption.unsupported'))}</p>`; return; }
    const todo = users.find(u => !u.encrypted) || { user: 'USER', home: '/home/USER' };
    const pkg = (lastStatus && lastStatus.distro && lastStatus.distro.family === 'rpm') ? 'sudo dnf install fscrypt' : 'sudo apt install fscrypt libpam-fscrypt';
    const steps = [
        ['encryption.step.backup', ''],
        encData.fscrypt && encData.pam ? null : ['encryption.step.install', pkg],
        encData.fs === 'ext4' && !encData.encrypt_feature ? ['encryption.step.feature' + (encData.boot_same_fs ? '_boot' : ''), `sudo tune2fs -O encrypt ${encData.device || '/dev/…'}`] : null,
        ['encryption.step.setup', 'sudo fscrypt setup\nsudo fscrypt setup /home'],
        ['encryption.step.logout', ''],
        ['encryption.step.migrate', `sudo mv ${todo.home} ${todo.home}.old\nsudo mkdir ${todo.home}\nsudo chown ${todo.user}: ${todo.home}\nsudo fscrypt encrypt ${todo.home} --user=${todo.user} --source=pam_passphrase\nsudo cp -a -T ${todo.home}.old ${todo.home}`],
        ['encryption.step.check', `fscrypt status ${todo.home}`],
        ['encryption.step.cleanup', `sudo rm -rf ${todo.home}.old`],
    ].filter(Boolean);
    box.innerHTML = `<ul class="enc-checks">${checks}</ul>
        <h5>${escapeHtml(t('encryption.steps_title'))}</h5>
        <ol class="enc-steps">${steps.map(([k, cmd]) => `<li>${escapeHtml(t(k, { user: todo.user }))}${cmd ? `<pre>${escapeHtml(cmd)}</pre>` : ''}</li>`).join('')}</ol>
        <p class="text-muted">${escapeHtml(t('encryption.warning'))}</p>`;
}

// ═══ 2.4.0 : test de restauration des sauvegardes ═════════════════════════════════════════════════════
function restoreTestLine(r, label) {
    if (!r) return `<div class="ts-line"><span class="ts-dot warn"></span><span>${escapeHtml(t('backup.restore_test.never', { what: label }))}</span></div>`;
    const err = r.error ? t(`backup.restore_test.error.${r.error}`) : '';
    const text = r.ok
        ? t('backup.restore_test.ok', { what: label, date: fmtDay(String(r.date || '').slice(0, 10)), n: r.restored, identical: r.identical, compared: r.compared })
        : t('backup.restore_test.bad', { what: label, date: fmtDay(String(r.date || '').slice(0, 10)), n: (r.failed || []).length, error: err });
    const files = (r.failed || []).slice(0, 4).map(f => `${f.path} (${t('backup.restore_test.fail.' + f.error) !== 'backup.restore_test.fail.' + f.error ? t('backup.restore_test.fail.' + f.error) : f.error})`).join(', ');
    return `<div class="ts-line"><span class="ts-dot ${r.ok ? 'ok' : 'danger'}"></span><span>${escapeHtml(text)}${files ? `<br><small class="text-muted">${escapeHtml(files)}</small>` : ''}</span></div>`;
}

function restoreTestHtml() {
    const d = (typeof backupData !== 'undefined' && backupData) || {};
    const parts = [];
    if ((d.destinations || []).length) {
        parts.push(restoreTestLine(d.restore_test, (d.restore_test && d.restore_test.dest_label) || t('backup.restore_test.files')));
        parts.push(`<div class="log-actions-right"><button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'backup_restore_test'})" ${d.restore_testing ? 'disabled' : ''}>${escapeHtml(t(d.restore_testing ? 'backup.restore_test.running' : 'backup.restore_test.run'))}</button></div>`);
    }
    if (d.timeshift_test && !['btrfs', 'not_configured', 'device_unmounted'].includes(d.timeshift_test.error)) parts.push(restoreTestLine(d.timeshift_test, 'Timeshift'));
    return parts.length ? `<div class="restore-test"><h5>${escapeHtml(t('backup.restore_test.title'))}</h5>${parts.join('')}</div>` : '';
}

// ═══ 2.4.0 : actions de la checklist, exposition sur Internet, « Après une attaque » ═══════════════════
async function confirmCenterAction(key, msg) {
    const ok = await appConfirm({ title: t(`check.${key}.confirm_title`), message: t(`check.${key}.confirm_msg`), ok: t(`check.${key}.action`), cancel: t('modal.cancel') });
    if (ok) sendToBackend(msg);
}

async function runExposureTest() {
    const ok = await appConfirm({ title: t('exposure.confirm_title'), message: t('exposure.confirm_msg'), ok: t('exposure.run'), cancel: t('modal.cancel') });
    if (!ok) return;
    const box = $('exposureBox');
    if (box) box.innerHTML = `<p class="text-muted">${escapeHtml(t('exposure.running'))}</p>`;
    sendToBackend({ action: 'exposure_test', consent: true });
}

function onExposureData(d) {
    const box = $('exposureBox');
    if (!box) return;
    const test = (d && d.test) || null, upnp = (d && d.upnp) || null;
    let html = '';
    if (!test) html += `<p class="text-muted">${escapeHtml(t('exposure.never'))}</p>`;
    else if (!test.ok) html += `<p class="dns-error">${escapeHtml(t('exposure.error.' + (test.error || 'unreachable')) !== 'exposure.error.' + (test.error || 'unreachable') ? t('exposure.error.' + (test.error || 'unreachable')) : (test.error || ''))}</p>`;
    else if (!(test.open || []).length) html += `<p class="enc-ok">✓ ${escapeHtml(t('exposure.none_open', { ip: test.ip, n: (test.tested || []).length, date: formatDateTime(test.at) }))}</p>`;
    else html += `<p class="isolate-on">${escapeHtml(t('exposure.open', { ip: test.ip, date: formatDateTime(test.at) }))}</p><ul class="isolate-procs">${test.open.map(p => `<li><b>${p}/tcp</b> — ${escapeHtml(t('exposure.port.' + p) !== 'exposure.port.' + p ? t('exposure.port.' + p) : t('exposure.port.other'))}</li>`).join('')}</ul><p class="text-muted">${escapeHtml(t('exposure.open_fix'))}</p>`;
    html += `<h5>${escapeHtml(t('exposure.upnp_title'))}</h5>`;
    if (!upnp) html += `<p class="text-muted">${escapeHtml(t('exposure.upnp_unknown'))}</p>`;
    else if (!upnp.router) html += `<p class="text-muted">${escapeHtml(t('exposure.upnp_none'))}</p>`;
    else {
        const maps = upnp.mappings || [];
        html += `<p>${escapeHtml(t('exposure.upnp_router', { router: upnp.router, model: upnp.model || '', n: maps.length }))}</p>`;
        if (maps.length) html += `<ul class="isolate-procs">${maps.map(m => `<li${m.this_host ? ' class="isolate-on"' : ''}>${escapeHtml(`${m.external}/${m.protocol} → ${m.client}:${m.internal}`)} ${m.description ? `— ${escapeHtml(m.description)}` : ''}${m.this_host ? ` · ${escapeHtml(t('exposure.upnp_this_host'))}` : ''}</li>`).join('')}</ul>`;
        html += `<p class="text-muted">${escapeHtml(t('exposure.upnp_advice'))}</p>`;
    }
    box.innerHTML = html;
}

// Étapes : [clé, action (bouton), page/onglet à ouvrir]
const INCIDENT_STEPS = [
    ['isolate', () => confirmIsolate(true)],
    ['scan', () => startFullSystemScan(true)],
    ['alerts', () => switchTab('system')],
    ['integrity', () => { openSection('security', 'integrity'); loadSecurityData('integrity', false, true); }],
    ['persistence', () => { switchTab('system'); setTimeout(() => { const el = $('persistenceList'); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 150); }],
    ['sshkeys', () => openSection('security', 'sshkeys')],
    ['checklist', () => switchTab('security')],
    ['passwords', () => openSection('security', 'leaks')],
    ['sessions', null],
    ['updates', () => switchTab('update')],
    ['restore', () => switchTab('backup')],
    ['report', null],
    ['keep', () => exportReport('pdf')],
    ['reconnect', () => confirmIsolate(false)],
];
let incidentData = {};

function onIncidentData(d) {
    incidentData = d || {};
    const box = $('incidentBox');
    if (!box) return;
    const steps = incidentData.steps || {};
    const isolated = !!(lastStatus && lastStatus.isolated);
    box.innerHTML = `<ol class="incident-steps">${INCIDENT_STEPS.map(([k, fn], i) => {
        const done = !!steps[k] || (k === 'isolate' && isolated);
        return `<li class="${done ? 'done' : ''}">
            <label class="incident-check"><input type="checkbox" ${done ? 'checked' : ''} onchange="incidentToggle('${k}', this.checked)"> <b>${escapeHtml(t(`incident.${k}.title`))}</b></label>
            <div class="text-muted">${escapeHtml(t(`incident.${k}.text`))}</div>
            ${fn ? `<button class="btn btn-secondary btn-sm" onclick="INCIDENT_STEPS[${i}][1]()">${escapeHtml(t(`incident.${k}.action`))}</button>` : ''}
        </li>`;
    }).join('')}</ol>`;
}

function incidentToggle(key, done) { sendToBackend({ action: 'incident_step', key, done }); }

async function incidentReset() {
    const ok = await appConfirm({ title: t('incident.reset_title'), message: t('incident.reset_msg'), ok: t('incident.reset'), cancel: t('modal.cancel') });
    if (ok) sendToBackend({ action: 'incident_step', reset: true });
}

// ═══ 2.5.0 : clés SSH autorisées, résumé de la semaine ════════════════════════════════════════════════
function onSshKeysData(keys) {
    const box = $('sshKeysBox');
    if (!box) return;
    keys = keys || [];
    if (!keys.length) { box.innerHTML = `<p class="text-muted">${escapeHtml(t('sshkeys.none'))}</p>`; return; }
    box.innerHTML = keys.map(k => `<div class="package-item">
        <span class="scope-badge scope-user">${escapeHtml(k.user)}</span>
        <span class="package-name">${escapeHtml(k.comment || k.type)}</span>
        <span class="package-versions" title="${escapeHtml(k.path)}">${escapeHtml(k.type)} · ${escapeHtml(k.fp)}${k.options ? ` · ${escapeHtml(k.options)}` : ''}</span>
        <button class="btn btn-danger btn-sm" onclick="removeSshKey('${escapeJs(k.path)}','${escapeJs(k.fp)}','${escapeJs(k.comment || k.type)}')">${escapeHtml(t('sshkeys.remove'))}</button>
    </div>`).join('') + `<p class="text-muted">${escapeHtml(t('sshkeys.note'))}</p>`;
}

async function removeSshKey(path, fp, label) {
    const ok = await appConfirm({ title: t('sshkeys.remove_title'), message: t('sshkeys.remove_msg', { key: label, fp, path }), ok: t('sshkeys.remove'), cancel: t('modal.cancel'), danger: true });
    if (ok) sendToBackend({ action: 'ssh_key_remove', path, fp });
}

function onWeeklySummary(d) {
    const box = $('weeklyBox');
    if (!box) return;
    if (!d) { box.innerHTML = ''; return; }
    const b = d.blocked || {};
    const delta = d.score != null && d.score_before != null && d.score !== d.score_before ? ` (${d.score > d.score_before ? '+' : ''}${d.score - d.score_before})` : '';
    const cells = [
        [t('weekly.score'), `${d.score ?? '—'} ${d.grade || ''}${delta}`], [t('weekly.scans'), `${d.scans} · ${(d.files || 0).toLocaleString(locale())}`],
        [t('weekly.alerts'), `${d.alerts} (${d.danger} ${t('weekly.danger')})`], [t('weekly.threats'), b.threats || 0],
        [t('weekly.links'), b.links || 0], [t('weekly.suspended'), b.suspended || 0], [t('weekly.network'), b.network || 0], [t('weekly.changes'), b.changes || 0],
    ];
    box.innerHTML = `<div class="weekly-card"><h5>${escapeHtml(t('weekly.title', { date: fmtDay(String(d.date || '').slice(0, 10)) }))}</h5>
        <div class="weekly-grid">${cells.map(([k, v]) => `<div><span class="text-muted">${escapeHtml(k)}</span><b>${escapeHtml(String(v))}</b></div>`).join('')}</div>
        ${(d.todo || []).length ? `<p class="text-muted">${escapeHtml(t('weekly.todo'))} ${d.todo.map(k => escapeHtml(t('check.' + k + '.title'))).join(', ')}</p>` : ''}</div>`;
}

// ═══ 2.7.0 : dossiers protégés ═══════════════════════════════════════════════════════════════════════
function onProtectedData(d) {
    const box = $('protectedBox'), badge = $('protectedBadge');
    if (!box) return;
    d = d || {};
    const state = d.active ? 'on' : d.enabled ? (d.error ? 'error' : 'starting') : 'off';
    if (badge) { badge.textContent = t('protected.badge.' + state); badge.className = `badge ${state === 'on' ? 'badge-green' : state === 'error' ? 'badge-red' : 'badge-amber'}`; }
    const roots = (d.roots || []).map(r => `<li><code>${escapeHtml(r)}</code>${(d.extra || []).includes(r) ? ` <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'protected_folder', remove:true, path:'${escapeJs(r)}'})">${escapeHtml(t('settings.trusted.remove'))}</button>` : ''}</li>`).join('');
    const allowed = (d.allowed || []).map(e => `<li><code>${escapeHtml(e)}</code> <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'protected_allow', remove:true, exe:'${escapeJs(e)}'})">${escapeHtml(t('settings.trusted.remove'))}</button></li>`).join('');
    box.innerHTML = `
        ${d.error ? `<p class="dns-error">${escapeHtml(t('protected.error.' + d.error) !== 'protected.error.' + d.error ? t('protected.error.' + d.error) : d.error)}</p>` : ''}
        ${d.active ? `<p class="text-muted">${escapeHtml(t('protected.stats', { n: d.marked || 0, denied: d.denied || 0 }))}</p>` : ''}
        ${!d.enabled ? `<p><button class="btn btn-primary btn-sm" onclick="confirmProtected()">${escapeHtml(t('protected.enable'))}</button></p>` : ''}
        <h5>${escapeHtml(t('protected.folders'))}</h5><ul class="protected-list">${roots || `<li class="text-muted">—</li>`}</ul>
        <div class="backup-add-row"><input type="text" id="protectedAdd" class="input-field input-sm input-wide" placeholder="/home/…/Projets"><button class="btn btn-secondary btn-sm" onclick="addProtectedFolder()">${escapeHtml(t('protected.add'))}</button></div>
        <h5>${escapeHtml(t('protected.allowed'))}</h5><ul class="protected-list">${allowed || `<li class="text-muted">${escapeHtml(t('protected.allowed_none'))}</li>`}</ul>
        <p class="text-muted">${escapeHtml(t('protected.note'))}</p>`;
}

async function confirmProtected() {
    const ok = await appConfirm({ title: t('protected.confirm_title'), message: t('protected.confirm_msg'), ok: t('protected.enable'), cancel: t('modal.cancel') });
    if (!ok) return;
    if ($('setProtectedFolders')) $('setProtectedFolders').checked = true;
    sendToBackend({ action: 'set_settings', system: { protected_folders: true } });
    setTimeout(() => sendToBackend({ action: 'get_security_data', type: 'protected' }), 15000);
}

function addProtectedFolder() {
    const el = $('protectedAdd');
    const path = el ? el.value.trim() : '';
    if (path) sendToBackend({ action: 'protected_folder', path });
}
