/* Dukiwi Shield — authentification de l'expéditeur (Thunderbird). SPF, DKIM et DMARC sont lus dans les en-têtes
   Authentication-Results (et ARC-Authentication-Results, Received-SPF) posés par le serveur de réception, avec
   alignement sur le domaine de l'expéditeur ; plus deux heuristiques d'usurpation : adresse de réponse d'un autre
   domaine (fraude au président) et nom affiché contenant une autre adresse e-mail. Fonctions pures (testables avec node). */
'use strict';
const MailAuth = (() => {
    const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'com.br', 'net.br', 'org.br', 'gov.br', 'co.nz', 'net.nz', 'org.nz',
        'co.za', 'org.za', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw', 'co.in', 'co.kr', 'com.my',
        'com.ph', 'com.pl', 'com.pe', 'com.co', 'com.ve', 'com.ec', 'com.uy', 'com.ua', 'com.eg', 'com.sa', 'com.ng', 'co.ke',
        'co.il', 'org.il', 'co.th', 'co.id', 'com.vn', 'com.pk', 'com.bd', 'com.lb', 'com.qa', 'com.tn', 'co.ma']);
    // Fournisseurs grand public : une adresse de réponse chez eux, pour un expéditeur d'entreprise, est la signature de la
    // fraude au président (« From: direction@entreprise.ch, Reply-To: direction.entreprise@gmail.com »)
    const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'yahoo.fr',
        'yahoo.de', 'yahoo.it', 'aol.com', 'protonmail.com', 'proton.me', 'gmx.com', 'gmx.net', 'gmx.ch', 'gmx.de', 'gmx.fr',
        'icloud.com', 'me.com', 'mail.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'bluewin.ch', 'sunrise.ch', 'orange.fr',
        'wanadoo.fr', 'free.fr', 'laposte.net', 'sfr.fr', 'web.de', 't-online.de', 'libero.it', 'tiscali.it', 'zoho.com']);

    function orgDomain(host) {
        const h = String(host || '').toLowerCase().replace(/\.$/, '');
        const parts = h.split('.').filter(Boolean);
        if (parts.length <= 2) return h;
        const last2 = parts.slice(-2).join('.');
        return TWO_LEVEL.has(last2) ? parts.slice(-3).join('.') : last2;
    }
    function addressOf(s) {
        const m = String(s || '').match(/<([^<>]+)>/);
        const a = (m ? m[1] : String(s || '')).trim().toLowerCase();
        return /^[^\s@]+@[^\s@]+$/.test(a) ? a : '';
    }
    function domainOf(addr) { const i = String(addr || '').lastIndexOf('@'); return i >= 0 ? addr.slice(i + 1) : ''; }
    function displayNameOf(s) { const m = String(s || '').match(/^\s*"?([^"<]*?)"?\s*<[^>]+>\s*$/); return m ? m[1].trim() : ''; }
    function headerList(headers, name) {
        if (!headers) return [];
        const v = headers[name] !== undefined ? headers[name] : headers[name.toLowerCase()];
        return Array.isArray(v) ? v : v ? [v] : [];
    }
    function unfold(raw) { return String(raw || '').replace(/\r?\n[ \t]+/g, ' '); }

    function parseAuthResults(values) {
        const spf = [], dkim = [], dmarc = [];
        for (const raw of values) {
            const clauses = unfold(raw).split(';');
            for (const clause of clauses.slice(1)) {                   // la première partie est l'identifiant du serveur
                const c = clause.trim();
                let m;
                if ((m = c.match(/^spf=(\w+)/i))) {
                    spf.push({ result: m[1].toLowerCase(), mailfrom: ((c.match(/smtp\.mailfrom=([^\s;()]+)/i) || [])[1] || '').toLowerCase().replace(/^.*@/, '') });
                } else if ((m = c.match(/^dkim=(\w+)/i))) {
                    dkim.push({ result: m[1].toLowerCase(), domain: ((c.match(/header\.d=([^\s;()]+)/i) || c.match(/header\.i=@?([^\s;()]+)/i) || [])[1] || '').toLowerCase() });
                } else if ((m = c.match(/^dmarc=(\w+)/i))) {
                    dmarc.push({ result: m[1].toLowerCase(), from: ((c.match(/header\.from=([^\s;()]+)/i) || [])[1] || '').toLowerCase() });
                }
            }
        }
        return { spf, dkim, dmarc };
    }

    function analyze(headers, author) {
        const fromHeader = headerList(headers, 'from')[0] || author || '';
        const from = addressOf(fromHeader);
        const fromDomain = domainOf(from), fromOrg = orgDomain(fromDomain);
        const aligned = d => !d || orgDomain(d) === fromOrg;
        const r = parseAuthResults(headerList(headers, 'authentication-results').concat(headerList(headers, 'arc-authentication-results')));
        const receivedSpf = headerList(headers, 'received-spf').map(v => ((unfold(v).trim().match(/^(\w+)/) || [])[1] || '').toLowerCase()).filter(Boolean);
        const dkimSigned = headerList(headers, 'dkim-signature').map(v => ((unfold(v).match(/\bd=([^\s;]+)/) || [])[1] || '').toLowerCase()).filter(Boolean);
        const reasons = [];
        let verdict = 'none', method = '';
        if (r.dmarc.some(d => d.result === 'pass' || d.result === 'bestguesspass')) { verdict = 'ok'; method = 'DMARC'; }
        else if (r.dkim.some(d => d.result === 'pass' && d.domain && aligned(d.domain))) { verdict = 'ok'; method = 'DKIM'; }
        else if (r.spf.some(s => s.result === 'pass' && aligned(s.mailfrom)) || (!r.spf.length && receivedSpf.includes('pass'))) { verdict = 'ok'; method = 'SPF'; }
        if (verdict !== 'ok') {
            if (r.dmarc.some(d => d.result === 'fail')) reasons.push('dmarc_fail');
            if (r.dkim.some(d => d.result === 'fail' && aligned(d.domain))) reasons.push('dkim_fail');
            if (r.spf.some(s => s.result === 'fail' && aligned(s.mailfrom)) || (!r.spf.length && receivedSpf.includes('fail'))) reasons.push('spf_fail');
            else if (r.spf.some(s => s.result === 'softfail' && aligned(s.mailfrom)) || (!r.spf.length && receivedSpf.includes('softfail'))) reasons.push('spf_softfail');
            if (reasons.length) verdict = 'fail';
        }
        // Heuristiques d'usurpation, indépendantes des en-têtes d'authentification
        const replyTo = addressOf(headerList(headers, 'reply-to')[0] || '');
        const replyOrg = replyTo ? orgDomain(domainOf(replyTo)) : '';
        if (replyTo && fromDomain && replyOrg !== fromOrg && (verdict !== 'ok' || FREE_MAIL.has(replyOrg))) reasons.push('reply_to_differs');
        const name = displayNameOf(fromHeader);
        const nameAddr = addressOf(name) || ((name.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/) || [])[0] || '').toLowerCase();
        if (nameAddr && fromDomain && orgDomain(domainOf(nameAddr)) !== fromOrg) reasons.push('display_name_address');
        if (verdict !== 'fail' && reasons.length) verdict = 'warn';
        return { verdict, method, reasons, from, fromDomain, replyTo, dkimSigned, spf: r.spf, dkim: r.dkim, dmarc: r.dmarc };
    }
    return { analyze, orgDomain, addressOf, parseAuthResults };
})();
if (typeof module !== 'undefined') module.exports = MailAuth;
