/* VISaR dashboard — inlined into visar_dashboard.html at build time.
 *
 * Kept as a sibling file (not a Python triple-quoted string) so editors can
 * apply syntax highlighting and so the SHA-256 CSP hash stays stable across
 * builds. The browser executes this verbatim — there is no minifier in the
 * pipeline by design (auditable plain JS is the goal).
 *
 * The DATASETS global is injected by dashboard_funcs.py in a sibling <script>
 * tag immediately before this one.
 */
(function () {
    'use strict';

    var tbody          = document.getElementById('vuln-tbody');
    var severityCards  = Array.from(document.querySelectorAll('.stat-card[data-filter]'));
    var searchInput    = document.getElementById('search-input');
    var resultCount    = document.getElementById('result-count');
    var emptyState     = document.getElementById('empty-state');
    var repoSelect     = document.getElementById('repo-select');
    var repoLink       = document.getElementById('repo-link');
    var dateSelect     = document.getElementById('date-select');
    var downloadBtn    = document.getElementById('download-csv');
    var diffBar        = document.getElementById('diff-bar');
    var diffBaselineEl = document.getElementById('diff-baseline-date');
    var diffNewEl      = document.getElementById('diff-count-new');
    var diffChangedEl  = document.getElementById('diff-count-changed');
    var diffResolvedEl = document.getElementById('diff-count-resolved');
    var toggleResolved = document.getElementById('toggle-resolved');
    var toggleChanges  = document.getElementById('toggle-changes-only');
    var baselineSelect = document.getElementById('baseline-select');
    var historySection = document.getElementById('scan-history');
    var historyRepoEl  = document.getElementById('history-repo');
    var historyTbody   = document.getElementById('history-tbody');
    var historyChart   = document.getElementById('history-chart');

    var SEV_ORDER    = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3 };
    var SEV_LABEL    = { CRITICAL: 'Critical', HIGH: 'High', MODERATE: 'Moderate', LOW: 'Low' };
    var activeFilter = 'all';
    var searchQuery  = '';
    var sortCol      = 'severity';
    var sortDir      = 'asc';
    var rows         = [];
    var currentDataset = null;
    var currentDiff    = null;   // { perRow, resolvedRows, counts, baseline } or null
    var showResolved   = false;
    var changesOnly    = false;
    // Which scan to diff against: 'previous' (the next-older scan) or 'first'
    // (the oldest scan of the repo, giving cumulative change since baseline).
    var baselineMode   = 'previous';

    // Group datasets by repo so the two-level Repo -> Scan selectors stay
    // independent. Scans within each repo are ordered newest-first.
    var REPOS = {};
    DATASETS.forEach(function (ds, i) {
        ds._idx = i;
        if (!REPOS[ds.repo]) { REPOS[ds.repo] = []; }
        REPOS[ds.repo].push(ds);
    });
    Object.keys(REPOS).forEach(function (r) {
        REPOS[r].sort(function (a, b) {
            return (b.isoDate || '').localeCompare(a.isoDate || '');
        });
    });
    var REPO_NAMES = Object.keys(REPOS).sort();

    // For each dataset _idx, store the next-older scan of the same repo (if any).
    // This is the baseline used for the implicit diff in renderDataset.
    var PREV_FOR_DATASET = {};
    Object.keys(REPOS).forEach(function (repo) {
        var scans = REPOS[repo];  // already sorted newest-first
        scans.forEach(function (ds, i) {
            if (i + 1 < scans.length) {
                PREV_FOR_DATASET[ds._idx] = scans[i + 1];
            }
        });
    });

    // Resolve the baseline dataset to diff a scan against, honouring the
    // current baselineMode. 'previous' uses the next-older scan; 'first' uses
    // the oldest scan of the repo so the diff is cumulative since that scan.
    // Returns null when there is no earlier scan to compare against (e.g. the
    // selected scan IS the first one).
    function baselineFor(ds) {
        if (baselineMode === 'first') {
            var scans = REPOS[ds.repo] || [];        // newest-first
            var first = scans[scans.length - 1];     // oldest scan
            return (first && first._idx !== ds._idx) ? first : null;
        }
        return PREV_FOR_DATASET[ds._idx] || null;
    }

    // Composite IDs ("PYSEC-xxx / GHSA-xxx") may appear in different orders
    // between scans — normalise by sorting segments so diff matches by identity
    function normalizeId(id) {
        return String(id).split(' / ').map(function (s) {
            return s.trim();
        }).filter(Boolean).sort().join(' / ');
    }

    // Compute the diff between current and baseline. Returns null if either
    // input is missing. Severity changes are surfaced separately from new/resolved.
    function computeDiff(currentDs, baselineDs) {
        if (!currentDs || !baselineDs) { return null; }
        var baseMap = {};
        baselineDs.rows.forEach(function (r) {
            baseMap[normalizeId(r.id)] = r;
        });
        var seen = {};
        var perRow = {};
        var counts = { newCount: 0, resolvedCount: 0, changedCount: 0, unchangedCount: 0 };
        currentDs.rows.forEach(function (r) {
            var n = normalizeId(r.id);
            seen[n] = true;
            if (!(n in baseMap)) {
                perRow[n] = { status: 'new' };
                counts.newCount++;
            } else if (baseMap[n].severity !== r.severity) {
                perRow[n] = { status: 'sev-changed', prevSeverity: baseMap[n].severity };
                counts.changedCount++;
            } else {
                perRow[n] = { status: 'unchanged' };
                counts.unchangedCount++;
            }
        });
        var resolvedRows = [];
        baselineDs.rows.forEach(function (r) {
            var n = normalizeId(r.id);
            if (!seen[n]) {
                resolvedRows.push(r);
                counts.resolvedCount++;
            }
        });
        resolvedRows.sort(function (a, b) {
            var av = SEV_ORDER.hasOwnProperty(a.severity) ? SEV_ORDER[a.severity] : 99;
            var bv = SEV_ORDER.hasOwnProperty(b.severity) ? SEV_ORDER[b.severity] : 99;
            return av - bv;
        });
        return {
            perRow: perRow,
            resolvedRows: resolvedRows,
            counts: counts,
            baseline: baselineDs
        };
    }

    var TRUNCATE = 300;

    // Inline clipboard icon — kept here so no external assets are needed
    var COPY_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        + 'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        + '<rect x="9" y="9" width="13" height="13" rx="2"></rect>'
        + '<path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>';

    // Escape HTML special characters when building innerHTML from data values
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Build OSV link(s) — handles composite IDs like "PYSEC-xxx / GHSA-xxx"
    // Each segment gets its own copy-to-clipboard button.
    function buildIdHtml(id) {
        return id.split(' / ').map(function (p) {
            p = p.trim();
            var safe = esc(p);
            return '<a href="https://osv.dev/vulnerability/' + safe + '"'
                + ' target="_blank" rel="noopener noreferrer">' + safe + '</a>'
                + '<button type="button" class="copy-btn" data-copy="' + safe + '"'
                + ' aria-label="Copy ' + safe + ' to clipboard"'
                + ' title="Copy ' + safe + '">' + COPY_ICON_SVG + '</button>';
        }).join('<span class="id-sep"> / </span>');
    }

    // Return the badge CSS class — unknown severities render as "other"
    function badgeClass(sev) {
        return SEV_ORDER.hasOwnProperty(sev) ? sev.toLowerCase() : 'other';
    }

    // Human-readable label for screen readers — the visible badge is uppercase
    // but we surface a sentence-cased "Severity: High" via aria-label so the
    // screen reader announcement carries context, not just the bare word.
    function badgeAriaLabel(sev) {
        return 'Severity: ' + (SEV_LABEL[sev] || (sev ? esc(sev) : 'Other'));
    }

    function updateStats(ds) {
        document.getElementById('stat-total').textContent    = ds.total;
        document.getElementById('stat-critical').textContent = ds.counts.CRITICAL;
        document.getElementById('stat-high').textContent     = ds.counts.HIGH;
        document.getElementById('stat-moderate').textContent = ds.counts.MODERATE;
        document.getElementById('stat-low').textContent      = ds.counts.LOW;
        document.getElementById('stat-other').textContent    = ds.counts.OTHER;
        document.getElementById('hdr-repo').textContent      = ds.repo;
        document.getElementById('hdr-date').textContent      = ds.date;
        document.title = 'VISaR — ' + ds.repo;

        // Surface the source repository as a clickable link beside the repo
        // dropdown, hidden when the URL couldn't be derived from the filename.
        if (repoLink) {
            if (ds.repoUrl) {
                repoLink.href = ds.repoUrl;
                repoLink.textContent = ds.repoUrl.replace(/^https?:\/\//, '');
                repoLink.title = 'Open ' + ds.repoUrl + ' in a new tab';
                repoLink.hidden = false;
            } else {
                repoLink.removeAttribute('href');
                repoLink.hidden = true;
            }
        }
    }

    // Build a <tr> for one row record. diffInfo is optional and carries the
    // status / prevSeverity from computeDiff so the row can show a tag and stripe.
    function buildRow(r, diffInfo) {
        var tr = document.createElement('tr');
        tr.dataset.severity = r.severity;
        tr.dataset.search = (r.id + ' ' + r.detail).toLowerCase();
        tr._row = r;
        if (diffInfo && diffInfo.status) {
            tr.dataset.diff = diffInfo.status;
            if (diffInfo.prevSeverity) {
                tr.dataset.prevSeverity = diffInfo.prevSeverity;
            }
        }
        var needsExpand = r.detail.length > TRUNCATE;
        var diffTag = '';
        if (diffInfo) {
            if (diffInfo.status === 'new') {
                diffTag = '<span class="diff-tag new" title="New since previous scan">NEW</span>';
            } else if (diffInfo.status === 'sev-changed') {
                diffTag = '<span class="diff-tag changed" title="Was '
                    + esc(diffInfo.prevSeverity) + ' in previous scan">RECLASSIFIED</span>';
            } else if (diffInfo.status === 'resolved') {
                diffTag = '<span class="diff-tag resolved" title="Present in previous scan, not in current">RESOLVED</span>';
            }
        }
        // Inline expansion of detail HTML: just a class-wrapped escaped span.
        // Expand button is wired via tbody event delegation (no inline onclick),
        // which keeps script-src CSP free of 'unsafe-inline'.
        tr.innerHTML =
            '<td class="id-cell">' + buildIdHtml(r.id) + diffTag + '</td>'
            + '<td><span class="badge ' + badgeClass(r.severity)
            + '" aria-label="' + esc(badgeAriaLabel(r.severity)) + '">'
            + esc(r.severity) + '</span></td>'
            + '<td class="detail-cell"><span class="det-text">' + esc(r.detail) + '</span></td>'
            + '<td class="expand-col">' + (needsExpand
                ? '<button type="button" class="expand-btn" aria-expanded="false" aria-label="Expand details">+</button>'
                : '') + '</td>';
        return tr;
    }

    function renderDataset(ds) {
        currentDataset = ds;
        currentDiff = computeDiff(ds, baselineFor(ds));
        updateStats(ds);
        updateDiffBar();
        renderScanHistory(ds);
        tbody.innerHTML = '';
        rows = ds.rows.map(function (r) {
            var info = currentDiff
                ? currentDiff.perRow[normalizeId(r.id)]
                : null;
            var tr = buildRow(r, info);
            tbody.appendChild(tr);
            return tr;
        });
        // Append resolved rows (synthesized from baseline) so they participate
        // in filter / search / sort just like current rows do
        if (currentDiff) {
            currentDiff.resolvedRows.forEach(function (r) {
                var tr = buildRow(r, { status: 'resolved' });
                tbody.appendChild(tr);
                rows.push(tr);
            });
        }
        // Reset vulnerability filter controls when switching datasets
        setActiveFilter('all');
        searchQuery = '';
        if (searchInput) { searchInput.value = ''; }
        sortCol = 'severity';
        sortDir = 'asc';
        document.querySelectorAll('th.sortable').forEach(function (t) {
            t.classList.remove('sorted-asc', 'sorted-desc');
        });
        document.querySelector('th[data-sort="severity"]').classList.add('sorted-asc');
        applyView();
    }

    function applyView() {
        var n = 0;
        rows.forEach(function (tr) {
            var sev = tr.dataset.severity;
            var diff = tr.dataset.diff || '';
            var isResolved = diff === 'resolved';
            var isChange = diff === 'new' || diff === 'sev-changed' || diff === 'resolved';

            var sevMatch = activeFilter === 'all'
                || sev === activeFilter
                || (activeFilter === 'OTHER' && !SEV_ORDER.hasOwnProperty(sev));
            var searchMatch = !searchQuery
                || tr.dataset.search.indexOf(searchQuery) !== -1;

            // Diff-aware visibility:
            //   - resolved rows only appear when showResolved OR changesOnly is on
            //   - changesOnly hides anything that didn't change between scans
            var diffMatch = true;
            if (isResolved && !(showResolved || changesOnly)) {
                diffMatch = false;
            }
            if (changesOnly && !isChange) {
                diffMatch = false;
            }

            var show = sevMatch && searchMatch && diffMatch;
            tr.classList.toggle('hidden', !show);
            if (show) n++;
        });
        resultCount.textContent = n + ' of ' + rows.length + ' vulnerabilities';
        updateEmptyState(n);
        if (downloadBtn) { downloadBtn.disabled = n === 0; }
    }

    function updateDiffBar() {
        // Keep the baseline selector in sync with the active mode regardless
        // of whether a diff is currently shown.
        if (baselineSelect) { baselineSelect.value = baselineMode; }
        if (!currentDiff) {
            diffBar.hidden = true;
            // Disable diff-only controls when there's no baseline to compare against
            if (toggleResolved) { toggleResolved.disabled = true; }
            if (toggleChanges)  { toggleChanges.disabled  = true; }
            return;
        }
        diffBar.hidden = false;
        diffBaselineEl.textContent = currentDiff.baseline.date;
        diffNewEl.textContent      = currentDiff.counts.newCount;
        diffChangedEl.textContent  = currentDiff.counts.changedCount;
        diffResolvedEl.textContent = currentDiff.counts.resolvedCount;
        if (toggleResolved) { toggleResolved.disabled = false; }
        if (toggleChanges)  { toggleChanges.disabled  = false; }
        // Reset toggles to default state on dataset switch
        showResolved = false;
        changesOnly = false;
        if (toggleResolved) { toggleResolved.setAttribute('aria-pressed', 'false'); }
        if (toggleChanges)  { toggleChanges.setAttribute('aria-pressed', 'false'); }
    }

    // --- Scan history ------------------------------------------------------
    // Build the per-scan history table + trend chart for the repo of the
    // currently-selected scan. Counts (new / resolved / reclassified) are each
    // computed against the immediately-prior scan, independent of the diff-bar
    // baseline toggle, so the table always reads as a chronological changelog.

    var SVG_NS = 'http://www.w3.org/2000/svg';

    function svgEl(name, attrs) {
        var el = document.createElementNS(SVG_NS, name);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                el.setAttribute(k, attrs[k]);
            });
        }
        return el;
    }

    // Round a value up to a tidy axis maximum so y-labels stay readable.
    function niceCeil(v) {
        if (v <= 5) { return 5; }
        var pow = Math.pow(10, Math.floor(Math.log(v) / Math.LN10));
        return Math.ceil(v / pow) * pow;
    }

    function renderScanHistory(currentDs) {
        if (!historySection) { return; }
        var scans = REPOS[currentDs.repo] || [];   // newest-first
        if (!scans.length) { historySection.hidden = true; return; }
        historySection.hidden = false;
        if (historyRepoEl) { historyRepoEl.textContent = currentDs.repo; }

        var chron = scans.slice().reverse();        // oldest-first
        historyTbody.innerHTML = '';
        var series = [];

        chron.forEach(function (ds, i) {
            var prior = i > 0 ? chron[i - 1] : null;
            var d = prior ? computeDiff(ds, prior) : null;
            var newC = d ? d.counts.newCount : null;
            var resC = d ? d.counts.resolvedCount : null;
            var chgC = d ? d.counts.changedCount : null;
            var isCurrent = ds._idx === currentDs._idx;

            var tr = document.createElement('tr');
            if (isCurrent) { tr.className = 'current-scan'; }
            function cell(text, cls) {
                var td = document.createElement('td');
                if (cls) { td.className = cls; }
                td.textContent = text;
                return td;
            }
            tr.appendChild(cell(ds.date, ''));
            tr.appendChild(cell(String(ds.total), 'num'));
            tr.appendChild(cell(newC === null ? '—' : '+' + newC, 'num new'));
            tr.appendChild(cell(resC === null ? '—' : '−' + resC, 'num resolved'));
            tr.appendChild(cell(chgC === null ? '—' : String(chgC), 'num changed'));
            historyTbody.appendChild(tr);

            series.push({
                date: ds.date, iso: ds.isoDate, total: ds.total,
                isCurrent: isCurrent, newCount: newC, resolvedCount: resC
            });
        });

        buildTrendChart(series);
    }

    function buildTrendChart(series) {
        if (!historyChart) { return; }
        historyChart.innerHTML = '';
        if (!series.length) { return; }

        var W = 560, H = 200;
        var padL = 40, padR = 18, padT = 22, padB = 44;
        var plotW = W - padL - padR;
        var plotH = H - padT - padB;
        var n = series.length;

        var maxTotal = 0;
        series.forEach(function (p) { if (p.total > maxTotal) { maxTotal = p.total; } });
        var yMax = niceCeil(maxTotal <= 0 ? 1 : maxTotal);

        // X positions are scaled linearly by calendar time (days between
        // scans), not by index — so uneven gaps between scans show as uneven
        // spacing. Falls back to equidistant if dates are missing or all equal.
        var times = series.map(function (p) {
            var t = p.iso ? Date.parse(p.iso) : NaN;
            return isNaN(t) ? null : t;
        });
        var validTimes = times.filter(function (t) { return t !== null; });
        var tMin = Math.min.apply(null, validTimes);
        var tMax = Math.max.apply(null, validTimes);
        var span = tMax - tMin;
        var useTime = validTimes.length === n && span > 0;

        function xFor(i) {
            if (n === 1) { return padL + plotW / 2; }
            if (useTime) { return padL + (plotW * (times[i] - tMin)) / span; }
            return padL + (plotW * i) / (n - 1);
        }
        function yFor(v) {
            return padT + plotH - (plotH * v) / yMax;
        }

        var svg = svgEl('svg', {
            viewBox: '0 0 ' + W + ' ' + H,
            preserveAspectRatio: 'xMidYMid meet',
            'aria-hidden': 'true'
        });

        // Horizontal gridlines + y-axis labels at 0, mid, max
        [0, yMax / 2, yMax].forEach(function (t) {
            var y = yFor(t);
            svg.appendChild(svgEl('line', {
                x1: padL, y1: y.toFixed(1), x2: W - padR, y2: y.toFixed(1),
                stroke: '#262626', 'stroke-width': 1
            }));
            var lbl = svgEl('text', {
                x: padL - 8, y: (y + 3).toFixed(1), 'text-anchor': 'end',
                fill: '#9ca3af', 'font-size': 10, 'font-family': 'inherit'
            });
            lbl.textContent = String(Math.round(t));
            svg.appendChild(lbl);
        });

        // Trend line
        if (n > 1) {
            var dPath = '';
            series.forEach(function (p, i) {
                dPath += (i === 0 ? 'M' : 'L')
                    + xFor(i).toFixed(1) + ' ' + yFor(p.total).toFixed(1) + ' ';
            });
            svg.appendChild(svgEl('path', {
                d: dPath.trim(), fill: 'none', stroke: '#4ade80',
                'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round'
            }));
        }

        // Markers, value labels, hover titles
        var prevCx = null;
        series.forEach(function (p, i) {
            var cx = xFor(i), cy = yFor(p.total);
            var marker = svgEl('circle', {
                cx: cx.toFixed(1), cy: cy.toFixed(1), r: p.isCurrent ? 5 : 3.5,
                fill: p.isCurrent ? '#86efac' : '#4ade80',
                stroke: '#0a0a0a', 'stroke-width': p.isCurrent ? 2 : 1
            });
            var title = svgEl('title');
            var bits = p.date + ': ' + p.total + ' total';
            if (p.newCount !== null && p.newCount !== undefined) {
                bits += ' (+' + p.newCount + ' new, −' + p.resolvedCount + ' resolved)';
            }
            title.textContent = bits;
            marker.appendChild(title);
            svg.appendChild(marker);

            // Lift the value label higher when this marker sits close to the
            // previous one, so clustered scans don't print their totals on top
            // of each other.
            var close = prevCx !== null && (cx - prevCx) < 26;
            var vlbl = svgEl('text', {
                x: cx.toFixed(1), y: (cy - (close ? 20 : 10)).toFixed(1),
                'text-anchor': 'middle',
                fill: p.isCurrent ? '#86efac' : '#d4d4d4', 'font-size': 10,
                'font-weight': p.isCurrent ? 700 : 400, 'font-family': 'inherit'
            });
            vlbl.textContent = String(p.total);
            svg.appendChild(vlbl);
            prevCx = cx;
        });

        // X-axis date labels. Linear time scaling can cluster scans, so draw
        // labels with collision avoidance: always keep the first and last,
        // skip any intermediate label that would overlap one already drawn,
        // and anchor the two end labels inward so they don't clip the edges.
        var labels = series.map(function (p, i) {
            return { x: xFor(i), text: p.date, w: p.date.length * 5.3 };
        });
        var last = labels.length - 1;
        var keep = [];
        labels.forEach(function (m, i) {
            if (i === 0 || i === last) { keep.push(i); return; }
            var prev = labels[keep[keep.length - 1]];
            if ((m.x - m.w / 2) > (prev.x + prev.w / 2) + 6) { keep.push(i); }
        });
        // Drop intermediate labels that would collide with the forced last one.
        while (keep.length > 2) {
            var pm = labels[keep[keep.length - 2]];
            if ((pm.x + pm.w / 2) + 6 > (labels[last].x - labels[last].w / 2)) {
                keep.splice(keep.length - 2, 1);
            } else { break; }
        }
        keep.forEach(function (idx) {
            var m = labels[idx], anchor = 'middle', x = m.x;
            if (idx === 0) { anchor = 'start'; x = padL; }
            else if (idx === last) { anchor = 'end'; x = W - padR; }
            var xlbl = svgEl('text', {
                x: x.toFixed(1), y: (H - padB + 18).toFixed(1),
                'text-anchor': anchor,
                fill: '#9ca3af', 'font-size': 9.5, 'font-family': 'inherit'
            });
            xlbl.textContent = m.text;
            svg.appendChild(xlbl);
        });

        historyChart.appendChild(svg);
    }

    // Distinguish a clean scan (zero findings full-stop) from a filtered
    // view that happens to show nothing — clean scans get a celebratory tone
    function updateEmptyState(visibleCount) {
        if (visibleCount > 0) {
            emptyState.hidden = true;
            return;
        }
        if (rows.length === 0) {
            var dateLabel = currentDataset ? currentDataset.date : '—';
            emptyState.textContent = 'No known vulnerabilities in this scan — clean as of '
                + dateLabel + '.';
            emptyState.classList.add('clean');
        } else {
            emptyState.textContent = 'No vulnerabilities match your current filter or search.';
            emptyState.classList.remove('clean');
        }
        emptyState.hidden = false;
    }

    function csvEscape(v) {
        var s = String(v == null ? '' : v);
        // Neutralise spreadsheet formula injection: a cell beginning with
        // = + - @ (or a leading tab / carriage return) is evaluated as a
        // formula by Excel / Google Sheets. Vulnerability details come from
        // OSV and are untrusted, so prefix such cells with an apostrophe to
        // force text interpretation. Done before quoting below.
        if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
        if (/[",\r\n]/.test(s)) { return '"' + s.replace(/"/g, '""') + '"'; }
        return s;
    }

    function safeFilename(s) {
        return String(s || 'export').replace(/[^A-Za-z0-9._-]+/g, '_');
    }

    // Map a tr's data-diff value to the CSV Status column value
    function statusLabelFor(tr) {
        var d = tr.dataset.diff || '';
        if (d === 'new') { return 'NEW'; }
        if (d === 'sev-changed') { return 'RECLASSIFIED'; }
        if (d === 'resolved') { return 'RESOLVED'; }
        if (currentDiff) { return 'UNCHANGED'; }
        return '';
    }

    // Build CSV from visible rows only — respects severity filter, search,
    // and any future column-sort the user applied. When a baseline diff is
    // active, an extra Status column is included and the filename records
    // which scan we compared against.
    function downloadFilteredCsv() {
        if (!currentDataset) { return; }
        var withDiff = !!currentDiff;
        var header = withDiff
            ? 'VulnerabilityID,Severity,Details,Status,PreviousSeverity'
            : 'VulnerabilityID,Severity,Details';
        var lines = [header];
        var n = 0;
        rows.forEach(function (tr) {
            if (tr.classList.contains('hidden')) { return; }
            var r = tr._row;
            var row = csvEscape(r.id) + ',' + csvEscape(r.severity)
                + ',' + csvEscape(r.detail);
            if (withDiff) {
                row += ',' + csvEscape(statusLabelFor(tr))
                    + ',' + csvEscape(tr.dataset.prevSeverity || '');
            }
            lines.push(row);
            n++;
        });
        if (n === 0) { return; }
        // Prepend a UTF-8 BOM so Excel opens unicode characters correctly
        var blob = new Blob(['﻿' + lines.join('\r\n') + '\r\n'],
            { type: 'text/csv;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var fname = safeFilename(currentDataset.repo)
            + '_' + safeFilename(currentDataset.isoDate);
        if (withDiff) {
            fname += '_vs_' + safeFilename(currentDiff.baseline.isoDate);
        }
        fname += '_filtered.csv';
        var a = document.createElement('a');
        a.href = url;
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    // Update which severity card is active — kept in one place so card click,
    // keyboard activation, and dataset switch all stay in sync
    function setActiveFilter(f) {
        activeFilter = f;
        severityCards.forEach(function (c) {
            var isActive = c.dataset.filter === f;
            c.classList.toggle('active', isActive);
            c.setAttribute('aria-pressed', isActive ? 'true' : 'false');
        });
    }

    function reSort() {
        rows.sort(function (a, b) {
            if (sortCol === 'severity') {
                var av = SEV_ORDER.hasOwnProperty(a.dataset.severity)
                    ? SEV_ORDER[a.dataset.severity] : 99;
                var bv = SEV_ORDER.hasOwnProperty(b.dataset.severity)
                    ? SEV_ORDER[b.dataset.severity] : 99;
                return sortDir === 'asc' ? av - bv : bv - av;
            }
            var at = a.querySelector('.id-cell').textContent.trim().toLowerCase();
            var bt = b.querySelector('.id-cell').textContent.trim().toLowerCase();
            return sortDir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
        });
        rows.forEach(function (tr) { tbody.appendChild(tr); });
        applyView();
    }

    function populateRepoSelect() {
        repoSelect.innerHTML = '';
        REPO_NAMES.forEach(function (name) {
            var opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            repoSelect.appendChild(opt);
        });
    }

    // Populate the Scan dropdown with every scan available for the given
    // repo, newest-first. Returns the dataset index of the option auto-selected.
    function populateDateSelect(repoName) {
        dateSelect.innerHTML = '';
        var scans = REPOS[repoName] || [];
        scans.forEach(function (ds) {
            var opt = document.createElement('option');
            opt.value = ds._idx;
            opt.textContent = ds.date;
            dateSelect.appendChild(opt);
        });
        return scans.length > 0 ? scans[0]._idx : -1;
    }

    severityCards.forEach(function (card) {
        card.addEventListener('click', function () {
            setActiveFilter(card.dataset.filter);
            applyView();
        });
        card.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setActiveFilter(card.dataset.filter);
                applyView();
            }
        });
    });

    if (searchInput) {
        searchInput.addEventListener('input', function () {
            searchQuery = searchInput.value.trim().toLowerCase();
            applyView();
        });
    }

    // Single tbody click listener handles both .copy-btn and .expand-btn —
    // letting us drop the inline onclick attribute on the expand button
    // (which would otherwise force 'unsafe-inline' in script-src).
    tbody.addEventListener('click', function (e) {
        if (!e.target.closest) { return; }
        var copyBtn = e.target.closest('.copy-btn');
        if (copyBtn) {
            e.preventDefault();
            var text = copyBtn.getAttribute('data-copy') || '';
            var done = function () {
                copyBtn.classList.add('copied');
                setTimeout(function () { copyBtn.classList.remove('copied'); }, 1200);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, function () {});
            } else {
                // Fallback for older browsers / file:// contexts without async clipboard.
                // Uses a CSS class (.copy-fallback) instead of inline style.* so we
                // can hash-pin style-src — no 'unsafe-inline' needed.
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.setAttribute('readonly', '');
                ta.className = 'copy-fallback';
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); done(); } catch (err) {}
                document.body.removeChild(ta);
            }
            return;
        }
        var expandBtn = e.target.closest('.expand-btn');
        if (expandBtn) {
            var tr = expandBtn.closest('tr');
            var expanded = tr.classList.toggle('expanded');
            expandBtn.textContent = expanded ? '−' : '+';
            expandBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
            expandBtn.setAttribute('aria-label', expanded ? 'Collapse details' : 'Expand details');
            return;
        }
    });

    repoSelect.addEventListener('change', function () {
        var idx = populateDateSelect(repoSelect.value);
        if (idx >= 0) { renderDataset(DATASETS[idx]); }
    });

    dateSelect.addEventListener('change', function () {
        var idx = parseInt(dateSelect.value, 10);
        if (!isNaN(idx)) { renderDataset(DATASETS[idx]); }
    });

    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadFilteredCsv);
    }

    if (toggleResolved) {
        toggleResolved.addEventListener('click', function () {
            showResolved = !showResolved;
            toggleResolved.setAttribute('aria-pressed', showResolved ? 'true' : 'false');
            applyView();
        });
    }
    if (toggleChanges) {
        toggleChanges.addEventListener('click', function () {
            changesOnly = !changesOnly;
            toggleChanges.setAttribute('aria-pressed', changesOnly ? 'true' : 'false');
            applyView();
        });
    }
    if (baselineSelect) {
        baselineSelect.addEventListener('change', function () {
            baselineMode = baselineSelect.value === 'first' ? 'first' : 'previous';
            // Re-render the current scan so the diff (and the row tags / stripes)
            // recompute against the newly chosen baseline.
            if (currentDataset) { renderDataset(currentDataset); }
        });
    }

    Array.from(document.querySelectorAll('th.sortable')).forEach(function (th) {
        th.addEventListener('click', function () {
            var col = th.dataset.sort;
            if (sortCol === col) {
                sortDir = sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                sortCol = col;
                sortDir = 'asc';
            }
            document.querySelectorAll('th.sortable').forEach(function (t) {
                t.classList.remove('sorted-asc', 'sorted-desc');
            });
            th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
            reSort();
        });
    });

    // Populate selectors and render the most-recent scan of the first repo
    // (DATASETS arrives newest-first, so DATASETS[0].repo gives the freshest)
    populateRepoSelect();
    if (DATASETS.length > 0) {
        var defaultRepo = DATASETS[0].repo;
        repoSelect.value = defaultRepo;
        var idx = populateDateSelect(defaultRepo);
        if (idx >= 0) { renderDataset(DATASETS[idx]); }
    } else {
        applyView();
    }
}());
