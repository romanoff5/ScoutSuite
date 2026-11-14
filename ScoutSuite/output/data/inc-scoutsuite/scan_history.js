/* P4-F2 Scan History: keyless, local-only browsing of Scout RESULTS and snapshots.
 * Real resource IDs and ARN remain visible when loaded from normal RESULTS.
 * Signed P4-F/P4-F2 snapshots are only previewed here: without the local key
 * their HMAC authenticity CANNOT be verified, and this UI never says otherwise.
 * No fetch, no eval, no persistent storage, no raw data sent to servers.
 */
(function (root) {
  'use strict'

  const MAX_BYTES = 64 * 1024 * 1024
  const MAX_SCANS = 24
  const MAX_ROWS = 600
  const RULES = Object.freeze({
    'ec2-instance-imdsv1-enabled': {
      service: 'ec2', path: 'ec2.regions.id.vpcs.id.instances.id.imds_v2_status',
      field: 'this', target: 'optional', allowed: ['optional', 'required', 'disabled', 'unknown']
    },
    'ec2-account-imdsv2-not-required-default': {
      service: 'ec2', path: 'ec2.regions.id.regional_settings.id',
      field: 'account_imds_default_status', target: 'not_required',
      allowed: ['required', 'not_required', 'unknown']
    },
    'cloudwatch-log-group-unlimited-retention': {
      service: 'cloudwatch', path: 'cloudwatch.regions.id.log_groups.id',
      field: 'retention_status', target: 'unlimited',
      allowed: ['unlimited', 'configured', 'unknown']
    },
    'cloudwatch-log-group-no-customer-kms': {
      service: 'cloudwatch', path: 'cloudwatch.regions.id.log_groups.id',
      field: 'customer_kms_status', target: 'aws_managed',
      allowed: ['customer_kms', 'aws_managed', 'unknown']
    },
    'rds-proxy-require-tls-disabled': {
      service: 'rds', path: 'rds.regions.id.proxies.id',
      field: 'tls_status', target: 'disabled', allowed: ['enabled', 'disabled', 'unknown']
    }
  })
  const scans = []
  let selected = 0

  function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  }

  function decode(text) {
    if (typeof text !== 'string') throw new Error('Not a text report')
    const clean = text.replace(/^\uFEFF/, '').trim()
    const assigned = /^scoutsuite_results\s*=\s*/.test(clean)
    const raw = assigned ? clean.replace(/^scoutsuite_results\s*=\s*/, '').replace(/;\s*$/, '') : clean
    const value = JSON.parse(raw)
    if (!isObject(value)) throw new Error('A JSON object is required')
    return value
  }

  function inspect(data, label) {
    if (!isObject(data)) throw new Error('Invalid report object')
    if (data.format === 'scoutsuite-semantic-facts' && data.schema_version === 1) {
      if (!isObject(data.rules) || !Object.keys(data.rules).length ||
          typeof data.key_id !== 'string' || !isObject(data.integrity)) {
        throw new Error('Invalid P4-F2 snapshot')
      }
      return { type: 'facts', label, data, provider: 'aws', account: '',
        date: '', completeness: data.source_collection_status || 'incomplete' }
    }
    if (data.format === 'scoutsuite-evidence-snapshot' && data.schema_version === 1) {
      if (!isObject(data.findings) || typeof data.key_id !== 'string' ||
          !isObject(data.integrity)) throw new Error('Invalid P4-F snapshot')
      return { type: 'observations', label, data, provider: 'aws', account: '',
        date: '', completeness: data.collection && data.collection.status || 'incomplete' }
    }
    if (!isObject(data.services) || !['aws', 'azure', 'gcp', 'aliyun', 'oci', 'kubernetes', 'do'].includes(data.provider_code)) {
      throw new Error('Unsupported Scout RESULTS file')
    }
    if (data.report_schema_version !== undefined &&
        data.report_schema_version !== 0 && data.report_schema_version !== 1) {
      throw new Error('Unsupported report schema version')
    }
    return { type: 'report', label, data, provider: data.provider_code,
      account: String(data.account_id || ''), date: String(data.last_run && (
        data.last_run.time || data.last_run.date || data.last_run.timestamp) || ''),
      completeness: isObject(data.collection_status) && data.collection_status.complete === true
        ? 'observed_complete' : 'incomplete' }
  }

  function findFacts(data, definition) {
    const path = definition.path.split('.')
    const out = []
    let incomplete = false
    function visit(node, remaining, prefix) {
      if (!remaining.length) {
        const value = definition.field === 'this'
          ? node : isObject(node) ? node[definition.field] : undefined
        const safe = typeof value === 'string' && definition.allowed.includes(value) ? value : 'unknown'
        out.push({ id: prefix.join('.'), value: safe, match: safe === definition.target })
        return
      }
      const [head, ...tail] = remaining
      if (!isObject(node)) { incomplete = true; return }
      if (head === 'id') {
        for (const id of Object.keys(node).sort()) visit(node[id], tail, prefix.concat(id))
      } else if (Object.prototype.hasOwnProperty.call(node, head)) {
        visit(node[head], tail, prefix.concat(head))
      } else {
        incomplete = true
        if (!tail.length && head !== 'id') {
          out.push({ id: prefix.concat(head).join('.'), value: 'unknown', match: false })
        }
      }
    }
    visit({ [definition.service]: data.services[definition.service] }, path, [])
    return { facts: out, incomplete }
  }

  function semantic(scan) {
    const results = {}
    if (scan.type === 'report') {
      if (scan.provider !== 'aws') return results
      for (const [rule, def] of Object.entries(RULES)) {
        const found = findFacts(scan.data, def)
        const flagged = found.facts.filter(f => f.match).map(f => f.id)
        const unknown = found.facts.filter(f => f.value === 'unknown').length
        results[rule] = { count: flagged.length, ids: flagged, unknown,
          status: scan.completeness === 'observed_complete' &&
            !found.incomplete && !unknown ? 'observed' : 'partial',
          evidence: found.facts }
      }
    } else if (scan.type === 'facts') {
      for (const [rule, def] of Object.entries(RULES)) {
        const row = scan.data.rules[rule]
        if (!isObject(row) || !Array.isArray(row.facts)) continue
        const safe = row.facts.filter(f => isObject(f) && typeof f.token === 'string' &&
          /^hmac:[0-9a-f]{40}$/.test(f.token) && def.allowed.includes(f.value))
        const flagged = safe.filter(f => f.value === def.target).map(f => f.token)
        const unknown = safe.filter(f => f.value === 'unknown').length
        results[rule] = { count: flagged.length, ids: flagged, unknown,
          status: scan.completeness === 'observed_complete' &&
            row.scope === 'observed' && !unknown && safe.length === row.facts.length ? 'unverified' : 'partial',
          evidence: safe.map(f => ({ id: f.token, value: f.value, match: f.value === def.target })) }
      }
    }
    return results
  }

  function observations(scan) {
    const rules = {}
    if (scan.type === 'report') {
      for (const [service, data] of Object.entries(scan.data.services)) {
        if (!isObject(data) || !isObject(data.findings)) continue
        for (const [rule, record] of Object.entries(data.findings)) {
          if (!isObject(record)) continue
          const key = service + '/' + rule
          rules[key] = {
            ids: Array.isArray(record.items) ? record.items.filter(x => typeof x === 'string') : [],
            count: Number.isSafeInteger(record.flagged_items) ? record.flagged_items : null,
            status: typeof record.assessment_status === 'string' ? record.assessment_status : 'unknown'
          }
        }
      }
    } else if (scan.type === 'observations') {
      for (const [service, items] of Object.entries(scan.data.findings)) {
        if (!isObject(items)) continue
        for (const [rule, entry] of Object.entries(items)) {
          if (!isObject(entry)) continue
          rules[service + '/' + rule] = {
            ids: Array.isArray(entry.flagged_identity_tokens) ? entry.flagged_identity_tokens : [],
            count: Number.isSafeInteger(entry.flagged_items) ? entry.flagged_items : null,
            status: entry.evidence_status || 'unknown'
          }
        }
      }
    } else {
      for (const [rule, value] of Object.entries(semantic(scan))) {
        rules[RULES[rule].service + '/' + rule] = {
          ids: value.ids, count: value.count, status: value.status
        }
      }
    }
    return rules
  }

  function sameIdentitySpace(a, b) {
    if (a.type === 'report' && b.type === 'report') {
      return a.provider === b.provider && !!a.account && a.account === b.account
    }
    if (a.type === 'report' || b.type === 'report') return false
    return a.data.key_id === b.data.key_id
  }

  function compare(a, b) {
    const old = observations(a)
    const fresh = observations(b)
    const comparable = sameIdentitySpace(a, b)
    const rows = []
    let added = 0, resolved = 0, incomplete = 0
    for (const rule of Array.from(new Set([...Object.keys(old), ...Object.keys(fresh)])).sort()) {
      const previous = old[rule], current = fresh[rule]
      const before = previous && previous.count !== null ? previous.count : null
      const after = current && current.count !== null ? current.count : null
      const valid = comparable && !!previous && !!current &&
        !['unknown', 'incomplete', 'partial', 'unavailable'].includes(previous.status) &&
        !['unknown', 'incomplete', 'partial', 'unavailable'].includes(current.status) &&
        a.completeness === 'observed_complete' && b.completeness === 'observed_complete'
      const gone = valid ? previous.ids.filter(x => !current.ids.includes(x)) : []
      const news = valid ? current.ids.filter(x => !previous.ids.includes(x)) : []
      if (!valid) incomplete += 1
      added += news.length
      resolved += gone.length
      rows.push({ rule, before, after, newIds: news, resolvedIds: gone,
        status: valid ? 'Comparable' : 'Not verified', valid })
    }
    return { rows, added, resolved, incomplete, comparable }
  }

  function tag(name, options, className) {
    const element = document.createElement(name)
    if (className) element.className = className
    if (options !== undefined) element.textContent = String(options)
    return element
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild)
  }

  function optionList(node) {
    clear(node)
    for (let i = 0; i < scans.length; i++) {
      const option = document.createElement('option')
      option.value = String(i)
      option.textContent = scans[i].label + ' — ' +
        (scans[i].account || scans[i].type) + ' (' + scans[i].completeness + ')'
      node.appendChild(option)
    }
  }

  function showMessage(message, error) {
    const el = document.getElementById('scout-history-message')
    el.textContent = message
    el.className = error ? 'text-warning small mb-2' : 'text-muted small mb-2'
  }

  function render() {
    const earlier = document.getElementById('scout-history-before')
    const later = document.getElementById('scout-history-after')
    if (!earlier || !later || !scans.length) return
    const a = scans[Number(earlier.value) || 0]
    const b = scans[Number(later.value) || 0]
    if (!a || !b) return
    const result = compare(a, b)
    document.getElementById('scout-history-summary').textContent =
      scans.length + ' versions loaded · ' + result.rows.length +
      ' rules · New observed: ' + result.added + ' · Resolved observed: ' +
      result.resolved + ' · Unverified comparisons: ' + result.incomplete
    const warning = document.getElementById('scout-history-warning')
    const signed = a.type !== 'report' || b.type !== 'report'
    warning.textContent = signed
      ? 'P4-F snapshots are shown without HMAC verification. Their data and signature are NOT authenticated in this keyless viewer.'
      : !result.comparable
        ? 'Different account/provider or missing account ID: resource-level changes cannot be verified.'
        : a.completeness !== 'observed_complete' || b.completeness !== 'observed_complete'
          ? 'At least one scan has incomplete collection; missing findings are not treated as resolved.'
          : 'Comparison uses real finding paths from local RESULTS; no AWS calls and no upload.'
    const tbody = document.getElementById('scout-history-rows')
    clear(tbody)
    for (const row of result.rows.slice(0, MAX_ROWS)) {
      const tr = document.createElement('tr')
      for (const field of [row.rule, row.before === null ? '—' : row.before,
        row.after === null ? '—' : row.after,
        row.valid ? row.newIds.length : '—',
        row.valid ? row.resolvedIds.length : '—', row.status]) {
        const td = tag('td', field)
        td.className = 'scout-history-cell'
        tr.appendChild(td)
      }
      tbody.appendChild(tr)
      if (row.valid && (row.newIds.length || row.resolvedIds.length)) {
        const details = document.createElement('tr')
        const cell = document.createElement('td')
        cell.colSpan = 6
        const text = [
          'New: ' + (row.newIds.length ? row.newIds.slice(0, 20).join(', ') : 'none'),
          'Resolved: ' + (row.resolvedIds.length ? row.resolvedIds.slice(0, 20).join(', ') : 'none')
        ]
        cell.textContent = text.join(' · ')
        cell.className = 'scout-history-evidence'
        details.appendChild(cell)
        tbody.appendChild(details)
      }
    }
    if (result.rows.length > MAX_ROWS) showMessage('Only the first ' + MAX_ROWS + ' rules are displayed.', false)
    const semanticBody = document.getElementById('scout-history-semantic')
    clear(semanticBody)
    const semantics = semantic(b)
    for (const [name, rule] of Object.entries(semantics)) {
      const row = document.createElement('tr')
      for (const value of [name, rule.count, rule.unknown, rule.status]) {
        row.appendChild(tag('td', value, 'scout-history-cell'))
      }
      semanticBody.appendChild(row)
    }
    document.getElementById('scout-history-replay-note').textContent =
      b.type === 'facts'
        ? 'P4-F2 facts preview (fixed 5-rule grammar); HMAC not authenticated. To cryptographically verify or execute installed Python predicates, use the offline replay tool.'
        : b.type === 'report' && b.provider === 'aws'
          ? 'P4-F2-compatible local enum re-evaluation on raw scan facts (five supported checks). Results are observations, not proof of security.'
          : 'P4-F2 semantic facts are only available for AWS RESULTS or P4-F2 snapshots.'
  }

  async function importFiles(files) {
    if (!files || !files.length) return
    let errors = 0
    let added = 0
    for (const file of Array.from(files)) {
      if (scans.length >= MAX_SCANS || file.size > MAX_BYTES || file.size === 0) {
        errors++; continue
      }
      try {
        const data = decode(await file.text())
        const scan = inspect(data, file.name.slice(0, 140))
        scans.push(scan)
        added++
      } catch (error) { errors++ }
    }
    const before = document.getElementById('scout-history-before')
    const after = document.getElementById('scout-history-after')
    optionList(before); optionList(after)
    before.value = String(added ? scans.length - added : 0)
    after.value = '0'
    showMessage('Loaded ' + added + ' local file(s)' + (errors ? '; rejected ' + errors + ' invalid/oversize file(s)' : '') +
      '. Files are session-only; nothing is uploaded or saved by the viewer.', errors > 0)
    render()
  }

  function initialize() {
    const button = document.getElementById('scout-history-toggle')
    const panel = document.getElementById('scout-history-panel')
    const picker = document.getElementById('scout-history-files')
    if (!button || !panel || !picker || !root.runResults) return
    try { scans.push(inspect(root.runResults, 'Current report')) }
    catch (error) { showMessage('Current report is not available for comparison.', true); return }
    optionList(document.getElementById('scout-history-before'))
    optionList(document.getElementById('scout-history-after'))
    button.addEventListener('click', function () {
      panel.hidden = !panel.hidden
      button.setAttribute('aria-expanded', String(!panel.hidden))
      if (!panel.hidden) render()
    })
    picker.addEventListener('change', function () { importFiles(picker.files); picker.value = '' })
    document.getElementById('scout-history-before').addEventListener('change', render)
    document.getElementById('scout-history-after').addEventListener('change', render)
    document.getElementById('scout-history-reset').addEventListener('click', function () {
      scans.splice(1)
      optionList(document.getElementById('scout-history-before'))
      optionList(document.getElementById('scout-history-after'))
      showMessage('Imported versions cleared from this browser session.', false)
      render()
    })
  }

  root.ScoutScanHistory = Object.freeze({ decode, inspect, semantic, observations, compare, importFiles, rules: RULES })
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize)
    else initialize()
  }
})(typeof window !== 'undefined' ? window : globalThis)
