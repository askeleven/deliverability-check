/**
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 * @typedef {import('./finding.js').Finding} Finding
 */

import { finding } from './finding.js'

/**
 * @param {string} record
 * @returns {Record<string, string>}
 */
function parseTags(record) {
  /** @type {Record<string, string>} */
  const tags = {}
  for (const part of record.split(';')) {
    const [key, ...rest] = part.split('=')
    if (!key || rest.length === 0) continue
    tags[key.trim().toLowerCase()] = rest.join('=').trim()
  }
  return tags
}

/**
 * Checks the DMARC policy for a domain.
 *
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @returns {Promise<Finding[]>}
 */
export async function checkDmarc(domain, resolver) {
  const txt = await resolver.txt(`_dmarc.${domain}`)
  const records = txt.filter((r) => r.trim().toLowerCase().startsWith('v=dmarc1'))

  if (records.length === 0) {
    return [
      finding({
        id: 'dmarc.missing',
        record: 'DMARC',
        status: 'fail',
        title: 'No DMARC record',
        detail:
          'Nobody can forge your domain and be stopped, and you receive no reports, so ' +
          'you have no way of knowing who is sending as you. Google and Yahoo require ' +
          'DMARC to accept bulk mail, so this also caps how much you can send.',
        fix:
          'Publish a TXT record at _dmarc.' +
          domain +
          ' starting at monitoring only: ' +
          '"v=DMARC1; p=none; rua=mailto:dmarc@' +
          domain +
          '". Read the reports for a month, then tighten to quarantine and reject.',
      }),
    ]
  }

  if (records.length > 1) {
    return [
      finding({
        id: 'dmarc.multiple',
        record: 'DMARC',
        status: 'fail',
        title: `${records.length} DMARC records published`,
        detail:
          'A domain may publish exactly one DMARC record. Receivers discard the whole ' +
          'set when there is more than one, leaving you with no policy.',
        fix: 'Delete all but one.',
        evidence: records,
      }),
    ]
  }

  const record = records[0]
  const tags = parseTags(record)
  /** @type {Finding[]} */
  const findings = []

  const policy = (tags.p ?? '').toLowerCase()
  if (policy === 'reject') {
    findings.push(
      finding({
        id: 'dmarc.policy-reject',
        record: 'DMARC',
        status: 'pass',
        title: 'DMARC policy is reject',
        detail: 'Forged mail claiming to be from your domain is refused outright.',
        evidence: [record],
      }),
    )
  } else if (policy === 'quarantine') {
    findings.push(
      finding({
        id: 'dmarc.policy-quarantine',
        record: 'DMARC',
        status: 'warn',
        title: 'DMARC policy is quarantine, not reject',
        detail:
          'Forged mail goes to spam rather than being refused. This is a reasonable ' +
          'staging post but it is not the destination.',
        fix: 'Move to p=reject once reports show no legitimate senders failing.',
        evidence: [record],
      }),
    )
  } else if (policy === 'none') {
    findings.push(
      finding({
        id: 'dmarc.policy-none',
        record: 'DMARC',
        status: 'warn',
        title: 'DMARC policy is none, which enforces nothing',
        detail:
          'You are collecting reports but anyone can still successfully forge your ' +
          'domain. p=none is a monitoring mode, and a large number of domains are ' +
          'parked here permanently by accident.',
        fix:
          'Read a month of reports, confirm every legitimate sender passes, then move ' +
          'to p=quarantine and on to p=reject.',
        evidence: [record],
      }),
    )
  } else {
    findings.push(
      finding({
        id: 'dmarc.policy-invalid',
        record: 'DMARC',
        status: 'fail',
        title: 'DMARC record has no valid policy tag',
        detail:
          'The p= tag is missing or unrecognised, so the record does nothing. Receivers ' +
          'treat it as absent.',
        fix: 'Add p=none, p=quarantine, or p=reject.',
        evidence: [record],
      }),
    )
  }

  if (!tags.rua) {
    findings.push(
      finding({
        id: 'dmarc.no-rua',
        record: 'DMARC',
        status: 'warn',
        title: 'DMARC sends no aggregate reports',
        detail:
          'Without a rua address you get no data on who is sending as your domain, ' +
          'which means you can never safely tighten the policy. It also means a sending ' +
          'problem is invisible to you until a customer mentions it.',
        fix: `Add rua=mailto:dmarc@${domain} and make sure somebody or something reads it.`,
        evidence: [record],
      }),
    )
  }

  const pct = tags.pct ? Number(tags.pct) : 100
  if (Number.isFinite(pct) && pct < 100) {
    findings.push(
      finding({
        id: 'dmarc.partial-pct',
        record: 'DMARC',
        status: 'warn',
        title: `DMARC policy applies to only ${pct}% of mail`,
        detail:
          'The remainder is treated as p=none. Partial rollout is a deliberate ramp ' +
          'technique, but it is frequently left in place and forgotten.',
        fix: 'Remove the pct tag, or raise it to 100, once the ramp is finished.',
        evidence: [record],
      }),
    )
  }

  return findings
}
