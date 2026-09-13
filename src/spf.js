/**
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 * @typedef {import('./finding.js').Finding} Finding
 */

import { finding } from './finding.js'

/** Mechanisms and modifiers that cost a DNS lookup. RFC 7208 caps the total at 10. */
const LOOKUP_MECHANISMS = ['include', 'a', 'mx', 'ptr', 'exists', 'redirect']
const MAX_LOOKUPS = 10

/**
 * @param {string} record
 * @returns {number}
 */
function countLookups(record) {
  return record
    .split(/\s+/)
    .filter((term) => {
      const bare = term.replace(/^[+\-~?]/, '').split(/[:=]/)[0].toLowerCase()
      return LOOKUP_MECHANISMS.includes(bare)
    }).length
}

/**
 * @param {string} record
 * @returns {'-'|'~'|'?'|'+'|null}
 */
function allQualifier(record) {
  const match = record.match(/([+\-~?]?)all\b/i)
  if (!match) return null
  return /** @type {'-'|'~'|'?'|'+'} */ (match[1] || '+')
}

/**
 * Checks the SPF record for a domain.
 *
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @returns {Promise<Finding[]>}
 */
export async function checkSpf(domain, resolver) {
  const txt = await resolver.txt(domain)
  const records = txt.filter((r) => r.trim().toLowerCase().startsWith('v=spf1'))

  if (records.length === 0) {
    return [
      finding({
        id: 'spf.missing',
        record: 'SPF',
        status: 'fail',
        title: 'No SPF record',
        detail:
          'Nothing tells receiving mail servers which servers are allowed to send as ' +
          `${domain}. Anyone can forge your address, and strict receivers will treat ` +
          'your real mail as suspicious.',
        fix:
          'Publish a TXT record on the root domain listing the services that send for ' +
          'you, ending in -all. Example: "v=spf1 include:_spf.google.com -all".',
      }),
    ]
  }

  if (records.length > 1) {
    // Receivers must treat multiple SPF records as a permanent error, so this is
    // strictly worse than having none.
    return [
      finding({
        id: 'spf.multiple',
        record: 'SPF',
        status: 'fail',
        title: `${records.length} SPF records published`,
        detail:
          'A domain may publish exactly one SPF record. Receivers treat more than one ' +
          'as a permanent error and ignore all of them, so you currently have no ' +
          'working SPF at all.',
        fix: 'Merge them into a single TXT record by combining their include: terms.',
        evidence: records,
      }),
    ]
  }

  const record = records[0]
  /** @type {Finding[]} */
  const findings = []

  const lookups = countLookups(record)
  if (lookups > MAX_LOOKUPS) {
    findings.push(
      finding({
        id: 'spf.lookup-limit',
        record: 'SPF',
        status: 'fail',
        title: `SPF needs ${lookups} DNS lookups, limit is ${MAX_LOOKUPS}`,
        detail:
          'Receivers stop evaluating past ten lookups and return a permanent error. ' +
          'Mail that should pass will fail, usually only for some recipients, which ' +
          'makes it look intermittent.',
        fix:
          'Remove include: terms for services you no longer use, or flatten the ' +
          'heaviest include into explicit ip4:/ip6: ranges.',
        evidence: [record],
      }),
    )
  } else if (lookups === MAX_LOOKUPS) {
    findings.push(
      finding({
        id: 'spf.lookup-limit-edge',
        record: 'SPF',
        status: 'warn',
        title: `SPF uses all ${MAX_LOOKUPS} permitted DNS lookups`,
        detail:
          'You are at the limit. Adding one more sending service, or a provider ' +
          'expanding their own record, will silently break SPF for you.',
        fix: 'Retire an unused include: term now to leave headroom.',
        evidence: [record],
      }),
    )
  }

  const qualifier = allQualifier(record)
  if (qualifier === null) {
    findings.push(
      finding({
        id: 'spf.no-all',
        record: 'SPF',
        status: 'warn',
        title: 'SPF record has no "all" mechanism',
        detail:
          'Without a closing all term, receivers get no instruction about mail from ' +
          'servers you did not list, and default to neutral.',
        fix: 'End the record with -all once you are confident the list is complete.',
        evidence: [record],
      }),
    )
  } else if (qualifier === '+') {
    findings.push(
      finding({
        id: 'spf.pass-all',
        record: 'SPF',
        status: 'fail',
        title: 'SPF ends in +all, which authorises the entire internet',
        detail:
          'This tells receivers that any server anywhere may send as your domain. It ' +
          'is worse than publishing no SPF record.',
        fix: 'Change +all to -all.',
        evidence: [record],
      }),
    )
  } else if (qualifier === '?') {
    findings.push(
      finding({
        id: 'spf.neutral-all',
        record: 'SPF',
        status: 'warn',
        title: 'SPF ends in ?all (neutral)',
        detail: 'Neutral gives receivers no signal about unlisted servers.',
        fix: 'Move to ~all, then to -all once you have confirmed every sender is listed.',
        evidence: [record],
      }),
    )
  } else if (qualifier === '~') {
    findings.push(
      finding({
        id: 'spf.soft-all',
        record: 'SPF',
        status: 'warn',
        title: 'SPF ends in ~all (softfail)',
        detail:
          'Softfail is the right setting while you are still finding senders, but it ' +
          'asks receivers to accept forged mail and merely note it.',
        fix:
          'Once DMARC reports show no legitimate sources failing, tighten ~all to -all.',
        evidence: [record],
      }),
    )
  }

  if (/(^|\s)[+\-~?]?ptr\b/i.test(record)) {
    findings.push(
      finding({
        id: 'spf.ptr',
        record: 'SPF',
        status: 'warn',
        title: 'SPF uses the deprecated ptr mechanism',
        detail:
          'RFC 7208 tells receivers not to use ptr and some ignore records containing ' +
          'it. It is slow and unreliable.',
        fix: 'Replace ptr with explicit ip4:/ip6: ranges or an include: for the provider.',
        evidence: [record],
      }),
    )
  }

  if (findings.length === 0) {
    findings.push(
      finding({
        id: 'spf.ok',
        record: 'SPF',
        status: 'pass',
        title: `SPF published and strict (${lookups}/${MAX_LOOKUPS} lookups)`,
        detail: 'Receivers know which servers may send as you, and to reject the rest.',
        evidence: [record],
      }),
    )
  }

  return findings
}
