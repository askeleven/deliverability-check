import { createResolver } from './resolver.js'
import { sortFindings } from './finding.js'
import { checkSpf } from './spf.js'
import { checkDmarc } from './dmarc.js'
import { checkDkim } from './dkim.js'
import { checkMx, checkBimi } from './mx.js'
import { checkBlocklists } from './blocklist.js'

export { createResolver, createFixtureResolver } from './resolver.js'
export { complianceChecklist, CHECKLIST } from './compliance.js'
export { COMMON_SELECTORS } from './dkim.js'
export { sortFindings, STATUS_ORDER } from './finding.js'

/**
 * @typedef {import('./finding.js').Finding} Finding
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 *
 * @typedef {object} CheckResult
 * @property {string} domain
 * @property {string} checkedAt ISO 8601.
 * @property {Finding[]} findings Worst first.
 * @property {{ fail: number, warn: number, unknown: number, pass: number }} summary
 */

/**
 * Runs every DNS-visible deliverability check for a domain.
 *
 * Deliberately produces no overall score. A score invites a business to optimise the
 * number, and the number would be arbitrary: a missing DMARC record and a 1024-bit DKIM
 * key are not commensurable. Findings carry their own severity and their own fix.
 *
 * @param {string} domain
 * @param {{ resolver?: DnsResolver, selectors?: string[], skipBlocklists?: boolean }} [options]
 * @returns {Promise<CheckResult>}
 */
export async function check(domain, options = {}) {
  const normalised = normaliseDomain(domain)
  const resolver = options.resolver ?? createResolver()

  const groups = await Promise.all([
    checkSpf(normalised, resolver),
    checkDkim(normalised, resolver, { selectors: options.selectors }),
    checkDmarc(normalised, resolver),
    checkMx(normalised, resolver),
    checkBimi(normalised, resolver),
    options.skipBlocklists ? Promise.resolve([]) : checkBlocklists(normalised, resolver),
  ])

  const findings = sortFindings(groups.flat())

  return {
    domain: normalised,
    checkedAt: new Date().toISOString(),
    findings,
    summary: {
      fail: findings.filter((f) => f.status === 'fail').length,
      warn: findings.filter((f) => f.status === 'warn').length,
      unknown: findings.filter((f) => f.status === 'unknown').length,
      pass: findings.filter((f) => f.status === 'pass').length,
    },
  }
}

/**
 * Accepts the things people actually paste: a bare domain, a URL, or an email address.
 *
 * @param {string} input
 * @returns {string}
 */
export function normaliseDomain(input) {
  let value = String(input ?? '').trim().toLowerCase()
  if (value.includes('@')) value = value.slice(value.lastIndexOf('@') + 1)
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  value = value.split('/')[0]
  value = value.split(':')[0]
  value = value.replace(/\.$/, '')

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(value)) {
    throw new Error(`Not a valid domain: ${input}`)
  }
  return value
}
