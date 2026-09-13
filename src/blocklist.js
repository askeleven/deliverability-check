/**
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 * @typedef {import('./finding.js').Finding} Finding
 */

import { finding } from './finding.js'

/**
 * Public DNS blocklists queried over DNS.
 *
 * Caveat worth stating plainly, because it changes how the result should be read:
 * Spamhaus refuses queries that arrive via large public resolvers such as 8.8.8.8, and
 * returns either nothing or a synthetic "listed" answer. If you run this behind a public
 * resolver, treat Spamhaus results as unusable rather than as clean. Use --dns to point
 * at your own resolver for a trustworthy answer.
 */
const BLOCKLISTS = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN' },
  { zone: 'bl.spamcop.net', name: 'SpamCop' },
]

/** Spamhaus returns 127.255.255.x to signal a query refusal, not a listing. */
const SPAMHAUS_ERROR_PREFIX = '127.255.255.'

/**
 * @param {string} ip IPv4 address.
 * @returns {string} Reversed octets, as DNSBL queries require.
 */
function reverseIp(ip) {
  return ip.split('.').reverse().join('.')
}

/**
 * Checks whether the domain's own mail servers appear on public blocklists.
 *
 * This checks the servers that receive mail for the domain, which are frequently not the
 * servers that send it. It is a useful smoke test, not a verdict on your sending
 * reputation. Only a check against your actual outbound IPs can tell you that.
 *
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @returns {Promise<Finding[]>}
 */
export async function checkBlocklists(domain, resolver) {
  const mx = await resolver.mx(domain)
  if (mx.length === 0) return []

  const hosts = mx
    .sort((a, b) => a.priority - b.priority)
    .slice(0, 3)
    .map((r) => r.exchange)
    .filter(Boolean)

  const addresses = (
    await Promise.all(
      hosts.map(async (host) => (await resolver.a(host)).slice(0, 1).map((ip) => ({ host, ip }))),
    )
  ).flat()

  if (addresses.length === 0) {
    return [
      finding({
        id: 'blocklist.unresolvable',
        record: 'Blocklists',
        status: 'unknown',
        title: 'Could not resolve mail server addresses to check',
        detail: 'The MX hostnames did not resolve to IPv4 addresses, so no lookup was made.',
      }),
    ]
  }

  /** @type {{ list: string, host: string, ip: string }[]} */
  const listings = []
  let refused = false

  await Promise.all(
    addresses.flatMap(({ host, ip }) =>
      BLOCKLISTS.map(async ({ zone, name }) => {
        const answers = await resolver.a(`${reverseIp(ip)}.${zone}`)
        if (answers.length === 0) return
        if (answers.some((a) => a.startsWith(SPAMHAUS_ERROR_PREFIX))) {
          refused = true
          return
        }
        listings.push({ list: name, host, ip })
      }),
    ),
  )

  if (refused) {
    return [
      finding({
        id: 'blocklist.query-refused',
        record: 'Blocklists',
        status: 'unknown',
        title: 'Blocklist provider refused the query',
        detail:
          'Spamhaus blocks lookups coming from large public DNS resolvers, and answered ' +
          'with a refusal code rather than a real result. This says nothing about ' +
          'whether your servers are listed.',
        fix: 'Re-run with --dns pointing at your own resolver for a usable answer.',
      }),
    ]
  }

  if (listings.length === 0) {
    return [
      finding({
        id: 'blocklist.clear',
        record: 'Blocklists',
        status: 'pass',
        title: `Mail servers not listed on ${BLOCKLISTS.length} public blocklists`,
        detail:
          'Checked the servers that receive mail for this domain. Note that these are ' +
          'often not the servers that send your outbound campaigns, so this is a smoke ' +
          'test rather than a verdict on your sending reputation.',
        evidence: addresses.map(({ host, ip }) => `${host} (${ip})`),
      }),
    ]
  }

  return listings.map(({ list, host, ip }) =>
    finding({
      id: `blocklist.listed.${list.toLowerCase().replace(/\W+/g, '-')}`,
      record: 'Blocklists',
      status: 'fail',
      title: `${host} is listed on ${list}`,
      detail:
        'Receivers consulting this list will refuse or spam-folder mail from this ' +
        'address. Listings usually follow either a compromised account or a bad list ' +
        'purchase.',
      fix: `Find the cause first, then use the ${list} removal form. Delisting without ` +
        'fixing the source relists you within days.',
      evidence: [`${host} (${ip})`],
    }),
  )
}
