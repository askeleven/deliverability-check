/**
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 * @typedef {import('./finding.js').Finding} Finding
 */

import { finding } from './finding.js'

/**
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @returns {Promise<Finding[]>}
 */
export async function checkMx(domain, resolver) {
  const records = await resolver.mx(domain)

  if (records.length === 0) {
    return [
      finding({
        id: 'mx.missing',
        record: 'MX',
        status: 'fail',
        title: 'No MX records',
        detail:
          `Nothing can deliver mail to ${domain}. Replies to anything you send will ` +
          'bounce, which most receivers read as a strong spam signal in itself.',
        fix: 'Point MX at your mail provider.',
      }),
    ]
  }

  // RFC 7505: a single "." exchange is an explicit declaration that the domain accepts
  // no mail. Deliberate on a send-only subdomain, a serious problem on a main domain.
  if (records.length === 1 && records[0].exchange === '') {
    return [
      finding({
        id: 'mx.null',
        record: 'MX',
        status: 'warn',
        title: 'Domain publishes a null MX (accepts no mail)',
        detail:
          'This domain has explicitly declared that it receives no email. That is ' +
          'correct for a send-only subdomain and wrong for a domain a customer might ' +
          'reply to.',
        fix: 'If people should be able to reply to you here, publish real MX records.',
      }),
    ]
  }

  return [
    finding({
      id: 'mx.ok',
      record: 'MX',
      status: 'pass',
      title: `${records.length} MX record${records.length === 1 ? '' : 's'} published`,
      detail: 'Mail sent to this domain has somewhere to go.',
      evidence: records
        .sort((a, b) => a.priority - b.priority)
        .map((r) => `${r.priority} ${r.exchange}`),
    }),
  ]
}

/**
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @returns {Promise<Finding[]>}
 */
export async function checkBimi(domain, resolver) {
  const txt = await resolver.txt(`default._bimi.${domain}`)
  const record = txt.find((r) => r.trim().toLowerCase().startsWith('v=bimi1'))

  if (!record) {
    return [
      finding({
        id: 'bimi.missing',
        record: 'BIMI',
        status: 'unknown',
        title: 'No BIMI record',
        detail:
          'BIMI shows your logo next to your messages in supporting inboxes. It is ' +
          'optional, it requires DMARC at quarantine or reject first, and displaying ' +
          'the logo in Gmail additionally requires a paid Verified Mark Certificate.',
        fix:
          'Worth doing only once DMARC is enforcing. Not a deliverability problem on ' +
          'its own.',
      }),
    ]
  }

  const hasLogo = /(^|;)\s*l=/i.test(record)
  const hasCert = /(^|;)\s*a=/i.test(record)

  return [
    finding({
      id: 'bimi.found',
      record: 'BIMI',
      status: hasLogo ? 'pass' : 'warn',
      title: hasLogo
        ? `BIMI published${hasCert ? ' with a mark certificate' : ' without a mark certificate'}`
        : 'BIMI record published but names no logo',
      detail: hasLogo
        ? hasCert
          ? 'Your logo can display in inboxes that support BIMI, including Gmail.'
          : 'Some inboxes will show your logo. Gmail additionally requires a Verified ' +
            'Mark Certificate referenced in the a= tag.'
        : 'The l= tag is missing, so there is no logo to show and the record has no ' +
          'effect.',
      ...(hasLogo ? {} : { fix: 'Add l= pointing at a square SVG Tiny PS logo over HTTPS.' }),
      evidence: [record],
    }),
  ]
}
