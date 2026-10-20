/**
 * @typedef {import('./resolver.js').DnsResolver} DnsResolver
 * @typedef {import('./finding.js').Finding} Finding
 */

import { finding } from './finding.js'

/**
 * DKIM selectors are not discoverable from DNS: you can only look one up if you already
 * know its name. The best any external tool can do is probe the selectors that the
 * common providers use. A miss here means "not found", never "not configured", and the
 * output says so.
 */
export const COMMON_SELECTORS = [
  { selector: 'google', provider: 'Google Workspace' },
  { selector: 'selector1', provider: 'Microsoft 365' },
  { selector: 'selector2', provider: 'Microsoft 365' },
  { selector: 'k1', provider: 'Mailchimp / Mandrill' },
  { selector: 'k2', provider: 'Mailchimp / Mandrill' },
  { selector: 's1', provider: 'SendGrid / Amazon SES' },
  { selector: 's2', provider: 'SendGrid / Amazon SES' },
  { selector: 'pm', provider: 'Postmark' },
  { selector: 'mte1', provider: 'Mailgun' },
  { selector: 'mailo', provider: 'Mailgun' },
  { selector: 'hs1-', provider: 'HubSpot' },
  { selector: 'zoho', provider: 'Zoho Mail' },
  { selector: 'fd', provider: 'Freshdesk / Front' },
  { selector: 'dkim', provider: 'generic' },
  { selector: 'default', provider: 'generic' },
  { selector: 'mail', provider: 'generic' },
  { selector: 'smtp', provider: 'generic' },
]

/**
 * Reads the key size out of a DKIM record.
 *
 * The public key is a base64 DER SubjectPublicKeyInfo. Rather than guess from the
 * length of the whole TXT record, decode it and measure: RSA-1024 SPKI is 162 bytes,
 * RSA-2048 is 294, RSA-4096 is 550. Ed25519 keys are 44 bytes and are not weak.
 *
 * @param {string} record
 * @returns {{ algorithm: string, weak: boolean, bits: number | null }}
 */
export function keyStrength(record) {
  // k= defaults to rsa when absent (RFC 6376 s3.6.1).
  const algorithm = (record.match(/(^|;)\s*k=\s*([a-z0-9]+)/i)?.[2] ?? 'rsa').toLowerCase()
  const key = record.match(/(^|;)\s*p=\s*([A-Za-z0-9+/=\s]*)/)?.[2]?.replace(/\s/g, '') ?? ''

  if (algorithm === 'ed25519') return { algorithm, weak: false, bits: 256 }
  if (!key) return { algorithm, weak: false, bits: null }

  const der = Buffer.from(key, 'base64')
  if (der.length === 0) return { algorithm, weak: false, bits: null }

  // SPKI overhead for an RSA key is 38 bytes: sequence + algorithm identifier +
  // bit string + inner sequence + the leading zero byte on the modulus integer.
  const bits = Math.round(((der.length - 38) * 8) / 256) * 256
  return { algorithm, weak: bits > 0 && bits < 2048, bits: bits > 0 ? bits : null }
}

/**
 * @param {string} domain
 * @param {DnsResolver} resolver
 * @param {{ selectors?: string[] }} [options] Extra selectors to probe, for domains
 *   using a provider or convention not in the common list.
 * @returns {Promise<Finding[]>}
 */
export async function checkDkim(domain, resolver, options = {}) {
  const candidates = [
    ...COMMON_SELECTORS,
    ...(options.selectors ?? []).map((selector) => ({ selector, provider: 'user supplied' })),
  ]

  const probes = await Promise.all(
    candidates.map(async ({ selector, provider }) => {
      const txt = await resolver.txt(`${selector}._domainkey.${domain}`)
      const key = txt.find((r) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(r))
      return key ? { selector, provider, record: key } : null
    }),
  )

  const found = probes.filter((p) => p !== null)

  if (found.length === 0) {
    return [
      finding({
        id: 'dkim.none-found',
        record: 'DKIM',
        status: 'unknown',
        title: 'No DKIM key found on the selectors we probed',
        detail:
          'DKIM selectors cannot be discovered from DNS, so this is not proof that DKIM ' +
          `is missing. We tried ${candidates.length} selectors used by the common ` +
          'providers and none answered. If you know your selector, re-run with ' +
          '--selector to check it directly.',
        fix:
          'Confirm in your mail provider that DKIM signing is switched on and that the ' +
          'published key matches. Without DKIM, DMARC can only pass via SPF, which ' +
          'breaks whenever a message is forwarded.',
      }),
    ]
  }

  /** @type {Finding[]} */
  const findings = []

  for (const { selector, provider, record } of found) {
    const revoked = /(^|;)\s*p=\s*(;|$)/.test(record)
    if (revoked) {
      findings.push(
        finding({
          id: `dkim.revoked.${selector}`,
          record: 'DKIM',
          status: 'warn',
          title: `DKIM selector "${selector}" is published but revoked`,
          detail:
            'The record exists with an empty public key, which explicitly tells ' +
            'receivers that any signature from this selector should be treated as ' +
            'invalid. This is normal for a retired selector and a problem for a live one.',
          fix: `If ${provider} is still sending for you, republish the key.`,
          evidence: [record],
        }),
      )
      continue
    }

    const { weak, bits } = keyStrength(record)
    findings.push(
      finding({
        id: `dkim.found.${selector}`,
        record: 'DKIM',
        status: weak ? 'warn' : 'pass',
        title: weak
          ? `DKIM selector "${selector}" uses a ${bits}-bit key (${provider})`
          : `DKIM key published on selector "${selector}"${bits ? ` (${bits}-bit, ${provider})` : ` (${provider})`}`,
        detail: weak
          ? 'Keys below 2048 bits are still accepted by most receivers but are being ' +
            'phased out, and some already treat them as unsigned.'
          : 'Messages signed with this key can be verified by receivers, and survive ' +
            'forwarding in a way SPF does not.',
        ...(weak ? { fix: 'Rotate to a 2048-bit key in your provider settings.' } : {}),
        evidence: [record],
      }),
    )
  }

  return findings
}
