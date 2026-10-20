/**
 * @typedef {'pass'|'warn'|'fail'|'unknown'} Status
 *
 * @typedef {object} Finding
 * @property {string} id Stable identifier, safe to match on in scripts.
 * @property {string} record Which record or area this concerns, e.g. "SPF".
 * @property {Status} status
 * @property {string} title One line, plain English, no jargon a business owner would
 *   have to look up.
 * @property {string} detail What it means in practice for mail actually arriving.
 * @property {string} [fix] The specific change to make. Omitted when status is pass.
 * @property {string[]} [evidence] Raw records the verdict was drawn from.
 */

/**
 * @param {Omit<Finding, 'evidence'> & { evidence?: string[] }} input
 * @returns {Finding}
 */
export function finding(input) {
  return input
}

/** Ordering used everywhere findings are displayed: worst first. */
export const STATUS_ORDER = { fail: 0, warn: 1, unknown: 2, pass: 3 }

/**
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status])
}
