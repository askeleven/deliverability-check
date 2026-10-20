/**
 * @typedef {import('./index.js').CheckResult} CheckResult
 * @typedef {import('./finding.js').Finding} Finding
 */

import { CHECKLIST } from './compliance.js'

const COLOURS = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
}

const MARKS = {
  fail: { glyph: 'FAIL', colour: COLOURS.red },
  warn: { glyph: 'WARN', colour: COLOURS.yellow },
  unknown: { glyph: '????', colour: COLOURS.blue },
  pass: { glyph: 'PASS', colour: COLOURS.green },
}

/**
 * @param {boolean} enabled
 * @returns {(code: string, text: string) => string}
 */
function painter(enabled) {
  return (code, text) => (enabled ? `${code}${text}${COLOURS.reset}` : text)
}

/**
 * Wraps text to a width, indenting continuation lines.
 *
 * @param {string} text
 * @param {number} width
 * @param {string} indent
 * @returns {string}
 */
function wrap(text, width, indent) {
  const words = text.split(/\s+/)
  /** @type {string[]} */
  const lines = []
  let line = ''
  for (const word of words) {
    if (line.length + word.length + 1 > width) {
      lines.push(line)
      line = word
    } else {
      line = line ? `${line} ${word}` : word
    }
  }
  if (line) lines.push(line)
  return lines.map((l) => indent + l).join('\n')
}

/**
 * @param {CheckResult} result
 * @param {{ colour?: boolean, width?: number, showPasses?: boolean }} [options]
 * @returns {string}
 */
export function formatText(result, options = {}) {
  const { colour = true, width = 76, showPasses = true } = options
  const paint = painter(colour)
  const lines = []

  lines.push('')
  lines.push(paint(COLOURS.bold, `Deliverability check: ${result.domain}`))
  lines.push('')

  const visible = showPasses
    ? result.findings
    : result.findings.filter((f) => f.status !== 'pass')

  for (const f of visible) {
    const mark = MARKS[f.status]
    lines.push(`${paint(mark.colour, mark.glyph)}  ${paint(COLOURS.bold, f.title)}`)
    lines.push(wrap(f.detail, width - 6, '      '))
    if (f.fix) {
      lines.push(wrap(`Fix: ${f.fix}`, width - 6, '      '))
    }
    if (f.evidence?.length) {
      for (const line of f.evidence) {
        lines.push(paint(COLOURS.dim, wrap(line, width - 6, '      ')))
      }
    }
    lines.push('')
  }

  const { fail, warn, unknown, pass } = result.summary
  lines.push(
    paint(
      COLOURS.dim,
      `${fail} failing, ${warn} to improve, ${unknown} undetermined, ${pass} passing.`,
    ),
  )
  lines.push('')

  return lines.join('\n')
}

/**
 * @param {{ colour?: boolean, width?: number }} [options]
 * @returns {string}
 */
export function formatChecklist(options = {}) {
  const { colour = true, width = 76 } = options
  const paint = painter(colour)
  const lines = ['']

  lines.push(paint(COLOURS.bold, 'What DNS cannot check'))
  lines.push(
    wrap(
      'Records are only half of it. These are the obligations outreach programmes ' +
        'actually breach, and no external tool can verify them for you. Not legal advice.',
      width,
      '',
    ),
  )
  lines.push('')

  let regime = ''
  for (const item of CHECKLIST) {
    if (item.regime !== regime) {
      regime = item.regime
      lines.push(paint(COLOURS.bold, regime))
    }
    lines.push(`  [ ] ${item.requirement}`)
    lines.push(paint(COLOURS.dim, wrap(item.detail, width - 6, '      ')))
  }
  lines.push('')

  return lines.join('\n')
}
