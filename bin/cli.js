#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { check, normaliseDomain } from '../src/index.js'
import { createResolver } from '../src/resolver.js'
import { formatText, formatChecklist } from '../src/report.js'
import { complianceChecklist } from '../src/compliance.js'

const USAGE = `
deliverability-check <domain>

  Checks whether a domain is set up so its email actually arrives, and prints the
  specific fix for anything that is not. No score, no signup, no data kept.

Options
  --selector <name>   Extra DKIM selector to probe. Repeatable.
  --dns <ip>          Resolver to query. Repeatable. Use your own for trustworthy
                      blocklist results; public resolvers are refused by Spamhaus.
  --json              Machine-readable output.
  --checklist         Also print the compliance obligations DNS cannot check.
  --quiet             Hide passing checks.
  --no-colour         Plain text.
  --help              This.

Exit codes
  0  no failures
  1  at least one failing check
  2  could not run (bad domain, bad arguments)

Examples
  npx @askeleven/deliverability-check example.com
  npx @askeleven/deliverability-check example.com --selector mysel --json
`

/**
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
async function main(argv) {
  let parsed
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        selector: { type: 'string', multiple: true },
        dns: { type: 'string', multiple: true },
        json: { type: 'boolean', default: false },
        checklist: { type: 'boolean', default: false },
        quiet: { type: 'boolean', default: false },
        // parseArgs has no --no-x negation, so both spellings are declared explicitly.
        'no-colour': { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
    })
  } catch (error) {
    process.stderr.write(`${error.message}\n${USAGE}`)
    return 2
  }

  const { values, positionals } = parsed

  if (values.help) {
    process.stdout.write(USAGE)
    return 0
  }

  const domain = positionals[0]
  if (!domain) {
    if (values.checklist) {
      process.stdout.write(
        values.json
          ? `${JSON.stringify(complianceChecklist(), null, 2)}\n`
          : formatChecklist({ colour: useColour(values) }),
      )
      return 0
    }
    process.stderr.write(USAGE)
    return 2
  }

  let result
  try {
    result = await check(normaliseDomain(domain), {
      resolver: values.dns?.length ? createResolver({ servers: values.dns }) : undefined,
      selectors: values.selector,
    })
  } catch (error) {
    process.stderr.write(`${error.message}\n`)
    return 2
  }

  if (values.json) {
    const payload = values.checklist
      ? { ...result, checklist: complianceChecklist() }
      : result
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`)
  } else {
    process.stdout.write(
      formatText(result, { colour: useColour(values), showPasses: !values.quiet }),
    )
    if (values.checklist) {
      process.stdout.write(formatChecklist({ colour: useColour(values) }))
    }
  }

  return result.summary.fail > 0 ? 1 : 0
}

/**
 * Honours --no-colour, --no-color, NO_COLOR, and a non-TTY stdout.
 *
 * @param {Record<string, unknown>} values
 * @returns {boolean}
 */
function useColour(values) {
  if (values['no-colour'] || values['no-color']) return false
  if (process.env.NO_COLOR) return false
  return process.stdout.isTTY === true
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
  },
  (error) => {
    process.stderr.write(`${error?.stack ?? error}\n`)
    process.exitCode = 2
  },
)
