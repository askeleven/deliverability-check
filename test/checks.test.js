import test from 'node:test'
import assert from 'node:assert/strict'

import { check, normaliseDomain } from '../src/index.js'
import { createFixtureResolver } from '../src/resolver.js'
import { checkSpf } from '../src/spf.js'
import { checkDmarc } from '../src/dmarc.js'
import { checkDkim, keyStrength } from '../src/dkim.js'
import { checkMx } from '../src/mx.js'
import { formatText } from '../src/report.js'

/**
 * @param {import('../src/finding.js').Finding[]} findings
 * @returns {string[]}
 */
const ids = (findings) => findings.map((f) => f.id)

test('normaliseDomain accepts what people actually paste', () => {
  assert.equal(normaliseDomain('example.com'), 'example.com')
  assert.equal(normaliseDomain('  EXAMPLE.com '), 'example.com')
  assert.equal(normaliseDomain('https://example.com/pricing?a=1'), 'example.com')
  assert.equal(normaliseDomain('someone@mail.example.com'), 'mail.example.com')
  assert.equal(normaliseDomain('example.com:443'), 'example.com')
  assert.equal(normaliseDomain('example.com.'), 'example.com')

  assert.throws(() => normaliseDomain('localhost'))
  assert.throws(() => normaliseDomain(''))
  assert.throws(() => normaliseDomain('not a domain'))
})

test('SPF: missing record fails', async () => {
  const resolver = createFixtureResolver({ txt: { 'example.com': [] } })
  assert.deepEqual(ids(await checkSpf('example.com', resolver)), ['spf.missing'])
})

test('SPF: two records are worse than none', async () => {
  const resolver = createFixtureResolver({
    txt: { 'example.com': ['v=spf1 include:a.com -all', 'v=spf1 include:b.com -all'] },
  })
  const findings = await checkSpf('example.com', resolver)
  assert.deepEqual(ids(findings), ['spf.multiple'])
  assert.equal(findings[0].status, 'fail')
})

test('SPF: strict record with headroom passes', async () => {
  const resolver = createFixtureResolver({
    txt: { 'example.com': ['v=spf1 include:_spf.google.com -all'] },
  })
  const findings = await checkSpf('example.com', resolver)
  assert.deepEqual(ids(findings), ['spf.ok'])
  assert.match(findings[0].title, /1\/10 lookups/)
})

test('SPF: counts every lookup mechanism and flags going over ten', async () => {
  const record =
    'v=spf1 a mx include:one.com include:two.com include:three.com include:four.com ' +
    'include:five.com include:six.com include:seven.com include:eight.com ' +
    'include:nine.com -all'
  const resolver = createFixtureResolver({ txt: { 'example.com': [record] } })
  const findings = await checkSpf('example.com', resolver)
  assert.ok(ids(findings).includes('spf.lookup-limit'))
  assert.match(findings[0].title, /needs 11 DNS lookups/)
})

test('SPF: exactly ten lookups warns rather than fails', async () => {
  const record =
    'v=spf1 a mx include:one.com include:two.com include:three.com include:four.com ' +
    'include:five.com include:six.com include:seven.com include:eight.com -all'
  const resolver = createFixtureResolver({ txt: { 'example.com': [record] } })
  const findings = await checkSpf('example.com', resolver)
  assert.deepEqual(ids(findings), ['spf.lookup-limit-edge'])
  assert.equal(findings[0].status, 'warn')
})

test('SPF: +all is a failure, ~all and ?all are warnings', async () => {
  /** @param {string} record */
  const run = (record) =>
    checkSpf('example.com', createFixtureResolver({ txt: { 'example.com': [record] } }))

  assert.deepEqual(ids(await run('v=spf1 include:a.com +all')), ['spf.pass-all'])
  assert.deepEqual(ids(await run('v=spf1 include:a.com ~all')), ['spf.soft-all'])
  assert.deepEqual(ids(await run('v=spf1 include:a.com ?all')), ['spf.neutral-all'])
  assert.deepEqual(ids(await run('v=spf1 include:a.com')), ['spf.no-all'])
})

test('SPF: bare "all" is treated as +all', async () => {
  const resolver = createFixtureResolver({ txt: { 'example.com': ['v=spf1 mx all'] } })
  assert.deepEqual(ids(await checkSpf('example.com', resolver)), ['spf.pass-all'])
})

test('SPF: deprecated ptr mechanism is flagged alongside other findings', async () => {
  const resolver = createFixtureResolver({
    txt: { 'example.com': ['v=spf1 ptr ~all'] },
  })
  const found = ids(await checkSpf('example.com', resolver))
  assert.ok(found.includes('spf.ptr'))
  assert.ok(found.includes('spf.soft-all'))
})

test('DMARC: missing record fails and names the subdomain to create', async () => {
  const resolver = createFixtureResolver({})
  const findings = await checkDmarc('example.com', resolver)
  assert.deepEqual(ids(findings), ['dmarc.missing'])
  assert.match(findings[0].fix, /_dmarc\.example\.com/)
})

test('DMARC: p=reject with reporting is a clean pass', async () => {
  const resolver = createFixtureResolver({
    txt: { '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'] },
  })
  const findings = await checkDmarc('example.com', resolver)
  assert.deepEqual(ids(findings), ['dmarc.policy-reject'])
})

test('DMARC: p=none without rua produces both findings', async () => {
  const resolver = createFixtureResolver({
    txt: { '_dmarc.example.com': ['v=DMARC1; p=none'] },
  })
  const found = ids(await checkDmarc('example.com', resolver))
  assert.deepEqual(found, ['dmarc.policy-none', 'dmarc.no-rua'])
})

test('DMARC: partial pct is flagged', async () => {
  const resolver = createFixtureResolver({
    txt: { '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com; pct=20'] },
  })
  const found = ids(await checkDmarc('example.com', resolver))
  assert.ok(found.includes('dmarc.partial-pct'))
})

test('DMARC: record without a policy tag fails', async () => {
  const resolver = createFixtureResolver({
    txt: { '_dmarc.example.com': ['v=DMARC1; rua=mailto:d@example.com'] },
  })
  const found = ids(await checkDmarc('example.com', resolver))
  assert.ok(found.includes('dmarc.policy-invalid'))
})

test('keyStrength decodes the real key size rather than guessing from record length', () => {
  // Live 1024-bit RSA key taken from selector1._domainkey.github.com.
  const rsa1024 =
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxZC/z2cK+2s1f/ktzSDSeFzkfIHrjwtGFsfKMAYvK' +
    'aXjPVNzKykpbXBkX5nB7dVUTFttda7aROr2iSrIseQ27Ui+4rUZVzgFanE8RaXhYM9n5wPKNv8GtLJk7' +
    'JgcsYZ7ErgID4uW2sEYyV/dnRYw6rDzOaeRKkKELTUfJI5ebLQIDAQAB'

  assert.deepEqual(keyStrength(`v=DKIM1; k=rsa; p=${rsa1024}`), {
    algorithm: 'rsa',
    weak: true,
    bits: 1024,
  })

  // k= defaults to rsa when the tag is absent (RFC 6376 s3.6.1).
  assert.equal(keyStrength(`v=DKIM1; p=${rsa1024}`).bits, 1024)

  // A 2048-bit SPKI is 294 bytes; build one of the right length rather than inline it.
  const rsa2048 = Buffer.alloc(294, 1).toString('base64')
  assert.deepEqual(keyStrength(`v=DKIM1; k=rsa; p=${rsa2048}`), {
    algorithm: 'rsa',
    weak: false,
    bits: 2048,
  })

  assert.deepEqual(keyStrength('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='), {
    algorithm: 'ed25519',
    weak: false,
    bits: 256,
  })

  // A revoked key has no size and must not be reported as weak.
  assert.deepEqual(keyStrength('v=DKIM1; k=rsa; p='), {
    algorithm: 'rsa',
    weak: false,
    bits: null,
  })
})

test('DKIM: a 1024-bit key warns and names the size', async () => {
  const rsa1024 =
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxZC/z2cK+2s1f/ktzSDSeFzkfIHrjwtGFsfKMAYvK' +
    'aXjPVNzKykpbXBkX5nB7dVUTFttda7aROr2iSrIseQ27Ui+4rUZVzgFanE8RaXhYM9n5wPKNv8GtLJk7' +
    'JgcsYZ7ErgID4uW2sEYyV/dnRYw6rDzOaeRKkKELTUfJI5ebLQIDAQAB'
  const resolver = createFixtureResolver({
    txt: { 'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsa1024}`] },
  })
  const findings = await checkDkim('example.com', resolver)
  assert.equal(findings[0].status, 'warn')
  assert.match(findings[0].title, /1024-bit/)
})

test('DKIM: nothing found reports unknown, never a failure', async () => {
  const resolver = createFixtureResolver({})
  const findings = await checkDkim('example.com', resolver)
  assert.deepEqual(ids(findings), ['dkim.none-found'])
  assert.equal(findings[0].status, 'unknown')
  assert.match(findings[0].detail, /not proof/)
})

test('DKIM: a published key on a known selector passes', async () => {
  const resolver = createFixtureResolver({
    txt: {
      'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${'A'.repeat(392)}`],
    },
  })
  const findings = await checkDkim('example.com', resolver)
  assert.deepEqual(ids(findings), ['dkim.found.google'])
  assert.equal(findings[0].status, 'pass')
})

test('DKIM: an empty p= is reported as revoked', async () => {
  const resolver = createFixtureResolver({
    txt: { 'google._domainkey.example.com': ['v=DKIM1; k=rsa; p='] },
  })
  const findings = await checkDkim('example.com', resolver)
  assert.deepEqual(ids(findings), ['dkim.revoked.google'])
  assert.equal(findings[0].status, 'warn')
})

test('DKIM: a user-supplied selector is probed', async () => {
  const resolver = createFixtureResolver({
    txt: { 'custom._domainkey.example.com': [`v=DKIM1; k=rsa; p=${'A'.repeat(392)}`] },
  })
  const findings = await checkDkim('example.com', resolver, { selectors: ['custom'] })
  assert.deepEqual(ids(findings), ['dkim.found.custom'])
})

test('MX: null MX is a warning, absent MX is a failure', async () => {
  const absent = await checkMx('example.com', createFixtureResolver({}))
  assert.deepEqual(ids(absent), ['mx.missing'])

  const nullMx = await checkMx(
    'example.com',
    createFixtureResolver({ mx: { 'example.com': [{ exchange: '', priority: 0 }] } }),
  )
  assert.deepEqual(ids(nullMx), ['mx.null'])
  assert.equal(nullMx[0].status, 'warn')
})

test('MX: records are reported in priority order', async () => {
  const resolver = createFixtureResolver({
    mx: {
      'example.com': [
        { exchange: 'backup.example.net', priority: 20 },
        { exchange: 'primary.example.net', priority: 10 },
      ],
    },
  })
  const findings = await checkMx('example.com', resolver)
  assert.deepEqual(findings[0].evidence, ['10 primary.example.net', '20 backup.example.net'])
})

test('check(): a fully broken domain fails every record and sorts worst first', async () => {
  const result = await check('broken.example', {
    resolver: createFixtureResolver({}),
    skipBlocklists: true,
  })

  assert.equal(result.domain, 'broken.example')
  assert.equal(result.summary.pass, 0)
  assert.ok(result.summary.fail >= 3)

  const statuses = result.findings.map((f) => f.status)
  assert.deepEqual(statuses, [...statuses].sort((a, b) =>
    ({ fail: 0, warn: 1, unknown: 2, pass: 3 })[a] - ({ fail: 0, warn: 1, unknown: 2, pass: 3 })[b],
  ))

  const found = ids(result.findings)
  assert.ok(found.includes('spf.missing'))
  assert.ok(found.includes('dmarc.missing'))
  assert.ok(found.includes('mx.missing'))
})

test('check(): a well-configured domain reports no failures', async () => {
  const result = await check('good.example', {
    skipBlocklists: true,
    resolver: createFixtureResolver({
      txt: {
        'good.example': ['v=spf1 include:_spf.google.com -all'],
        '_dmarc.good.example': ['v=DMARC1; p=reject; rua=mailto:dmarc@good.example'],
        'google._domainkey.good.example': [`v=DKIM1; k=rsa; p=${'A'.repeat(392)}`],
      },
      mx: { 'good.example': [{ exchange: 'aspmx.l.google.com', priority: 1 }] },
    }),
  })

  assert.equal(result.summary.fail, 0)
  assert.equal(result.summary.warn, 0)
  assert.ok(result.summary.pass >= 4)
})

test('every non-passing finding tells the reader what to do about it', async () => {
  const result = await check('broken.example', {
    resolver: createFixtureResolver({}),
    skipBlocklists: true,
  })
  for (const f of result.findings) {
    if (f.status === 'pass') continue
    assert.ok(f.fix, `finding ${f.id} has no fix`)
  }
})

test('report renders without colour codes when colour is off', async () => {
  const result = await check('broken.example', {
    resolver: createFixtureResolver({}),
    skipBlocklists: true,
  })
  const text = formatText(result, { colour: false })
  assert.doesNotMatch(text, /\x1b\[/)
  assert.match(text, /Deliverability check: broken\.example/)
  assert.match(text, /FAIL/)
})

test('report hides passing checks when asked', async () => {
  const result = await check('good.example', {
    skipBlocklists: true,
    resolver: createFixtureResolver({
      txt: {
        'good.example': ['v=spf1 include:_spf.google.com -all'],
        '_dmarc.good.example': ['v=DMARC1; p=reject; rua=mailto:d@good.example'],
      },
      mx: { 'good.example': [{ exchange: 'mx.good.example', priority: 1 }] },
    }),
  })
  const text = formatText(result, { colour: false, showPasses: false })
  assert.doesNotMatch(text, /PASS/)
})
