# deliverability-check

**Find out why your email is going to spam, and what specifically to change.**

```bash
npx @askeleven/deliverability-check yourdomain.com
```

No signup, no account, no email address, nothing stored. Zero dependencies, so you can
read the whole thing in about ten minutes and confirm that.

---

## What it checks

| | |
|---|---|
| **SPF** | Published, single record, under the ten-lookup limit, and how strict the closing `all` is |
| **DKIM** | Probes the selectors the common providers use, and decodes the key to report its real size |
| **DMARC** | Policy strength, whether reports are being collected, partial-rollout percentages left switched on |
| **MX** | Records present, null MX detected |
| **BIMI** | Published, logo referenced, mark certificate present |
| **Blocklists** | Your mail servers against public DNSBLs |
| **Compliance** | A checklist of the CAN-SPAM, CASL, and GDPR obligations that DNS cannot see (`--checklist`) |

## What it does not do

**It does not give you a score.** A score invites you to optimise a number, and the
number would be made up: a missing DMARC record and a 1024-bit DKIM key are not
commensurable, so any weighting between them is arbitrary. You get findings, each with
its own severity and its own fix.

**It does not tell you DKIM is missing.** DKIM selectors cannot be discovered from DNS.
You can only look one up if you already know its name. We probe seventeen selectors used
by the common providers, and if none answer we say we did not find one, not that you do
not have one. Pass `--selector` if you know yours.

**It does not check your sending reputation.** The blocklist check looks at the servers
that *receive* mail for your domain, because those are the ones DNS exposes. Those are
frequently not the servers sending your outbound campaigns. Treat it as a smoke test.

---

## Example

```
$ npx @askeleven/deliverability-check example.com

Deliverability check: example.com

FAIL  No DMARC record
      Nobody can forge your domain and be stopped, and you receive no reports, so
      you have no way of knowing who is sending as you. Google and Yahoo require
      DMARC to accept bulk mail, so this also caps how much you can send.
      Fix: Publish a TXT record at _dmarc.example.com starting at monitoring only:
      "v=DMARC1; p=none; rua=mailto:dmarc@example.com". Read the reports for a
      month, then tighten to quarantine and reject.

WARN  SPF ends in ~all (softfail)
      Softfail is the right setting while you are still finding senders, but it
      asks receivers to accept forged mail and merely note it.
      Fix: Once DMARC reports show no legitimate sources failing, tighten ~all
      to -all.
      v=spf1 include:_spf.google.com ~all

1 failing, 1 to improve, 0 undetermined, 4 passing.
```

## Options

```
--selector <name>   Extra DKIM selector to probe. Repeatable.
--dns <ip>          Resolver to query. Repeatable.
--json              Machine-readable output.
--checklist         Also print the compliance obligations DNS cannot check.
--quiet             Hide passing checks.
--no-colour         Plain text.
```

Exit code is `1` if anything failed, `0` otherwise, so it drops into CI:

```bash
npx @askeleven/deliverability-check yourdomain.com --quiet || exit 1
```

### A note on blocklist results

Spamhaus refuses lookups arriving via large public resolvers like `8.8.8.8`, and answers
with a refusal code rather than a real result. If you are behind one, we report
`unknown` rather than pretending you are clean. Point `--dns` at your own resolver for a
usable answer.

## As a library

```js
import { check } from '@askeleven/deliverability-check'

const result = await check('example.com')
if (result.summary.fail > 0) {
  for (const f of result.findings.filter((f) => f.status === 'fail')) {
    console.log(f.title, '->', f.fix)
  }
}
```

Every finding has a stable `id`, so you can match on specific problems without parsing
prose. `createFixtureResolver()` is exported so you can test against captured DNS without
touching the network.

## Requirements

Node 20 or newer. No dependencies.

---

## Why we built it

[AskEleven](https://askeleven.com) runs AI employees that send email on behalf of small
businesses. Which means we have had a front-row seat for every way this goes wrong, and
have caused a fair few of them ourselves: the SPF record that quietly went over ten
lookups when a client added a newsletter tool, the bounces nobody was reading until the
domain reputation was already gone.

The existing free checkers are lead-capture forms wearing a tool costume: enter your
domain, get a score out of 100, enter your email to find out what it means. This one just
tells you.

We would obviously rather you also
[hired us](https://askeleven.com). But this is useful whether you do or not, and it stays
useful either way.

## Contributing

Issues and pull requests welcome, especially:

- **Selectors we are missing.** If your provider uses one not in `COMMON_SELECTORS`, that
  is the single most useful contribution.
- **Wrong verdicts.** If a finding is technically incorrect, open an issue with the
  domain and we will fix it.
- **Confusing wording.** The audience is a business owner, not a sysadmin. If a message
  needs prior knowledge to act on, it is a bug.

Run the tests with `npm test`. They use fixture DNS, so they are offline and fast.

## License

MIT. See [LICENSE](LICENSE).

The compliance checklist is a summary of obligations, not legal advice. Talk to a lawyer
before running an outreach programme.
