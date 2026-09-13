/**
 * The half of cold outreach that DNS cannot see.
 *
 * Everything above this file is measurable: a record is published or it is not. The
 * obligations below are about conduct, and no external tool can verify them, so this is
 * a checklist rather than a check. It is deliberately short and covers the requirements
 * that outreach programmes actually breach, not the full text of any statute.
 *
 * Not legal advice.
 *
 * @typedef {object} ChecklistItem
 * @property {string} id
 * @property {string} regime
 * @property {string} requirement
 * @property {string} detail
 */

/** @type {ChecklistItem[]} */
export const CHECKLIST = [
  {
    id: 'canspam.unsubscribe-present',
    regime: 'CAN-SPAM (US)',
    requirement: 'Every commercial message carries a working opt-out mechanism.',
    detail:
      'It must still work for at least 30 days after sending. One-to-one cold outreach ' +
      'from a real person is not exempt: if the primary purpose is commercial, this ' +
      'applies.',
  },
  {
    id: 'canspam.unsubscribe-honoured',
    regime: 'CAN-SPAM (US)',
    requirement: 'Opt-outs are honoured within 10 business days.',
    detail:
      'Across every list and every sending tool, not just the one that sent the ' +
      'message. This is the requirement most often breached by teams running more than ' +
      'one outreach system.',
  },
  {
    id: 'canspam.no-fee',
    regime: 'CAN-SPAM (US)',
    requirement: 'Opting out requires no login, no fee, and no information beyond an email address.',
    detail: 'A preference centre that demands account creation does not satisfy this.',
  },
  {
    id: 'canspam.physical-address',
    regime: 'CAN-SPAM (US)',
    requirement: 'A valid physical postal address appears in every message.',
    detail: 'A registered PO box or commercial mail receiving agency counts.',
  },
  {
    id: 'canspam.honest-headers',
    regime: 'CAN-SPAM (US)',
    requirement: 'From, reply-to, routing, and subject line are not deceptive.',
    detail:
      'Subject lines implying an existing relationship, a prior conversation, or a ' +
      'reply thread that never happened are the common breach here. "Re:" on a first ' +
      'contact is deceptive.',
  },
  {
    id: 'casl.consent',
    regime: 'CASL (Canada)',
    requirement: 'You hold express or documented implied consent before sending.',
    detail:
      'CASL is opt-in, unlike CAN-SPAM. Implied consent from a published business ' +
      'address is narrow, expires (commonly 6 months from an enquiry, 2 years from a ' +
      'transaction), and must relate to the recipient\'s role. Penalties reach ' +
      'CAD $10M per violation.',
  },
  {
    id: 'casl.identification',
    regime: 'CASL (Canada)',
    requirement: 'The sender is identified with contact details valid for 60 days.',
    detail: 'Plus a functioning unsubscribe honoured within 10 business days.',
  },
  {
    id: 'gdpr.lawful-basis',
    regime: 'GDPR / PECR (EU, UK)',
    requirement: 'You have a lawful basis, and can evidence it.',
    detail:
      'B2B outreach on legitimate interests requires a documented balancing test done ' +
      'before sending. Scraped personal addresses generally fail it, and a purchased ' +
      'list almost always does.',
  },
  {
    id: 'gdpr.transparency',
    regime: 'GDPR (EU, UK)',
    requirement: 'On first contact you say where you got their details.',
    detail: 'Article 14 applies whenever data was not collected from the person directly.',
  },
  {
    id: 'ops.suppression-list',
    regime: 'Operational',
    requirement: 'One suppression list, shared by every tool and every sender.',
    detail:
      'Complaints, opt-outs, hard bounces, and current customers. If your AI agent, ' +
      'your CRM, and your newsletter tool each keep their own, someone will be mailed ' +
      'after opting out, and it will be the person most likely to complain about it.',
  },
  {
    id: 'ops.bounce-handling',
    regime: 'Operational',
    requirement: 'Something reads the bounces and acts on them.',
    detail:
      'Not a mailbox nobody opens. Continuing to send to addresses that hard-bounced is ' +
      'one of the fastest routes to a blocklist, and the damage is usually done before ' +
      'anyone notices.',
  },
  {
    id: 'ops.ai-disclosure',
    regime: 'Operational',
    requirement: 'If an AI writes or sends it, know your disclosure obligations.',
    detail:
      'Rules vary by jurisdiction and channel and are changing quickly. Voice and SMS ' +
      'are regulated more tightly than email in most places.',
  },
]

/**
 * @returns {ChecklistItem[]}
 */
export function complianceChecklist() {
  return CHECKLIST
}
