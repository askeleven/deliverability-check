import { Resolver } from 'node:dns/promises'

/**
 * @typedef {object} DnsResolver
 * @property {(name: string) => Promise<string[]>} txt Flattened TXT records.
 * @property {(name: string) => Promise<{exchange: string, priority: number}[]>} mx
 * @property {(name: string) => Promise<string[]>} a IPv4 addresses.
 */

/** Queries that take longer than this are treated as "no answer". */
const DEFAULT_TIMEOUT_MS = 5000

/**
 * Wraps node's DNS resolver so every lookup resolves to an empty array instead of
 * throwing. Every check in this tool treats "no record" and "lookup failed" the same
 * way at the call site, and distinguishing NXDOMAIN from SERVFAIL would not change any
 * verdict we produce.
 *
 * @param {{ servers?: string[], timeoutMs?: number }} [options]
 * @returns {DnsResolver}
 */
export function createResolver(options = {}) {
  const { servers, timeoutMs = DEFAULT_TIMEOUT_MS } = options
  const resolver = new Resolver()
  if (servers?.length) resolver.setServers(servers)

  /**
   * @template T
   * @param {Promise<T[]>} promise
   * @returns {Promise<T[]>}
   */
  const orEmpty = async (promise) => {
    /** @type {NodeJS.Timeout | undefined} */
    let timer
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve([]), timeoutMs)
    })
    try {
      return await Promise.race([promise, timeout])
    } catch {
      return []
    } finally {
      clearTimeout(timer)
    }
  }

  return {
    // resolveTxt returns string chunks per record; long records are split at 255 bytes
    // and must be rejoined with no separator.
    txt: (name) => orEmpty(resolver.resolveTxt(name).then((rs) => rs.map((r) => r.join('')))),
    mx: (name) => orEmpty(resolver.resolveMx(name)),
    a: (name) => orEmpty(resolver.resolve4(name)),
  }
}

/**
 * Builds a resolver backed by a fixed map, for tests and for replaying a captured
 * domain without touching the network.
 *
 * @param {{ txt?: Record<string, string[]>, mx?: Record<string, {exchange: string, priority: number}[]>, a?: Record<string, string[]> }} fixture
 * @returns {DnsResolver}
 */
export function createFixtureResolver(fixture) {
  return {
    txt: async (name) => fixture.txt?.[name] ?? [],
    mx: async (name) => fixture.mx?.[name] ?? [],
    a: async (name) => fixture.a?.[name] ?? [],
  }
}
