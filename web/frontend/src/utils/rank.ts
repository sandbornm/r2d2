import type { BriefingRegion } from '../types';

export const LENSES = ['unpack', 'sinks', 'network', 'auth', 'crypto'] as const;
export type Lens = (typeof LENSES)[number] | 'general';

const LENS_KEYWORDS: Record<Exclude<Lens, 'general'>, string[]> = {
  unpack: ['unpack', 'carve', 'extract', 'squash', 'rootfs', 'wrapper', 'unsquash', 'firmware', 'httpd', 'tdp', 'cgi', 'nvram'],
  sinks: ['sink', 'strcpy', 'sprintf', 'popen', 'system', 'overflow', 'dangerous', 'cgi', 'exec'],
  network: ['http', 'httpd', 'cgi', 'listen', 'accept', 'socket', 'web', 'tdp', 'bind', 'recv'],
  auth: ['auth', 'login', 'password', 'passwd', 'credential', 'nvram', 'admin'],
  crypto: ['crypto', 'encrypt', 'decrypt', 'aes', 'md5', 'sha', 'rsa'],
};

const LENS_BOOST: Record<Exclude<Lens, 'general'>, string[]> = {
  unpack: ['squashfs_filesystem', 'vendor_wrapper', 'uimage', 'firmware-child', 'elf_binary'],
  sinks: ['imports', 'plt', 'dangerous', 'function', 'disasm'],
  network: ['imports', 'network', 'function', 'firmware-child'],
  auth: ['credential', 'string', 'function', 'auth'],
  crypto: ['crypto', 'string', 'function'],
};

const LENS_MUTE: Record<Exclude<Lens, 'general'>, string[]> = {
  unpack: ['entry', 'function', 'disasm', 'issue', 'network'],
  sinks: ['firmware', 'vendor_wrapper', 'uimage'],
  network: ['vendor_wrapper', 'uimage'],
  auth: ['uimage', 'vendor_wrapper'],
  crypto: ['vendor_wrapper', 'uimage'],
};

const NAME_HINTS = [
  'main', 'entry', 'http', 'cgi', 'login', 'auth', 'passwd', 'password',
  'decrypt', 'encrypt', 'aes', 'md5', 'sha', 'nvram', 'tdp', 'upgrade',
  'upload', 'download', 'cmd', 'exec', 'parse', 'handler', 'socket',
];

const SINK_NEEDLES = [
  'popen', 'system', 'strcpy', 'strcat', 'sprintf', 'sscanf', 'memcpy',
  'memmove', 'recv', 'recvfrom', 'listen', 'accept', 'bind', 'socket',
  'ioctl', 'execl', 'execve',
];

export const KEEP_TARGET_KINDS = new Set([
  'squashfs_filesystem',
  'elf_binary',
  'vendor_wrapper',
  'uimage',
]);

export interface RankedGoal {
  goal: string;
  lenses: Lens[];
  source: 'user' | 'inferred';
}

export const matchLenses = (text: string, tags: string[] = []): Lens[] => {
  const hay = text.toLowerCase();
  const tagHay = tags.map((tag) => tag.toLowerCase());
  const hits: Lens[] = [];
  for (const lens of LENSES) {
    if (LENS_KEYWORDS[lens].some((keyword) => hay.includes(keyword))) {
      hits.push(lens);
    } else if (tagHay.includes(`lens-${lens}`) || tagHay.includes(`lens:${lens}`) || tagHay.includes(lens)) {
      hits.push(lens);
    }
  }
  return hits;
};

export const resolveGoal = (
  userGoal: string | undefined,
  inferredGoal: string | undefined,
  rankingTags: string[] = [],
  recordTags: string[] = [],
  subject?: Record<string, unknown> | null,
): RankedGoal => {
  const typed = (userGoal || '').trim();
  if (typed) {
    const lenses = matchLenses(typed, [...rankingTags, ...recordTags]);
    return { goal: typed, lenses: lenses.length ? lenses : ['general'], source: 'user' };
  }
  if (inferredGoal?.trim()) {
    const lenses = matchLenses(inferredGoal, rankingTags.length ? rankingTags : recordTags);
    return {
      goal: inferredGoal.trim(),
      lenses: lenses.length ? lenses : (rankingTags.length ? matchLenses(rankingTags.join(' '), rankingTags) : ['general']),
      source: 'inferred',
    };
  }
  const tags = [...rankingTags, ...recordTags];
  const name = String(subject?.name || '').toLowerCase();
  const format = `${subject?.format || ''} ${subject?.firmware_kind || ''}`.toLowerCase();
  if (/firmware|container|cloud|ver\. 2|img0|fwup/.test(format) && !format.includes('elf')) {
    return { goal: 'carve the rootfs and brief the userspace ELF — not this wrapper', lenses: ['unpack'], source: 'inferred' };
  }
  if (['httpd', 'uhttpd', 'tdpserver', 'tmpserver', 'busybox', 'dropbear'].some((hint) => name.includes(hint))) {
    return { goal: 'xref the dangerous and network imports; name the callers', lenses: ['sinks', 'network'], source: 'inferred' };
  }
  const fromTags = matchLenses(tags.join(' '), tags);
  if (fromTags.length) {
    return { goal: `follow tagged surface: ${tags.slice(0, 4).join(', ')}`, lenses: fromTags, source: 'inferred' };
  }
  return { goal: 'isolate the highest-signal next region', lenses: ['general'], source: 'inferred' };
};

const lensSets = (lenses: Lens[]) => {
  const boost = new Set<string>();
  const mute = new Set<string>();
  for (const lens of lenses) {
    if (lens === 'general') continue;
    LENS_BOOST[lens].forEach((tag) => boost.add(tag));
    LENS_MUTE[lens].forEach((tag) => mute.add(tag));
  }
  mute.forEach((tag) => {
    if (boost.has(tag)) mute.delete(tag);
  });
  return { boost, mute };
};

export const rankRegions = (regions: BriefingRegion[], lenses: Lens[], goal: string): BriefingRegion[] => {
  if (!regions.length) return [];
  const { boost, mute } = lensSets(lenses);
  const tokens = goal.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length >= 4);
  const scored = regions.map((region) => {
    const tags = new Set(region.tags || []);
    let score = region.score;
    const hay = `${region.title} ${region.why} ${(region.tags || []).join(' ')}`.toLowerCase();
    if ([...tags].some((tag) => boost.has(tag))) score += 18;
    else if ([...tags].some((tag) => mute.has(tag))) score -= 28;
    if (tokens.some((token) => hay.includes(token))) score += 6;
    return { region, score, muted: [...tags].some((tag) => mute.has(tag)) && ![...tags].some((tag) => boost.has(tag)) };
  });
  const boosted = scored.some((item) => !item.muted && item.score >= 70);
  return scored
    .filter((item) => !(item.muted && boosted && item.score < 70) && item.score >= 42)
    .sort((a, b) => b.score - a.score || a.region.id.localeCompare(b.region.id))
    .map((item) => item.region);
};

export const rankImports = (imports: string[], lenses: Lens[]): string[] => {
  const sinkFirst = lenses.includes('sinks') || lenses.includes('network') || lenses.includes('general');
  const hits = imports.filter((name) => SINK_NEEDLES.some((needle) => name.toLowerCase().includes(needle)));
  if (sinkFirst) return hits.slice(0, 12);
  if (lenses.includes('unpack')) return [];
  return hits.slice(0, 8);
};

export const rankStrings = (values: string[], lenses: Lens[], goal: string): string[] => {
  const keywords = new Set<string>();
  for (const lens of lenses) {
    if (lens !== 'general') LENS_KEYWORDS[lens].forEach((word) => keywords.add(word));
  }
  goal.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length >= 4).forEach((token) => keywords.add(token));
  const seen = new Set<string>();
  const requireKeyword = keywords.size > 0 && !lenses.includes('general');
  const kept: string[] = [];
  const fallback: string[] = [];
  for (const raw of values) {
    const text = raw.trim();
    const lower = text.toLowerCase();
    if (text.length < 4 || text.length > 96) continue;
    if (
      text.length < 6
      && !NAME_HINTS.some((word) => lower.includes(word) || word.includes(lower))
      && !SINK_NEEDLES.some((needle) => lower.includes(needle))
    ) continue;
    if (seen.has(lower)) continue;
    if (['rootpath', 'rootfs', 'root', 'login', 'auth', 'tftp', 'hello world', 'test string'].includes(lower)) continue;
    seen.add(lower);
    const hinted = NAME_HINTS.some((word) => lower.includes(word)) || SINK_NEEDLES.some((word) => lower.includes(word));
    if (!requireKeyword || [...keywords].some((word) => lower.includes(word))) {
      kept.push(text);
    } else if (hinted) {
      fallback.push(text);
    }
    if (kept.length >= 12) break;
  }
  return (kept.length ? kept : fallback).slice(0, 12);
};

export const rankTargets = (items: Record<string, unknown>[], lenses: Lens[]): Record<string, unknown>[] => {
  const seen = new Set<string>();
  const kept: Record<string, unknown>[] = [];
  const preferSquash = lenses.includes('unpack') || lenses.includes('general');
  for (const item of items) {
    const kind = String(item.kind || '');
    if (!KEEP_TARGET_KINDS.has(kind)) continue;
    const offset = typeof item.offset_hex === 'string' ? item.offset_hex : '';
    if (kind === 'elf_binary' && (offset === '0x0' || offset === '' || item.offset === 0)) {
      const hasWrapper = items.some((other) => String(other.kind) === 'vendor_wrapper');
      if (hasWrapper) continue;
    }
    const key = `${kind}:${offset}`;
    if (seen.has(key)) continue;
    if (kind === 'vendor_wrapper' && [...seen].some((value) => value.startsWith('vendor_wrapper:'))) continue;
    if (lenses.includes('sinks') && !lenses.includes('unpack') && kind !== 'elf_binary') continue;
    seen.add(key);
    kept.push(item);
  }
  return kept.sort((a, b) => {
    const rank = (kind: string) => {
      if (kind.includes('squash')) return preferSquash ? 0 : 2;
      if (kind.includes('elf')) return preferSquash ? 1 : 0;
      if (kind.includes('uimage')) return 3;
      return 4;
    };
    return rank(String(a.kind)) - rank(String(b.kind));
  }).slice(0, 5);
};

export const rankFunctions = <T extends { name: string }>(functions: T[], lenses: Lens[], goal: string): T[] => {
  if (lenses.includes('unpack') && !lenses.includes('sinks') && !lenses.includes('network')) return [];
  const tokens = new Set([
    ...NAME_HINTS,
    ...goal.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length >= 4),
  ]);
  return functions.filter((fn) => {
    const lower = fn.name.toLowerCase();
    return [...tokens].some((token) => lower.includes(token));
  }).slice(0, 12);
};
