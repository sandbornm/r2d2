import { describe, expect, it } from 'vitest';
import {
  matchLenses,
  rankFunctions,
  rankImports,
  rankRegions,
  rankStrings,
  rankTargets,
  resolveGoal,
} from '../utils/rank';
import type { BriefingRegion } from '../types';

const region = (partial: Partial<BriefingRegion> & Pick<BriefingRegion, 'id' | 'title' | 'tags'>): BriefingRegion => ({
  why: '',
  score: 80,
  ask: '',
  next_actions: [],
  ...partial,
});

describe('rank', () => {
  it('infers unpack on a firmware wrapper', () => {
    const resolved = resolveGoal('', undefined, [], [], { format: 'firmware_container', firmware_kind: 'tp_link_cloud', name: 'a13fc36a.bin' });
    expect(resolved.lenses).toEqual(['unpack']);
    expect(resolved.source).toBe('inferred');
    expect(resolved.goal).toMatch(/carve/i);
  });

  it('uses the typed thesis over inferred tags', () => {
    const resolved = resolveGoal('who calls strcpy on login', 'carve the rootfs', ['lens-unpack']);
    expect(resolved.source).toBe('user');
    expect(resolved.lenses).toEqual(expect.arrayContaining(['sinks', 'auth']));
  });

  it('drops muted firmware regions when the thesis is sinks', () => {
    const ranked = rankRegions(
      [
        region({ id: 'fw', title: 'Firmware region: Cloud', tags: ['firmware', 'vendor_wrapper'], score: 96 }),
        region({ id: 'plt', title: 'PLT / imported libc surface', tags: ['imports', 'plt', 'dangerous'], score: 93 }),
      ],
      ['sinks'],
      'who calls strcpy',
    );
    expect(ranked.map((item) => item.id)).toEqual(['plt']);
  });

  it('filters filler strings and keeps cgi/httpd', () => {
    expect(rankStrings(['Hello World', 'httpd', '/cgi-bin/login', 'rootpath'], ['network'], 'httpd cgi')).toEqual([
      'httpd',
      '/cgi-bin/login',
    ]);
  });

  it('hides wrapper ELF at 0x0 and keeps squashfs', () => {
    const kept = rankTargets(
      [
        { kind: 'vendor_wrapper', offset_hex: '0x0', name: 'Cloud' },
        { kind: 'elf_binary', offset_hex: '0x0', name: 'ELF @ 0x0' },
        { kind: 'jffs2_marker', offset_hex: '0x137eb', name: 'JFFS2' },
        { kind: 'squashfs_filesystem', offset_hex: '0x100200', name: 'SquashFS LE' },
      ],
      ['unpack'],
    );
    expect(kept.map((item) => item.kind)).toEqual(['squashfs_filesystem', 'vendor_wrapper']);
  });

  it('keeps named functions that match the thesis', () => {
    const kept = rankFunctions(
      [{ name: 'main' }, { name: 'helper' }, { name: 'http_auth' }],
      ['sinks', 'network'],
      'httpd',
    );
    expect(kept.map((item) => item.name)).toEqual(['main', 'http_auth']);
  });

  it('matches lens tags', () => {
    expect(matchLenses('', ['lens-unpack', 'httpd'])).toEqual(['unpack']);
  });

  it('hides imports on unpack-only', () => {
    expect(rankImports(['strcpy', 'printf'], ['unpack'])).toEqual([]);
  });
});
