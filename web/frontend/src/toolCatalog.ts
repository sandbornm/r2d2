export type ToolCategory = 'core' | 'firmware' | 'static' | 'dynamic' | 'library' | 'service' | 'ai';

export interface ToolCatalogEntry {
  key: string;
  displayName: string;
  shortName: string;
  category: ToolCategory;
  description: string;
  produces: string;
  priority: number;
  aliases?: string[];
}

export const TOOL_CATALOG: ToolCatalogEntry[] = [
  {
    key: 'firmware',
    displayName: 'Firmware',
    shortName: 'fw',
    category: 'firmware',
    description: 'Wrapper and embedded-blob inventory.',
    produces: 'Signatures, carve hints',
    priority: 10,
  },
  {
    key: 'binwalk',
    displayName: 'binwalk',
    shortName: 'binwalk',
    category: 'firmware',
    description: 'Signature scan and extract helper.',
    produces: 'FS signatures',
    priority: 20,
  },
  {
    key: 'autoprofile',
    displayName: 'AutoProfile',
    shortName: 'profile',
    category: 'core',
    description: 'Quick profile and risk hints.',
    produces: 'Security bits, strings',
    priority: 30,
  },
  {
    key: 'libmagic',
    displayName: 'libmagic',
    shortName: 'magic',
    category: 'core',
    description: 'File-type magic.',
    produces: 'Type / MIME',
    priority: 40,
    aliases: ['identification'],
  },
  {
    key: 'radare2',
    displayName: 'radare2',
    shortName: 'r2',
    category: 'static',
    description: 'Disassembly, functions, imports.',
    produces: 'Listing + metadata',
    priority: 50,
    aliases: ['r2'],
  },
  {
    key: 'rizin',
    displayName: 'Rizin',
    shortName: 'rz',
    category: 'static',
    description: 'r2-family static triage.',
    produces: 'Listing + metadata',
    priority: 55,
    aliases: ['rz-bin'],
  },
  {
    key: 'capstone',
    displayName: 'Capstone',
    shortName: 'cap',
    category: 'library',
    description: 'Instruction decoder.',
    produces: 'Operands',
    priority: 60,
  },
  {
    key: 'pyelftools',
    displayName: 'pyelftools',
    shortName: 'elf',
    category: 'library',
    description: 'ELF / DWARF parser.',
    produces: 'Headers, debug',
    priority: 70,
    aliases: ['elftools'],
  },
  {
    key: 'dwarf',
    displayName: 'DWARF',
    shortName: 'dwarf',
    category: 'library',
    description: 'Debug symbols and types.',
    produces: 'DWARF',
    priority: 75,
  },
  {
    key: 'pefile',
    displayName: 'pefile',
    shortName: 'pe',
    category: 'library',
    description: 'Windows PE parser.',
    produces: 'PE metadata',
    priority: 80,
  },
  {
    key: 'lief',
    displayName: 'LIEF',
    shortName: 'lief',
    category: 'library',
    description: 'ELF/PE/Mach-O parser.',
    produces: 'Format metadata',
    priority: 90,
  },
  {
    key: 'angr',
    displayName: 'angr',
    shortName: 'angr',
    category: 'static',
    description: 'Symbolic execution / CFG.',
    produces: 'CFG, paths',
    priority: 100,
  },
  {
    key: 'angr_mcp',
    displayName: 'angr MCP',
    shortName: 'angr mcp',
    category: 'service',
    description: 'Local angr service.',
    produces: 'CFG over MCP',
    priority: 110,
  },
  {
    key: 'ghidra',
    displayName: 'Ghidra',
    shortName: 'ghidra',
    category: 'static',
    description: 'Decompiler (headless).',
    produces: 'C-like, xrefs',
    priority: 120,
  },
  {
    key: 'ghidra_mcp',
    displayName: 'GhidraMCP',
    shortName: 'gh mcp',
    category: 'service',
    description: 'Ghidra GUI plugin (unused here).',
    produces: 'Plugin HTTP',
    priority: 130,
  },
  {
    key: 'ghidra_gdb',
    displayName: 'GDB MCP',
    shortName: 'gdb mcp',
    category: 'service',
    description: 'Docker GDB sidecar.',
    produces: 'Runtime inspect',
    priority: 140,
  },
  {
    key: 'gdb',
    displayName: 'GDB',
    shortName: 'gdb',
    category: 'dynamic',
    description: 'Debugger.',
    produces: 'Break/regs',
    priority: 150,
  },
  {
    key: 'gef',
    displayName: 'GEF/GDB',
    shortName: 'gef',
    category: 'dynamic',
    description: 'GDB traces in Docker.',
    produces: 'Trace, maps',
    priority: 160,
  },
  {
    key: 'frida',
    displayName: 'Frida',
    shortName: 'frida',
    category: 'dynamic',
    description: 'Runtime hooks.',
    produces: 'Modules, hooks',
    priority: 170,
  },
  {
    key: 'unicorn',
    displayName: 'Unicorn',
    shortName: 'uni',
    category: 'library',
    description: 'CPU emulator.',
    produces: 'Emulated state',
    priority: 180,
  },
  {
    key: 'keystone',
    displayName: 'Keystone',
    shortName: 'ks',
    category: 'library',
    description: 'Assembler.',
    produces: 'Bytes from asm',
    priority: 190,
  },
  {
    key: 'pwntools',
    displayName: 'pwntools',
    shortName: 'pwn',
    category: 'library',
    description: 'Exploit helpers (hidden).',
    produces: 'ROP / I/O',
    priority: 200,
    aliases: ['pwn'],
  },
  {
    key: 'ollama',
    displayName: 'Ollama',
    shortName: 'ollama',
    category: 'ai',
    description: 'Local chat models.',
    produces: 'Replies',
    priority: 300,
  },
];

const catalogByKey = new Map<string, ToolCatalogEntry>();

for (const entry of TOOL_CATALOG) {
  catalogByKey.set(entry.key, entry);
  for (const alias of entry.aliases ?? []) {
    catalogByKey.set(alias, entry);
  }
}

export const TOOL_ORDER = TOOL_CATALOG.map((tool) => tool.key);

export const getToolCatalogEntry = (name: string): ToolCatalogEntry | undefined => catalogByKey.get(name);

export const getToolDisplayName = (name: string): string => getToolCatalogEntry(name)?.displayName ?? name;

export const getToolShortName = (name: string): string => getToolCatalogEntry(name)?.shortName ?? name;

export const getToolDescription = (name: string): string => getToolCatalogEntry(name)?.description ?? 'Analysis support';

export const getToolProduces = (name: string): string => getToolCatalogEntry(name)?.produces ?? 'Analysis output';

export const getToolCategory = (name: string): ToolCategory | 'unknown' =>
  getToolCatalogEntry(name)?.category ?? 'unknown';

const getToolPriority = (name: string): number => getToolCatalogEntry(name)?.priority ?? 999;

export const sortToolEntries = <T>(entries: [string, T][]): [string, T][] =>
  [...entries].sort(([left], [right]) => getToolPriority(left) - getToolPriority(right) || left.localeCompare(right));
