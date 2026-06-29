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
    description: 'Built-in firmware signature inventory and embedded artifact routing.',
    produces: 'Signatures, carved target hints, firmware container metadata',
    priority: 10,
  },
  {
    key: 'binwalk',
    displayName: 'binwalk',
    shortName: 'binwalk',
    category: 'firmware',
    description: 'Firmware signature and filesystem extraction helper.',
    produces: 'Extraction hints, filesystem signatures, embedded archive matches',
    priority: 20,
  },
  {
    key: 'autoprofile',
    displayName: 'AutoProfile',
    shortName: 'profile',
    category: 'core',
    description: 'Quick binary profiling, security features, strings, and risk hints.',
    produces: 'Security profile, interesting strings, risk assessment',
    priority: 30,
  },
  {
    key: 'libmagic',
    displayName: 'libmagic',
    shortName: 'magic',
    category: 'core',
    description: 'File type identification using magic-number signatures.',
    produces: 'File type, MIME type, encoding detection',
    priority: 40,
    aliases: ['identification'],
  },
  {
    key: 'radare2',
    displayName: 'radare2',
    shortName: 'r2',
    category: 'static',
    description: 'Fast disassembly and binary metadata extraction through radare2/r2pipe.',
    produces: 'Disassembly, functions, imports, strings, binary metadata',
    priority: 50,
    aliases: ['r2'],
  },
  {
    key: 'rizin',
    displayName: 'Rizin',
    shortName: 'rz',
    category: 'static',
    description: 'radare-family disassembly alternative for local static triage.',
    produces: 'Disassembly, metadata, strings, command-line inspection',
    priority: 55,
    aliases: ['rz-bin'],
  },
  {
    key: 'capstone',
    displayName: 'Capstone',
    shortName: 'cap',
    category: 'library',
    description: 'Multi-architecture instruction decoder used for precise disassembly views.',
    produces: 'Instruction-level disassembly with operand details',
    priority: 60,
  },
  {
    key: 'pyelftools',
    displayName: 'pyelftools',
    shortName: 'elf',
    category: 'library',
    description: 'ELF and DWARF parser for metadata, sections, and debug information.',
    produces: 'ELF headers, sections, DWARF line/type metadata',
    priority: 70,
    aliases: ['elftools'],
  },
  {
    key: 'dwarf',
    displayName: 'DWARF',
    shortName: 'dwarf',
    category: 'library',
    description: 'Debug information parser for symbols, source mappings, and types.',
    produces: 'Debug symbols, type definitions, source line mappings',
    priority: 75,
  },
  {
    key: 'pefile',
    displayName: 'pefile',
    shortName: 'pe',
    category: 'library',
    description: 'Windows PE parser for imports, sections, resources, and headers.',
    produces: 'PE headers, imports, resources, section metadata',
    priority: 80,
  },
  {
    key: 'lief',
    displayName: 'LIEF',
    shortName: 'lief',
    category: 'library',
    description: 'Cross-format ELF/PE/Mach-O parser and patching library.',
    produces: 'Parsed executable metadata, patching primitives, format details',
    priority: 90,
  },
  {
    key: 'angr',
    displayName: 'angr',
    shortName: 'angr',
    category: 'static',
    description: 'Symbolic execution engine for CFG recovery and path analysis.',
    produces: 'CFG nodes/edges, reachability analysis, path constraints',
    priority: 100,
  },
  {
    key: 'angr_mcp',
    displayName: 'angr MCP',
    shortName: 'angr mcp',
    category: 'service',
    description: 'MCP-backed angr service for CFG and symbolic execution workflows.',
    produces: 'Service-backed CFG, reachability, and symbolic execution outputs',
    priority: 110,
  },
  {
    key: 'ghidra',
    displayName: 'Ghidra',
    shortName: 'ghidra',
    category: 'static',
    description: 'Decompiler and static analysis suite for types and cross-references.',
    produces: 'Decompiled C, type information, cross-references',
    priority: 120,
  },
  {
    key: 'ghidra_mcp',
    displayName: 'GhidraMCP',
    shortName: 'gh mcp',
    category: 'service',
    description: 'MCP-backed Ghidra service for richer static analysis workflows.',
    produces: 'Service-backed decompilation, function data, scripting support',
    priority: 130,
  },
  {
    key: 'ghidra_gdb',
    displayName: 'GDB MCP',
    shortName: 'gdb mcp',
    category: 'service',
    description: 'GhidraMCP GDB service for dynamic analysis over a controlled debugger bridge.',
    produces: 'Debugger-backed execution context and runtime inspection',
    priority: 140,
  },
  {
    key: 'gdb',
    displayName: 'GDB',
    shortName: 'gdb',
    category: 'dynamic',
    description: 'GNU debugger for dynamic inspection and execution control.',
    produces: 'Breakpoints, register state, memory inspection',
    priority: 150,
  },
  {
    key: 'gef',
    displayName: 'GEF/GDB',
    shortName: 'gef',
    category: 'dynamic',
    description: 'GDB Enhanced Features for dynamic execution tracing in an isolated container.',
    produces: 'Register snapshots, memory maps, execution traces',
    priority: 160,
  },
  {
    key: 'frida',
    displayName: 'Frida',
    shortName: 'frida',
    category: 'dynamic',
    description: 'Dynamic instrumentation toolkit for runtime analysis and hooks.',
    produces: 'Runtime module info, memory layout, hook points',
    priority: 170,
  },
  {
    key: 'unicorn',
    displayName: 'Unicorn',
    shortName: 'uni',
    category: 'library',
    description: 'CPU emulator for isolated instruction and shellcode experiments.',
    produces: 'Emulated execution traces and register/memory state',
    priority: 180,
  },
  {
    key: 'keystone',
    displayName: 'Keystone',
    shortName: 'ks',
    category: 'library',
    description: 'Assembler engine for quick patch and shellcode prototyping.',
    produces: 'Assembled bytes from architecture-specific assembly',
    priority: 190,
  },
  {
    key: 'pwntools',
    displayName: 'pwntools',
    shortName: 'pwn',
    category: 'library',
    description: 'Exploit-development helpers for ELF, ROP, packing, and process I/O.',
    produces: 'ELF helpers, ROP primitives, process/socket utilities',
    priority: 200,
    aliases: ['pwn'],
  },
  {
    key: 'ollama',
    displayName: 'Ollama',
    shortName: 'ollama',
    category: 'ai',
    description: 'Local model runtime for chat-based analysis support.',
    produces: 'Local assistant responses and code explanations',
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
