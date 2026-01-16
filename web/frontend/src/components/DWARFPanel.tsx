import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BugReportIcon from '@mui/icons-material/BugReport';
import CodeIcon from '@mui/icons-material/Code';
import DataObjectIcon from '@mui/icons-material/DataObject';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import FolderIcon from '@mui/icons-material/Folder';
import FunctionsIcon from '@mui/icons-material/Functions';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import InfoIcon from '@mui/icons-material/Info';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Chip,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material';
import { SyntheticEvent, useEffect, useState } from 'react';
import { useActivity } from '../contexts/ActivityContext';
import type {
  DWARFCompilationUnit,
  DWARFData,
  DWARFFunction,
  DWARFType,
  DWARFVariable,
} from '../types';

interface DWARFPanelProps {
  data: DWARFData | null;
  onAskClaude?: (question: string) => void;
}

type TabId = 'overview' | 'functions' | 'types' | 'variables' | 'sources';

const formatAddress = (addr: number | null | undefined): string => {
  if (addr === null || addr === undefined) return '?';
  return `0x${addr.toString(16)}`;
};

const getLanguageName = (lang: number | undefined): string => {
  if (lang === undefined) return 'Unknown';
  const languages: Record<number, string> = {
    0x0001: 'C89',
    0x0002: 'C',
    0x0004: 'C++',
    0x000c: 'C99',
    0x001d: 'C11',
    0x002a: 'C17',
    0x0021: 'C++11',
    0x002b: 'C++14',
  };
  return languages[lang] || `Language ${lang}`;
};

const getTypeName = (tag: string): string => {
  const names: Record<string, string> = {
    DW_TAG_base_type: 'Primitive',
    DW_TAG_typedef: 'Typedef',
    DW_TAG_structure_type: 'Struct',
    DW_TAG_union_type: 'Union',
    DW_TAG_enumeration_type: 'Enum',
    DW_TAG_pointer_type: 'Pointer',
    DW_TAG_array_type: 'Array',
  };
  return names[tag] || tag.replace('DW_TAG_', '');
};

export default function DWARFPanel({ data, onAskClaude }: DWARFPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [expandedCU, setExpandedCU] = useState<string | false>(false);
  const activity = useActivity();

  // Track when DWARF panel is viewed
  useEffect(() => {
    if (data?.has_dwarf) {
      activity.trackEvent('dwarf_view', {
        function_count: data.functions.length,
        type_count: data.types.length,
        dwarf_version: data.dwarf_version,
      });
    }
  }, [data, activity]);

  if (!data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <BugReportIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
        <Typography color="text.secondary">No DWARF data available</Typography>
        <Typography variant="caption" color="text.disabled">
          Binary may not contain debug information
        </Typography>
      </Box>
    );
  }

  if (!data.has_dwarf) {
    return (
      <Alert severity="info" sx={{ m: 2 }}>
        This binary does not contain DWARF debug information. Compile with{' '}
        <code>-g</code> flag to include debug symbols.
      </Alert>
    );
  }

  const handleTabChange = (_: SyntheticEvent, newValue: TabId) => {
    setActiveTab(newValue);
  };

  const handleAskAboutFunction = (func: DWARFFunction) => {
    if (!onAskClaude) return;
    activity.trackEvent('dwarf_function_view', {
      function_name: func.name,
      address: formatAddress(func.low_pc),
    });
    activity.trackEvent('dwarf_ask_claude', { topic: 'function', function_name: func.name });
    const params = func.parameters.map((p) => p.name).join(', ');
    const question = `Tell me about the function \`${func.name}(${params})\` at ${formatAddress(func.low_pc)}. What does it do based on the debug information?`;
    onAskClaude(question);
  };

  const handleAskAboutType = (type: DWARFType) => {
    if (!onAskClaude) return;
    const typeName = type.name || `anonymous ${getTypeName(type.tag)}`;
    activity.trackEvent('dwarf_type_view', {
      type_name: typeName,
      type_tag: type.tag,
    });
    activity.trackEvent('dwarf_ask_claude', { topic: 'type', type_name: typeName });
    const question = `Explain the ${getTypeName(type.tag).toLowerCase()} type \`${typeName}\` from the DWARF debug info. What is its purpose and structure?`;
    onAskClaude(question);
  };

  const handleAskAboutOverview = () => {
    if (!onAskClaude) return;
    activity.trackEvent('dwarf_ask_claude', { topic: 'overview' });
    const question = `Analyze the DWARF debug information for this binary:
- ${data.functions.length} functions
- ${data.types.length} types
- ${data.variables.length} global variables
- ${data.source_files.length} source files
- DWARF version: ${data.dwarf_version}

What can you tell me about this program's structure and design?`;
    onAskClaude(question);
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={activeTab} onChange={handleTabChange} variant="scrollable">
          <Tab
            value="overview"
            label="Overview"
            icon={<InfoIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            sx={{ minHeight: 48 }}
          />
          <Tab
            value="functions"
            label={`Functions (${data.functions.length})`}
            icon={<FunctionsIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            sx={{ minHeight: 48 }}
          />
          <Tab
            value="types"
            label={`Types (${data.types.length})`}
            icon={<DataObjectIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            sx={{ minHeight: 48 }}
          />
          <Tab
            value="variables"
            label={`Variables (${data.variables.length})`}
            icon={<CodeIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            sx={{ minHeight: 48 }}
          />
          <Tab
            value="sources"
            label={`Sources (${data.source_files.length})`}
            icon={<FolderIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            sx={{ minHeight: 48 }}
          />
        </Tabs>
      </Box>

      <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
        {activeTab === 'overview' && (
          <OverviewTab
            data={data}
            expandedCU={expandedCU}
            setExpandedCU={setExpandedCU}
            onAskClaude={handleAskAboutOverview}
          />
        )}
        {activeTab === 'functions' && (
          <FunctionsTab
            functions={data.functions}
            onAskClaude={handleAskAboutFunction}
          />
        )}
        {activeTab === 'types' && (
          <TypesTab types={data.types} onAskClaude={handleAskAboutType} />
        )}
        {activeTab === 'variables' && (
          <VariablesTab variables={data.variables} />
        )}
        {activeTab === 'sources' && (
          <SourcesTab sourceFiles={data.source_files} />
        )}
      </Box>
    </Box>
  );
}

interface OverviewTabProps {
  data: DWARFData;
  expandedCU: string | false;
  setExpandedCU: (cu: string | false) => void;
  onAskClaude?: () => void;
}

function OverviewTab({
  data,
  expandedCU,
  setExpandedCU,
  onAskClaude,
}: OverviewTabProps) {
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <Typography variant="h6" sx={{ flex: 1 }}>
          Debug Information Summary
        </Typography>
        {onAskClaude && (
          <Tooltip title="Ask Claude about this debug info">
            <IconButton size="small" onClick={onAskClaude}>
              <SmartToyIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
        <Chip
          label={`DWARF v${data.dwarf_version}`}
          color="primary"
          size="small"
        />
        <Chip
          label={`${data.compilation_units.length} Compilation Units`}
          size="small"
        />
        <Chip label={`${data.functions.length} Functions`} size="small" />
        <Chip label={`${data.types.length} Types`} size="small" />
        <Chip label={`${data.variables.length} Variables`} size="small" />
      </Box>

      <Typography variant="subtitle2" sx={{ mb: 1 }}>
        Compilation Units
      </Typography>

      {data.compilation_units.map((cu, idx) => (
        <Accordion
          key={cu.offset}
          expanded={expandedCU === `cu-${idx}`}
          onChange={(_, expanded) =>
            setExpandedCU(expanded ? `cu-${idx}` : false)
          }
        >
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <AccountTreeIcon sx={{ fontSize: 18, color: 'primary.main' }} />
              <Typography variant="body2" fontWeight={500}>
                {cu.name || `CU at offset ${cu.offset}`}
              </Typography>
              <Chip
                label={`v${cu.version}`}
                size="small"
                sx={{ height: 18, fontSize: '0.7rem' }}
              />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <CompilationUnitDetails cu={cu} />
          </AccordionDetails>
        </Accordion>
      ))}
    </Box>
  );
}

function CompilationUnitDetails({ cu }: { cu: DWARFCompilationUnit }) {
  return (
    <Box sx={{ fontSize: '0.85rem' }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: 0.5 }}>
        {cu.producer && (
          <>
            <Typography variant="caption" color="text.secondary">
              Compiler:
            </Typography>
            <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
              {cu.producer}
            </Typography>
          </>
        )}
        {cu.language !== undefined && (
          <>
            <Typography variant="caption" color="text.secondary">
              Language:
            </Typography>
            <Typography variant="caption">
              {getLanguageName(cu.language)}
            </Typography>
          </>
        )}
        {cu.comp_dir && (
          <>
            <Typography variant="caption" color="text.secondary">
              Build Dir:
            </Typography>
            <Typography
              variant="caption"
              sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
            >
              {cu.comp_dir}
            </Typography>
          </>
        )}
        <Typography variant="caption" color="text.secondary">
          Functions:
        </Typography>
        <Typography variant="caption">{cu.functions.length}</Typography>
        <Typography variant="caption" color="text.secondary">
          Source Files:
        </Typography>
        <Typography variant="caption">{cu.source_files.length}</Typography>
      </Box>
    </Box>
  );
}

interface FunctionsTabProps {
  functions: DWARFFunction[];
  onAskClaude?: (func: DWARFFunction) => void;
}

function FunctionsTab({ functions, onAskClaude }: FunctionsTabProps) {
  if (functions.length === 0) {
    return (
      <Typography color="text.secondary">
        No function debug info available
      </Typography>
    );
  }

  return (
    <List dense>
      {functions.slice(0, 100).map((func, idx) => (
        <Paper key={idx} variant="outlined" sx={{ mb: 1 }}>
          <ListItem
            secondaryAction={
              onAskClaude && (
                <Tooltip title="Ask Claude about this function">
                  <IconButton
                    edge="end"
                    size="small"
                    onClick={() => onAskClaude(func)}
                  >
                    <HelpOutlineIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </Tooltip>
              )
            }
          >
            <ListItemIcon sx={{ minWidth: 36 }}>
              <FunctionsIcon
                sx={{
                  fontSize: 18,
                  color: func.is_external ? 'primary.main' : 'text.secondary',
                }}
              />
            </ListItemIcon>
            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography
                    variant="body2"
                    fontWeight={500}
                    sx={{ fontFamily: 'monospace' }}
                  >
                    {func.name}
                  </Typography>
                  {func.is_inline && (
                    <Chip
                      label="inline"
                      size="small"
                      sx={{ height: 16, fontSize: '0.65rem' }}
                    />
                  )}
                  {func.is_external && (
                    <Chip
                      label="extern"
                      size="small"
                      color="primary"
                      sx={{ height: 16, fontSize: '0.65rem' }}
                    />
                  )}
                </Box>
              }
              secondary={
                <Box
                  component="span"
                  sx={{ display: 'flex', gap: 2, fontFamily: 'monospace' }}
                >
                  <span>@ {formatAddress(func.low_pc)}</span>
                  {func.size && <span>{func.size} bytes</span>}
                  {func.parameters.length > 0 && (
                    <span>{func.parameters.length} params</span>
                  )}
                </Box>
              }
            />
          </ListItem>
        </Paper>
      ))}
      {functions.length > 100 && (
        <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
          Showing 100 of {functions.length} functions
        </Typography>
      )}
    </List>
  );
}

interface TypesTabProps {
  types: DWARFType[];
  onAskClaude?: (type: DWARFType) => void;
}

function TypesTab({ types, onAskClaude }: TypesTabProps) {
  if (types.length === 0) {
    return (
      <Typography color="text.secondary">No type debug info available</Typography>
    );
  }

  // Group types by kind
  const grouped = types.reduce(
    (acc, type) => {
      const kind = getTypeName(type.tag);
      if (!acc[kind]) acc[kind] = [];
      acc[kind].push(type);
      return acc;
    },
    {} as Record<string, DWARFType[]>
  );

  return (
    <Box>
      {Object.entries(grouped).map(([kind, typeList]) => (
        <Box key={kind} sx={{ mb: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            {kind} ({typeList.length})
          </Typography>
          <List dense>
            {typeList.slice(0, 20).map((type, idx) => (
              <Paper key={idx} variant="outlined" sx={{ mb: 0.5 }}>
                <ListItem
                  secondaryAction={
                    onAskClaude && type.name && (
                      <Tooltip title="Ask Claude about this type">
                        <IconButton
                          edge="end"
                          size="small"
                          onClick={() => onAskClaude(type)}
                        >
                          <HelpOutlineIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    )
                  }
                >
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    <DataObjectIcon sx={{ fontSize: 18 }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace' }}
                      >
                        {type.name || '(anonymous)'}
                      </Typography>
                    }
                    secondary={
                      <Box component="span" sx={{ fontFamily: 'monospace' }}>
                        {type.byte_size && <span>{type.byte_size} bytes</span>}
                        {type.members && (
                          <span> | {type.members.length} members</span>
                        )}
                        {type.enumerators && (
                          <span> | {type.enumerators.length} values</span>
                        )}
                      </Box>
                    }
                  />
                </ListItem>
              </Paper>
            ))}
            {typeList.length > 20 && (
              <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
                +{typeList.length - 20} more
              </Typography>
            )}
          </List>
        </Box>
      ))}
    </Box>
  );
}

interface VariablesTabProps {
  variables: DWARFVariable[];
}

function VariablesTab({ variables }: VariablesTabProps) {
  if (variables.length === 0) {
    return (
      <Typography color="text.secondary">
        No global variable debug info available
      </Typography>
    );
  }

  // Filter to global variables only
  const globals = variables.filter((v) => !v.is_local);

  return (
    <List dense>
      {globals.slice(0, 50).map((variable, idx) => (
        <Paper key={idx} variant="outlined" sx={{ mb: 0.5 }}>
          <ListItem>
            <ListItemIcon sx={{ minWidth: 36 }}>
              <CodeIcon
                sx={{
                  fontSize: 18,
                  color: variable.is_external ? 'primary.main' : 'text.secondary',
                }}
              />
            </ListItemIcon>
            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography
                    variant="body2"
                    sx={{ fontFamily: 'monospace' }}
                  >
                    {variable.name}
                  </Typography>
                  {variable.is_external && (
                    <Chip
                      label="extern"
                      size="small"
                      color="primary"
                      sx={{ height: 16, fontSize: '0.65rem' }}
                    />
                  )}
                </Box>
              }
              secondary={
                variable.decl_line && (
                  <span>Line {variable.decl_line}</span>
                )
              }
            />
          </ListItem>
        </Paper>
      ))}
      {globals.length > 50 && (
        <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
          Showing 50 of {globals.length} global variables
        </Typography>
      )}
    </List>
  );
}

interface SourcesTabProps {
  sourceFiles: string[];
}

function SourcesTab({ sourceFiles }: SourcesTabProps) {
  if (sourceFiles.length === 0) {
    return (
      <Typography color="text.secondary">
        No source file information available
      </Typography>
    );
  }

  return (
    <List dense>
      {sourceFiles.map((file, idx) => (
        <ListItem key={idx}>
          <ListItemIcon sx={{ minWidth: 36 }}>
            <FolderIcon sx={{ fontSize: 18 }} />
          </ListItemIcon>
          <ListItemText
            primary={
              <Typography
                variant="body2"
                sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
              >
                {file}
              </Typography>
            }
          />
        </ListItem>
      ))}
    </List>
  );
}
