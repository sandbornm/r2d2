import { Box, Dialog, IconButton, Stack, Typography } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { FC } from 'react';

interface HelpGuideProps {
  open: boolean;
  onClose: () => void;
}

const Block: FC<{ title: string; children: string }> = ({ title, children }) => (
  <Box>
    <Typography variant="subtitle2" sx={{ mb: 0.5 }}>{title}</Typography>
    <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 560 }}>
      {children}
    </Typography>
  </Box>
);

const HelpGuide: FC<HelpGuideProps> = ({ open, onClose }) => (
  <Dialog
    open={open}
    onClose={onClose}
    maxWidth="sm"
    fullWidth
    PaperProps={{ sx: { bgcolor: 'background.paper', backgroundImage: 'none', p: 1 } }}
  >
    <Stack direction="row" alignItems="center" sx={{ px: 2, pt: 1.5 }}>
      <Typography variant="subtitle1" sx={{ flex: 1 }}>How this works</Typography>
      <IconButton onClick={onClose} size="small" aria-label="Close help">
        <CloseIcon fontSize="small" />
      </IconButton>
    </Stack>
    <Stack spacing={2.25} sx={{ px: 2, pb: 3, pt: 1.5 }}>
      <Typography variant="body1">
        Binary plus thesis. Tools are a budget. Qwen is here to notice something
        you might skip — not to teach assembly.
      </Typography>
      <Block title="1. State the thesis">
        One sentence: who calls system on the login path, where upgrade writes flash,
        whether tdpServer and httpd share a parser. That is the only question Qwen answers.
      </Block>
      <Block title="2. Give it the right file">
        An upgrade .bin is inventory only (wrapper, squashfs offset). The program you actually
        care about is usually httpd or tdpServer after unpack — the router’s web admin, not a
        process on this Pi.
      </Block>
      <Block title="3. Profile is a budget, not a personality">
        Triage: firmware + r2 metadata. Standard: add listing/CFG. Exhaustive: optional angr/Ghidra
        on an ELF. Hover a tool name in the header to see if it is ready or off.
      </Block>
      <Block title="4. Ask on a region, not the whole dump">
        Each ranked region has a four-bullet ask. That is what Qwen should see. Do not paste the
        analysis JSON. Click Ask on the region that matches your thesis.
      </Block>
      <Block title="What a professional does first">
        Unpack, open httpd, list imports and CGI/nvram strings, xref system/sprintf/recv, rename
        five functions, stop. QEMU and angr come after a named hypothesis.
      </Block>
      <Block title="omp is a different layer">
        Oh My Pi plans multi-step Qwen pilots and shells out to r2d2. This UI is
        the store and the ask surface, not a second planner.
      </Block>
      <Block title="Intake is host-side">
        file, strings, readelf, and a hex peek run on the host and never execute the guest.
        A container is unnecessary for sniff. qemu-user is only for later running httpd.
        Those facts also tune the system prompt as a triage card.
      </Block>
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Keys</Typography>
        <Box
          component="dl"
          sx={{
            m: 0,
            display: 'grid',
            gridTemplateColumns: '56px 1fr',
            columnGap: 1.5,
            rowGap: 0.4,
            fontFamily: 'var(--font-mono)',
            fontSize: '0.78rem',
          }}
        >
          <dt>?</dt><dd style={{ margin: 0 }}>help</dd>
          <dt>1–4</dt><dd style={{ margin: 0 }}>results / map / chat / logs</dd>
          <dt>g</dt><dd style={{ margin: 0 }}>thesis (or pick a file)</dd>
          <dt>a</dt><dd style={{ margin: 0 }}>analyze</dd>
          <dt>esc</dt><dd style={{ margin: 0 }}>close</dd>
        </Box>
      </Box>
    </Stack>
  </Dialog>
);

export default HelpGuide;
