import SettingsSuggestIcon from '@mui/icons-material/SettingsSuggest';
import { Slider, Stack, Typography } from '@mui/material';
import { FC } from 'react';
import type { ComplexityLevel } from '../types';

interface ComplexitySliderProps {
  value: ComplexityLevel;
  onChange: (value: ComplexityLevel) => void;
}

const marks = [
  { value: 0, label: 'Beginner' },
  { value: 1, label: 'Intermediate' },
  { value: 2, label: 'Expert' },
];

const levelFromValue = (value: number): ComplexityLevel => {
  if (value <= 0.5) {
    return 'beginner';
  }
  if (value <= 1.5) {
    return 'intermediate';
  }
  return 'expert';
};

const valueFromLevel = (level: ComplexityLevel): number => {
  switch (level) {
    case 'beginner':
      return 0;
    case 'intermediate':
      return 1;
    case 'expert':
      return 2;
    default:
      return 0;
  }
};

export const ComplexitySlider: FC<ComplexitySliderProps> = ({ value, onChange }) => {
  return (
    <Stack spacing={1} sx={{ px: 2 }}>
      <Stack direction="row" spacing={1} alignItems="center">
        <SettingsSuggestIcon color="secondary" />
        <Typography variant="subtitle1">Interface complexity</Typography>
      </Stack>
      <Slider
        value={valueFromLevel(value)}
        min={0}
        max={2}
        step={1}
        marks={marks}
        onChange={(_, newValue) => {
          if (typeof newValue === 'number') {
            onChange(levelFromValue(newValue));
          }
        }}
        valueLabelDisplay="auto"
        valueLabelFormat={(current) => marks.find((mark) => mark.value === current)?.label ?? ''}
        color="secondary"
      />
    </Stack>
  );
};

export default ComplexitySlider;
