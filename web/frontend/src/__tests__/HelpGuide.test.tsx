import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import HelpGuide from '../components/HelpGuide';

describe('HelpGuide', () => {
  it('states the binary-plus-thesis contract', () => {
    render(<HelpGuide open onClose={vi.fn()} />);
    expect(screen.getByText(/how this works/i)).toBeInTheDocument();
    expect(screen.getByText(/binary plus thesis/i)).toBeInTheDocument();
    expect(screen.getAllByText(/httpd/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/file, strings, readelf/i)).toBeInTheDocument();
    expect(screen.getByText(/1–4/)).toBeInTheDocument();
    expect(screen.getByText(/analyze/i)).toBeInTheDocument();
  });
});
