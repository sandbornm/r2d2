import { fireEvent, render, screen } from '@testing-library/react';
import ComplexitySlider from '../components/ComplexitySlider';

describe('ComplexitySlider', () => {
  it('invokes onChange with the expected level', async () => {
    const handleChange = vi.fn();

    render(<ComplexitySlider value="beginner" onChange={handleChange} />);

    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: 2 } });

    expect(handleChange).toHaveBeenCalledWith('expert');
  });

  it('maps slider values to complexity levels', () => {
    const handleChange = vi.fn();
    render(<ComplexitySlider value="intermediate" onChange={handleChange} />);

    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: 0 } });
    expect(handleChange).toHaveBeenCalledWith('beginner');
  });
});
