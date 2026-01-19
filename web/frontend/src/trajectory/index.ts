/**
 * Trajectory tracking module - exports for easy importing
 */
export {
  createSnapshot,
  createTrajectory,
  serializeSnapshot,
  type Trajectory,
  type TrajectoryNode,
  type TrajectoryNodeData,
  type TrajectoryNodeType,
  type TrajectorySnapshot,
  type TrajectoryStats,
} from './TrajectoryStore';

export {
  TrajectoryProvider,
  useTrajectory,
  useTrajectoryActions,
} from './TrajectoryContext';
