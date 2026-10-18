import type { DesktopProjectContext } from '../agent/types';
export interface SelectionStamp {
  root: string;
  projectId: string;
  profileId: string;
  generation: number;
}
export function captureSelection(
  project: DesktopProjectContext | null,
  generation: number,
): SelectionStamp | null {
  return project
    ? {
        root: project.root,
        projectId: project.project_id,
        profileId: project.profile_id,
        generation,
      }
    : null;
}
export async function withCurrentSelection<T>(
  captured: SelectionStamp,
  current: () => SelectionStamp | null,
  operation: () => Promise<T>,
  apply: (response: T) => void | Promise<void>,
): Promise<boolean> {
  const response = await operation();
  const selected = current();
  if (
    !selected ||
    captured.root !== selected.root ||
    captured.projectId !== selected.projectId ||
    captured.profileId !== selected.profileId ||
    captured.generation !== selected.generation
  )
    return false;
  await apply(response);
  return true;
}
export function initialProjectSelection(
  projects: DesktopProjectContext[],
  selected: DesktopProjectContext | null,
): DesktopProjectContext | null {
  return selected ?? (projects.length === 1 ? projects[0]! : null);
}
