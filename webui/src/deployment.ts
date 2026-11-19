// Where Atom runs, as the maintenance service reports it (composables/maintenance.ts). No imports, so `npm test` runs it directly.

/** The container version: updated by a new image, its network changed outside the panel. */
export function isContainer(overview: { deployment?: string } | null | undefined): boolean {
  return overview?.deployment === 'container'
}
