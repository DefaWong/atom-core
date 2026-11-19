// Which groups a node deletion leaves empty (pages/NodesPage.vue). No imports, so `npm test` runs it directly.
// It follows the host's `empty_groups` on the state the kernel runs (atom_proxy.rs: `effective`, `group_empty`,
// `uses_providers`), counting direct members only: a group whose only member is a group emptied here is not named.

export interface GroupLike {
  id: string
  /** Its own members: node IDs, group IDs or subscription nodes (`p-xxxxxxxx/name`). */
  members: string[]
  /** The nodes its filter matched. */
  matched?: string[] | null
  providers?: string[] | null
  all_providers?: boolean | null
  /** Already empty before the deletion (the host's warning covers it). */
  empty?: boolean
}

export interface DeletionContext {
  groups: readonly GroupLike[]
  final?: { members: string[]; empty?: boolean } | null
  /** Nodes the kernel cannot run: the host leaves them out of every group, so they count as no member. */
  inactive: ReadonlySet<string>
  /** The saved subscriptions' IDs. */
  providers: readonly string[]
  /** Subscriptions only feed groups under mihomo; under sing-box a group needs members of its own. */
  mihomo: boolean
}

/** The ID used for Final in the result. */
export const FINAL_ID = 'final'

/** Whether the group draws members from subscriptions (`uses_providers`). */
export function usesProviders(group: GroupLike, providers: readonly string[]): boolean {
  return (group.providers?.length ?? 0) > 0 || (!!group.all_providers && providers.length > 0)
}

/**
 * The groups (and Final, as `FINAL_ID`) that have a member now and none once `deleting` is gone: no remaining
 * member the kernel runs, and no subscription to draw from.
 */
export function emptiedBy(deleting: ReadonlySet<string>, context: DeletionContext): string[] {
  if (!deleting.size) return []
  const counts = (id: string) => !deleting.has(id) && !context.inactive.has(id)
  const emptied: string[] = []
  for (const group of context.groups) {
    if (group.empty) continue
    if (context.mihomo && usesProviders(group, context.providers)) continue
    const members = [...group.members, ...(group.matched ?? [])]
    if (!members.some((id) => deleting.has(id))) continue
    if (!members.some(counts)) emptied.push(group.id)
  }
  const final = context.final
  if (final && !final.empty && final.members.some((id) => deleting.has(id)) && !final.members.some(counts)) emptied.push(FINAL_ID)
  return emptied
}
