export function orderedMembers(group: { members: string[]; matched?: string[]; order?: string[] }): string[] {
  const base = [...group.members, ...(group.matched ?? []).filter((id) => !group.members.includes(id))]
  const ordered = (group.order ?? []).filter((id, at, all) => base.includes(id) && all.indexOf(id) === at)
  return [...ordered, ...base.filter((id) => !ordered.includes(id))]
}

export function availableMembers(group: Parameters<typeof orderedMembers>[0], inactive: ReadonlySet<string>): string[] {
  return orderedMembers(group).filter((id) => !inactive.has(id))
}

/** Dragging visible members leaves each hidden member in its saved slot. */
export function reorderVisibleMembers(saved: string[], visible: string[], inactive: ReadonlySet<string>): string[] {
  let index = 0
  return saved.map((id) => inactive.has(id) ? id : (visible[index++] ?? id))
}
