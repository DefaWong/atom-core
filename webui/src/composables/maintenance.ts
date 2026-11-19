import { computed, ref } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import { singleFlight } from '../flight'

export const maintenance = ref<Schemas['Maintenance'] | null>(null)
export const maintenanceError = ref('')
export const maintenanceBusy = computed(() => {
  const job = maintenance.value?.job
  return job !== undefined && (!job.done || job.blocking)
})

// One /maintenance request at a time: the shell's poll and the reset card's faster one share it, so a
// slow answer is waited for rather than dropped for a newer request that would be just as slow.
const flight = singleFlight(() => call(client.GET('/maintenance')), (outcome) => {
  if (!outcome.ok) {
    maintenanceError.value = describe(outcome.error)
    return
  }
  const next = outcome.value
  const previousVersion = maintenance.value?.version
  maintenance.value = next
  maintenanceError.value = ''
  if (previousVersion && next.version !== previousVersion) window.location.reload()
})

export function refreshMaintenance(): Promise<void> {
  return flight.run()
}

/** After a change made here: an answer already in flight may predate it, so ask again. */
export function refreshMaintenanceNow(): Promise<void> {
  flight.invalidate()
  return flight.run()
}

/** A job just started here: the answer in flight predates it, so it is dropped and the next refresh asks again. */
export function acceptMaintenanceJob(job: Schemas['MaintenanceJob']) {
  flight.invalidate()
  if (maintenance.value) maintenance.value = { ...maintenance.value, job }
}

export const phaseLabels: Record<Schemas['MaintenanceJob']['phase'], string> = {
  checking: '正在检查',
  downloading: '正在下载',
  validating: '正在校验',
  applying: '正在应用，服务可能短暂断开',
  awaiting_confirmation: '等待确认',
  restoring: '正在恢复',
  success: '已完成',
  failed: '操作失败',
  restored: '已恢复',
  recovery_failed: '恢复失败',
  preparing: '正在准备安装向导',
  awaiting_browser: '等待打开安装向导',
  resetting: '正在重置',
  reset: '已开始重置，请在安装向导中完成安装',
  cancelled: '已取消',
}
