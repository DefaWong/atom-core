<script setup lang="ts">
import { computed, ref } from 'vue'
import { call, client, describe } from '../api/client'
import AppModal from '../components/AppModal.vue'
import SettingsTabs from '../components/SettingsTabs.vue'
import ResetCard from '../components/ResetCard.vue'
import UpdateCard from '../components/UpdateCard.vue'
import { containerDeployment, maintenance } from '../composables/maintenance'
import { usePoll } from '../composables/poll'
import { backendName, backendVersion, isMihomo, status } from '../composables/status'
import { toast } from '../composables/toast'

type Service = 'atom-maintenance' | 'atom-dns' | 'atom-sing-box' | 'atom-mihomo'
type State = 'running' | 'stopped' | 'failed' | 'unknown'

const states = ref<Partial<Record<Service, State>>>({})
const statesError = ref('')
async function loadStates() {
  try {
    const answer = await call(client.GET('/maintenance/services'))
    states.value = Object.fromEntries(answer.services.map((item) => [item.name, item.state]))
    statesError.value = ''
  } catch (failure) {
    states.value = {}
    statesError.value = `读取运行状态失败：${describe(failure)}`
  }
}
usePoll(loadStates, 10000)

// The proxy kernel's row only once the current kernel is known.
const kernel = computed<Service | null>(() => (status.value?.backend ? (isMihomo.value ? 'atom-mihomo' : 'atom-sing-box') : null))
const rows = computed<{ service: Service; name: string; version: string }[]>(() => [
  // The container has no separate maintenance service: its entry process answers for it.
  ...(containerDeployment.value ? [] : [{ service: 'atom-maintenance' as Service, name: 'Atom 维护服务', version: maintenance.value?.version ?? '' }]),
  { service: 'atom-dns', name: 'AtomDNS', version: status.value?.atomdns.version ?? '' },
  ...(kernel.value ? [{ service: kernel.value, name: backendName.value, version: backendVersion.value }] : [])
])
const stateText: Record<State, [string, string]> = {
  running: ['ok', '运行中'],
  stopped: ['warn', '已停止'],
  failed: ['bad', '失败'],
  unknown: ['idle', '未知']
}

const restarting = ref<{ service: Service; name: string } | null>(null)
const restartBusy = ref(false)
const restartError = ref('')
const restartText = computed(() => {
  const target = restarting.value
  if (!target) return ''
  if (target.service === 'atom-dns') return '重启期间面板和 DNS 会中断几秒，页面稍后自动恢复。'
  if (target.service === 'atom-maintenance') return '重启期间无法检查更新和修改网络设置。'
  return `重启期间经 ${target.name} 的代理连接会中断几秒。`
})
async function restart() {
  const target = restarting.value
  if (!target) return
  restartError.value = ''
  if ((target.service === 'atom-sing-box' || target.service === 'atom-mihomo') && target.service !== kernel.value) {
    restartError.value = `当前内核已不是 ${target.name}`
    return
  }
  restartBusy.value = true
  try {
    await call(client.POST('/maintenance/restart', { body: { service: target.service } }))
    restarting.value = null
    toast('ok', `正在重启 ${target.name}`)
    setTimeout(() => void loadStates(), 3000)
  } catch (failure) {
    restartError.value = describe(failure)
  } finally {
    restartBusy.value = false
  }
}
</script>

<template>
  <SettingsTabs />
  <UpdateCard />
  <section class="card grid" style="gap: 12px">
    <h2>组件</h2>
    <div v-if="statesError" class="err">{{ statesError }}</div>
    <div class="tblwrap">
      <table>
        <thead>
          <tr><th>名称</th><th>版本号</th><th>运行状态</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.service">
            <td>{{ row.name }}</td>
            <td class="mono">{{ row.version || '—' }}</td>
            <td>
              <span v-if="states[row.service]" class="pill" :class="stateText[states[row.service]!][0]"><span class="dot"></span>{{ stateText[states[row.service]!][1] }}</span>
              <span v-else class="t2">—</span>
            </td>
            <td style="text-align: right">
              <button class="btn sm" type="button" :disabled="!states[row.service]" @click="((restarting = { service: row.service, name: row.name }), (restartError = ''))">重启</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
  <ResetCard v-if="maintenance" />
  <AppModal v-if="restarting" :title="`重启 ${restarting.name}`" @close="restarting = null">
    <div>{{ restartText }}</div>
    <div v-if="restartError" class="err">{{ restartError }}</div>
    <template #footer>
      <button class="btn" type="button" @click="restarting = null">取消</button>
      <button class="btn red" type="button" :disabled="restartBusy" @click="restart">重启</button>
    </template>
  </AppModal>
</template>
