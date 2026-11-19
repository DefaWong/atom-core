<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { acceptMaintenanceJob, maintenance, maintenanceBusy, phaseLabels, refreshMaintenance } from '../composables/maintenance'
import { RESET_WORD, wizardURL } from '../reset'

const job = computed(() => maintenance.value?.job)
const resetJob = computed(() => job.value?.kind === 'reset' ? job.value : undefined)
const confirming = ref(false)
const word = ref('')
const busy = ref(false)
const error = ref('')
// Only the tab that asked for the reset goes to the wizard by itself; another one shows the link.
const mine = ref('')

const wizard = computed(() => {
  const value = resetJob.value
  if (!value || value.done || value.phase !== 'awaiting_browser' || !value.wizard_port || !value.wizard_code) return ''
  return wizardURL(window.location, value.wizard_port, value.wizard_code, value.wizard_urls ?? [])
})
const deadline = computed(() => resetJob.value?.deadline && !resetJob.value.done ?
  new Date(resetJob.value.deadline).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '')

// The wizard is ready within seconds: follow the job faster than the shell's poll while it waits.
let timer: ReturnType<typeof setInterval> | undefined
watch(() => !!resetJob.value && !resetJob.value.done, (open) => {
  clearInterval(timer)
  timer = open ? setInterval(() => void refreshMaintenance(), 1000) : undefined
}, { immediate: true })
onUnmounted(() => clearInterval(timer))

watch(wizard, (url) => {
  if (url && mine.value === resetJob.value?.id) window.location.assign(url)
})

function open() {
  word.value = ''
  error.value = ''
  confirming.value = true
}

async function reset() {
  if (word.value.trim() !== RESET_WORD || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const next = await call(client.POST('/maintenance/reset', { body: {} }))
    mine.value = next.id
    acceptMaintenanceJob(next)
    confirming.value = false
  } catch (failure) {
    error.value = describe(failure)
    void refreshMaintenance()
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card grid" style="gap: 12px">
    <div class="hd" style="margin: 0">
      <h2>重置所有设置</h2>
      <span class="sp"></span>
      <button type="button" class="btn danger sm" :disabled="busy || maintenanceBusy" @click="open">重置…</button>
    </div>
    <div class="t2">删除全部规则、节点、订阅和设置，从头运行安装向导。</div>
    <div v-if="resetJob" class="grid" style="gap: 7px" aria-live="polite">
      <div>{{ phaseLabels[resetJob.phase] }}</div>
      <div v-if="resetJob.error" class="err">{{ resetJob.error }}</div>
      <template v-if="wizard">
        <div class="t2">正在跳转到安装向导。{{ deadline }} 前没有打开会自动取消，不做任何更改。</div>
        <div class="row"><a class="btn pri sm" :href="wizard">打开安装向导</a></div>
      </template>
    </div>
    <div v-if="error && !confirming" class="err">{{ error }}</div>
  </section>

  <AppModal v-if="confirming" title="重置所有设置" @close="confirming = false">
    <div class="warnbox">Atom 将恢复为刚安装前的状态，此操作不能撤销。</div>
    <ul class="reset-list">
      <li>删除全部规则、节点、订阅、DNS 上游和其他设置，包括面板登录。</li>
      <li>还原安装时改过的系统设置，移除 Atom 的服务和防火墙规则。</li>
      <li>从开始重置到安装向导完成前，局域网的 DNS 和代理不可用，网络会中断。</li>
      <li>当前数据先备份到 <span class="mono">/opt/atom/backup/reset-时间</span>，不会自动恢复。</li>
      <li>确认后跳转到安装向导，在浏览器打开向导后才开始重置；3 分钟内没有打开则取消。重置后 30 分钟内没有完成安装，将按原来的网络、面板端口和登录，其余用默认配置自动安装。</li>
    </ul>
    <form class="field" @submit.prevent="reset">
      <label for="atom-reset-word">输入「{{ RESET_WORD }}」确认</label>
      <input id="atom-reset-word" v-model="word" class="inp" autocomplete="off" spellcheck="false" />
    </form>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button class="btn" type="button" @click="confirming = false">取消</button>
      <button class="btn red" type="button" :disabled="busy || word.trim() !== RESET_WORD" @click="reset">重置并打开安装向导</button>
    </template>
  </AppModal>
</template>

<style scoped>
.reset-list {
  margin: 0;
  padding-left: 18px;
  display: grid;
  gap: 6px;
  font-size: 13px;
}
</style>
