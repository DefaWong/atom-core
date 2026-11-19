<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { toast } from '../composables/toast'

const emit = defineEmits<{ reset: [] }>()
const route = useRoute()
const tabs = [
  ['/dns', '概览'],
  ['/dns/logs', '日志'],
  ['/dns/upstreams', '上游'],
  ['/dns/settings', '高级设置']
] as const

const confirming = ref(false)
const busy = ref(false)
const error = ref('')
// The log emptied in this dialog: a retry after the counters failed only resets them.
const logCleared = ref(false)
function open() {
  confirming.value = true
  error.value = ''
  logCleared.value = false
}
// The statistics and rankings are computed from the query log; the cache and upstream
// counters are kept apart, so both are emptied.
async function reset() {
  busy.value = true
  error.value = ''
  try {
    if (!logCleared.value) {
      await call(client.POST('/audit/clear'))
      logCleared.value = true
    }
    await call(client.POST('/stats/reset'))
    confirming.value = false
    toast('ok', '统计已重置')
    emit('reset')
  } catch (failure) {
    error.value = logCleared.value ? `日志已清空，计数清零失败：${describe(failure)}` : describe(failure)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="row" style="justify-content: space-between">
    <nav class="tabs" aria-label="DNS">
      <RouterLink v-for="tab in tabs" :key="tab[0]" :to="tab[0]" :class="{ on: route.path === tab[0] }">{{ tab[1] }}</RouterLink>
    </nav>
    <button v-if="route.path === '/dns'" class="btn sm" type="button" @click="open">重置统计</button>
  </div>
  <AppModal v-if="confirming" title="重置统计" @close="confirming = false">
    <div>将清空查询日志，并把缓存命中和上游统计清零，此操作不可撤销。</div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button class="btn" type="button" @click="confirming = false">取消</button>
      <button class="btn red" type="button" :disabled="busy" @click="reset">重置</button>
    </template>
  </AppModal>
</template>
