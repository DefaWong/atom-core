<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { lines, loadRulesets, parseNames, type Builtin, type Ruleset } from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

/** A new custom ruleset, an edit of one, or a builtin set's source (address and automatic update). */
const props = defineProps<{ mode: 'new' | 'edit' | 'builtin'; target?: Ruleset | Builtin }>()
const emit = defineEmits<{ close: [] }>()

const FORMATS = ['auto', 'text', 'yaml', 'json', 'srs', 'mrs', 'dat']
const custom = props.target && props.target.type !== 'builtin' ? (props.target as Ruleset) : undefined
const builtin = props.target?.type === 'builtin' ? (props.target as Builtin) : undefined
const form = reactive({
  type: (custom?.type === 'local' ? 'local' : 'remote') as 'remote' | 'local',
  name: props.target?.name ?? '',
  url: props.target?.url ?? '',
  format: custom?.format || 'auto',
  category: custom?.category ?? '',
  text: '',
  autoUpdate: builtin?.auto_update ?? false,
  hours: builtin?.update_interval_hours ?? 24
})
const error = ref('')
const busy = ref(false)
const loading = ref(false)
// A local list being edited must have been read: saving sends the whole list.
const loadedText = ref('')
const listRead = ref(!(props.mode === 'edit' && custom?.type === 'local'))

async function readList() {
  if (listRead.value || !custom) return
  loading.value = true
  error.value = ''
  try {
    const set = (await call(client.GET('/rulesets/{id}', { params: { path: { id: custom.id } } }))) as { rules?: string[] }
    form.text = (set.rules ?? []).join('\n')
    loadedText.value = form.text
    listRead.value = true
  } catch (failure) {
    error.value = `读取名单失败：${describe(failure)}`
  } finally {
    loading.value = false
  }
}
onMounted(readList)

const stats = () => {
  const parsed = parseNames(form.text)
  return parsed.bad.length ? `无法识别：${parsed.bad.slice(0, 3).join('、')}` : `${parsed.count} 条`
}

async function submit() {
  error.value = ''
  busy.value = true
  try {
    if (props.mode === 'builtin' && builtin) {
      if (form.autoUpdate && !(Number.isInteger(form.hours) && form.hours >= 1 && form.hours <= 8760)) throw new Error('更新周期是 1 到 8760 小时')
      // Only what changed is sent; a new address is downloaded at once.
      const body: { url?: string; auto_update?: boolean; update_interval_hours?: number } = {}
      if (form.url.trim() !== (builtin.url ?? '')) body.url = form.url.trim()
      if (form.autoUpdate !== builtin.auto_update) body.auto_update = form.autoUpdate
      if (form.autoUpdate && form.hours !== builtin.update_interval_hours) body.update_interval_hours = form.hours
      if (Object.keys(body).length) await call(client.PUT('/rulesets/{id}', { params: { path: { id: builtin.id } }, body }))
      toast('ok', body.url !== undefined ? '已保存并下载' : '已保存')
    } else {
      if (form.type === 'local' && parseNames(form.text).bad.length) throw new Error(stats())
      const source =
        form.type === 'remote'
          ? { type: 'remote' as const, url: form.url.trim(), format: form.format, ...(form.format === 'dat' ? { category: form.category.trim() } : {}) }
          : { type: 'local' as const, rules: lines(form.text) }
      if (props.mode === 'new') await call(client.POST('/rulesets', { body: { name: form.name.trim(), ...source } }))
      else if (custom) {
        // Rulesets carry no version: only what changed here is sent, so a change made elsewhere
        // to the rest (its address, say) is not put back.
        const body: Record<string, unknown> = {}
        if (form.name.trim() !== custom.name) body.name = form.name.trim()
        const sourceChanged =
          form.type === 'remote'
            ? form.url.trim() !== (custom.url ?? '') || form.format !== (custom.format || 'auto') || (form.format === 'dat' && form.category.trim() !== (custom.category ?? ''))
            : form.text !== loadedText.value
        if (sourceChanged) Object.assign(body, source)
        if (Object.keys(body).length) await call(client.PUT('/rulesets/{id}', { params: { path: { id: custom.id } }, body }))
      }
      toast('ok', '已保存')
    }
    emit('close')
  } catch (failure) {
    // 502: saved, but the download failed (the old list stays).
    if (failure instanceof ApiError && failure.status === 502) {
      toast('warn', `已保存，但下载失败：${failure.message}`)
      emit('close')
    } else {
      error.value = failure instanceof ApiError ? describe(failure) : failure instanceof Error ? failure.message : String(failure)
    }
  } finally {
    busy.value = false
    await loadRulesets().catch(() => {})
    refreshStatus().catch(() => {})
  }
}

const titles = { new: '新建规则集', edit: '编辑规则集', builtin: '编辑默认规则集' }
</script>

<template>
  <AppModal :dismissible="false" :title="`${titles[mode]}${target ? ` · ${target.name}` : ''}`" @close="emit('close')">
    <div v-if="mode === 'new'" class="seg" style="align-self: flex-start">
      <button type="button" :class="{ on: form.type === 'remote' }" @click="form.type = 'remote'">远程订阅</button>
      <button type="button" :class="{ on: form.type === 'local' }" @click="form.type = 'local'">本地列表</button>
    </div>
    <div v-if="mode !== 'builtin'" class="field">
      <label for="rsname">名称</label>
      <input id="rsname" v-model="form.name" class="inp" autocomplete="off" />
    </div>
    <template v-if="mode === 'builtin' || form.type === 'remote'">
      <div class="field">
        <label for="rsurl">URL</label>
        <input id="rsurl" v-model="form.url" class="inp mono" placeholder="https://…" autocomplete="off" />
      </div>
      <div v-if="mode !== 'builtin'" class="row">
        <div class="field">
          <label for="rsfmt">格式</label>
          <select id="rsfmt" v-model="form.format" class="inp" style="width: auto">
            <option v-for="format in FORMATS" :key="format" :value="format">{{ format }}</option>
          </select>
        </div>
        <div v-if="form.format === 'dat'" class="field" style="flex: 1">
          <label for="rscat">分类</label>
          <input id="rscat" v-model="form.category" class="inp mono" placeholder="例如 cn" autocomplete="off" />
        </div>
      </div>
    </template>
    <template v-if="mode === 'builtin'">
      <div class="row">
        <div style="flex: 1">自动更新</div>
        <button class="sw" type="button" :class="{ on: form.autoUpdate }" :aria-pressed="form.autoUpdate" aria-label="自动更新" @click="form.autoUpdate = !form.autoUpdate"></button>
      </div>
      <div v-if="form.autoUpdate" class="field">
        <label for="rshours">更新周期（小时）</label>
        <input id="rshours" v-model.number="form.hours" class="inp" type="number" min="1" max="8760" step="1" style="width: 120px" />
      </div>
    </template>
    <div v-if="mode !== 'builtin' && form.type === 'local'" class="field">
      <label for="rstext">名单</label>
      <textarea id="rstext" v-model="form.text" class="inp" style="min-height: 160px" :disabled="loading" placeholder="domain:example.com&#10;full:www.example.com&#10;keyword:tracker&#10;regexp:^ads?\d*\."></textarea>
      <span class="hint" :style="{ color: parseNames(form.text).bad.length ? 'var(--bad)' : '' }">{{ stats() }}</span>
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button v-if="!listRead && !loading" class="btn" type="button" @click="readList">重新读取</button>
      <button class="btn" type="button" @click="emit('close')">取消</button>
      <button class="btn pri" type="button" :disabled="busy || loading || (form.type === 'local' && !listRead) || (form.type === 'remote' && !form.url.trim())" @click="submit">保存</button>
    </template>
  </AppModal>
</template>
