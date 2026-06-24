<script lang="ts">
  import {
    getLogs,
    getLogLevel,
    setDebug,
    logsTextUrl,
    getCrashes,
    getCrash,
    type LogEntry,
    type CrashInfo,
  } from "../lib/api";
  import { clock, levelColor } from "../lib/format";

  let entries = $state<LogEntry[]>([]);
  let level = $state("info");
  let debug = $state(false);
  let auto = $state(true);
  let err = $state("");
  let crashes = $state<CrashInfo[]>([]);
  let crashOpen = $state<string | null>(null);
  let crashBody = $state("");

  async function refresh() {
    try {
      entries = await getLogs(level, 1000);
      err = "";
    } catch (e) {
      err = String(e);
    }
  }

  async function loadLevel() {
    try {
      const l = await getLogLevel();
      debug = l.debug;
    } catch {
      /* ignore */
    }
  }

  async function loadCrashes() {
    try {
      crashes = await getCrashes();
    } catch {
      /* ignore */
    }
  }

  async function toggleDebug() {
    const l = await setDebug(!debug);
    debug = l.debug;
    refresh();
  }

  async function openCrash(name: string) {
    if (crashOpen === name) {
      crashOpen = null;
      return;
    }
    crashOpen = name;
    crashBody = "…";
    try {
      crashBody = await getCrash(name);
    } catch (e) {
      crashBody = String(e);
    }
  }

  // Initial load + poll when auto-refresh is on and this view is mounted.
  $effect(() => {
    loadLevel();
    loadCrashes();
    refresh();
  });

  $effect(() => {
    if (!auto) return;
    level; // re-arm when the level filter changes
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  });
</script>

<div class="wrap">
  <div class="bar">
    <label class="ctl">
      Niveau
      <select bind:value={level} onchange={refresh}>
        <option value="debug">debug+</option>
        <option value="info">info+</option>
        <option value="warn">warn+</option>
        <option value="error">error</option>
      </select>
    </label>

    <label class="ctl toggle" title="Capture les logs debug (sinon ils ne sont pas stockés)">
      <input type="checkbox" checked={debug} onchange={toggleDebug} />
      Debug
    </label>

    <label class="ctl toggle">
      <input type="checkbox" bind:checked={auto} />
      Auto-refresh
    </label>

    <button onclick={refresh}>Rafraîchir</button>
    <a class="btn" href={logsTextUrl(level)} download>Télécharger</a>

    <span class="grow"></span>
    <span class="muted">{entries.length} entrées</span>
  </div>

  {#if err}
    <div class="err">⚠ {err}</div>
  {/if}

  {#if crashes.length > 0}
    <div class="crashes">
      <div class="crash-head">⚠ {crashes.length} rapport(s) de crash</div>
      {#each crashes as c (c.name)}
        <div class="crash">
          <button class="crash-link" onclick={() => openCrash(c.name)}>
            {crashOpen === c.name ? "▾" : "▸"}
            {c.name} · {clock(c.time)} · {c.size} o
          </button>
          {#if crashOpen === c.name}
            <pre class="crash-body mono">{crashBody}</pre>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  <div class="logs mono">
    {#if entries.length === 0}
      <div class="empty">Aucune entrée à ce niveau.</div>
    {:else}
      {#each entries as e}
        <div class="row">
          <span class="time">{clock(e.time)}</span>
          <span class="lvl" style="color:{levelColor(e.level)}">{e.level}</span>
          <span class="msg">
            {e.message}
            {#if e.attrs}
              {#each Object.entries(e.attrs) as [k, v]}
                <span class="attr">{k}=<b>{String(v)}</b></span>
              {/each}
            {/if}
          </span>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .wrap {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .bar {
    display: flex;
    gap: 14px;
    align-items: center;
    padding: 10px 14px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .ctl {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--muted);
  }
  .ctl.toggle {
    cursor: pointer;
  }
  select {
    font: inherit;
    color: var(--text);
    background: #0b1220;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 8px;
  }
  .btn {
    font: inherit;
    color: var(--text);
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 10px;
    text-decoration: none;
  }
  .btn:hover {
    border-color: var(--accent);
  }
  .grow {
    flex: 1;
  }
  .muted {
    color: var(--muted);
  }
  .logs {
    flex: 1;
    overflow: auto;
    padding: 6px 0;
    font-size: 12px;
  }
  .row {
    display: grid;
    grid-template-columns: 110px 56px 1fr;
    gap: 10px;
    padding: 2px 14px;
    border-bottom: 1px solid #161f30;
  }
  .row:hover {
    background: var(--panel-2);
  }
  .time {
    color: var(--muted);
  }
  .lvl {
    font-weight: 700;
  }
  .msg {
    word-break: break-word;
  }
  .attr {
    color: var(--muted);
    margin-left: 8px;
  }
  .attr b {
    color: var(--text);
    font-weight: 600;
  }
  .empty,
  .err {
    padding: 16px;
    color: var(--muted);
  }
  .err {
    color: #f87171;
  }
  .crashes {
    border-bottom: 1px solid var(--border);
    background: #2a1416;
    padding: 8px 14px;
  }
  .crash-head {
    color: #fca5a5;
    font-weight: 600;
    margin-bottom: 6px;
  }
  .crash-link {
    background: none;
    border: none;
    color: #fecaca;
    cursor: pointer;
    padding: 2px 0;
    font: inherit;
    text-align: left;
  }
  .crash-body {
    margin: 6px 0;
    padding: 10px;
    background: #0b1220;
    border-radius: 6px;
    font-size: 11.5px;
    white-space: pre-wrap;
    max-height: 320px;
    overflow: auto;
    color: #cbd5e1;
  }
</style>
