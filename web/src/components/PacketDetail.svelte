<script lang="ts">
  import { getDetail, type Detail } from "../lib/api";

  let { num, onclose }: { num: number; onclose: () => void } = $props();

  let detail = $state<Detail | null>(null);
  let err = $state("");
  let open = $state<Set<string>>(new Set());

  $effect(() => {
    const n = num; // track
    detail = null;
    err = "";
    getDetail(n)
      .then((d) => {
        detail = d;
        open = new Set(d.layers.map((l) => l.name)); // expanded by default
      })
      .catch((e) => (err = String(e)));
  });

  function toggle(name: string) {
    const s = new Set(open);
    if (s.has(name)) s.delete(name);
    else s.add(name);
    open = s;
  }
</script>

<div class="panel">
  <div class="bar">
    <span>Paquet #{num}</span>
    <button onclick={onclose}>✕</button>
  </div>

  {#if err}
    <div class="err">⚠ {err}</div>
  {:else if !detail}
    <div class="muted pad">Décodage…</div>
  {:else}
    <div class="tree">
      {#each detail.layers as layer (layer.name)}
        <div class="layer">
          <div
            class="layer-head"
            onclick={() => toggle(layer.name)}
            onkeydown={(e) => e.key === "Enter" && toggle(layer.name)}
            role="button"
            tabindex="-1"
          >
            <span class="caret">{open.has(layer.name) ? "▾" : "▸"}</span>
            <span class="layer-name">{layer.name}</span>
          </div>
          {#if open.has(layer.name)}
            <div class="fields mono">
              {#each layer.fields as f}
                <div class="field">
                  <span class="fname">{f.name}</span>
                  <span class="fval">{f.value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <div class="hexhead">Octets bruts</div>
    <pre class="hex mono">{detail.hexDump}</pre>
  {/if}
</div>

<style>
  .panel {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: var(--panel);
  }
  .bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    flex-shrink: 0;
  }
  .tree {
    overflow: auto;
  }
  .layer-head {
    display: flex;
    gap: 6px;
    align-items: center;
    padding: 6px 12px;
    cursor: pointer;
    background: var(--panel-2);
    border-bottom: 1px solid var(--border);
  }
  .layer-head:hover {
    color: var(--accent);
  }
  .layer-name {
    font-weight: 600;
  }
  .caret {
    color: var(--muted);
    width: 12px;
  }
  .fields {
    padding: 4px 0;
  }
  .field {
    display: grid;
    grid-template-columns: 180px 1fr;
    gap: 10px;
    padding: 2px 12px 2px 30px;
    font-size: 12px;
  }
  .fname {
    color: var(--muted);
  }
  .fval {
    word-break: break-all;
  }
  .hexhead {
    padding: 6px 12px;
    color: var(--muted);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .hex {
    margin: 0;
    padding: 10px 12px;
    font-size: 11.5px;
    line-height: 1.45;
    overflow: auto;
    white-space: pre;
    color: #cbd5e1;
  }
  .pad {
    padding: 12px;
  }
  .muted {
    color: var(--muted);
  }
  .err {
    padding: 12px;
    color: #f87171;
  }
</style>
