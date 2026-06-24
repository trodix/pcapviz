<script lang="ts">
  import { getMemInfo, type MemInfo } from "../lib/api";
  import { bytes } from "../lib/format";

  let mem = $state<MemInfo | null>(null);
  let down = $state(false);

  $effect(() => {
    const tick = async () => {
      try {
        mem = await getMemInfo();
        down = false;
      } catch {
        down = true;
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => clearInterval(id);
  });
</script>

<footer class="statusbar mono">
  {#if mem}
    <span title="Resident Set Size — mémoire physique utilisée par le process pcapviz">
      🧠 Mémoire <b>{bytes(mem.rss || mem.sys)}</b>
    </span>
    <span class="sep">·</span>
    <span title="Heap Go actuellement alloué">heap {bytes(mem.heapAlloc)}</span>
    <span class="sep">·</span>
    <span title="Goroutines actives">{mem.numGoroutine} goroutines</span>
  {:else if down}
    <span class="off">● serveur injoignable</span>
  {:else}
    <span class="muted">…</span>
  {/if}
  <span class="grow"></span>
  <span class="muted">pcapviz</span>
</footer>

<style>
  .statusbar {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 12px;
    background: var(--panel);
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
  }
  .statusbar b {
    color: var(--text);
    font-weight: 600;
  }
  .sep {
    opacity: 0.4;
  }
  .grow {
    flex: 1;
  }
  .muted {
    color: var(--muted);
  }
  .off {
    color: #f87171;
  }
</style>
