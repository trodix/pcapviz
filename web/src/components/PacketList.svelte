<script lang="ts">
  import { listPackets, type Packet } from "../lib/api";
  import { clock, protoColor } from "../lib/format";

  let {
    filter,
    selected,
    onselect,
  }: { filter: string; selected: number | null; onselect: (n: number) => void } = $props();

  const PAGE = 200;
  const ROW = 26;

  let total = $state(0);
  let cache = $state(new Map<number, Packet>());
  let pending = new Set<number>();
  let scrollTop = $state(0);
  let viewportH = $state(600);
  let container = $state<HTMLDivElement | null>(null);
  let err = $state("");

  async function loadPage(pageIdx: number, f: string) {
    if (pending.has(pageIdx)) return;
    pending.add(pageIdx);
    try {
      const res = await listPackets(f, pageIdx * PAGE, PAGE);
      total = res.total;
      const m = new Map(cache);
      res.items.forEach((p, i) => m.set(pageIdx * PAGE + i, p));
      cache = m;
    } catch (e) {
      err = String(e);
    } finally {
      pending.delete(pageIdx);
    }
  }

  // Reset and reload whenever the active filter changes.
  $effect(() => {
    filter; // track
    cache = new Map();
    total = 0;
    pending.clear();
    err = "";
    if (container) container.scrollTop = 0;
    scrollTop = 0;
    loadPage(0, filter);
  });

  let startIdx = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 6));
  let endIdx = $derived(Math.min(total, Math.ceil((scrollTop + viewportH) / ROW) + 6));

  // Ensure pages covering the visible window are loaded.
  $effect(() => {
    if (total === 0) return;
    const first = Math.floor(startIdx / PAGE);
    const last = Math.floor(Math.max(startIdx, endIdx - 1) / PAGE);
    for (let p = first; p <= last; p++) {
      if (!cache.has(p * PAGE) && !pending.has(p)) loadPage(p, filter);
    }
  });

  let rows = $derived.by(() => {
    const out: { i: number; p: Packet | undefined }[] = [];
    for (let i = startIdx; i < endIdx; i++) out.push({ i, p: cache.get(i) });
    return out;
  });

  function onScroll() {
    if (container) scrollTop = container.scrollTop;
  }
</script>

<div class="wrap">
  <div class="head mono">
    <span class="c-num">#</span>
    <span class="c-time">Heure</span>
    <span class="c-addr">Source</span>
    <span class="c-addr">Destination</span>
    <span class="c-proto">Proto</span>
    <span class="c-len">Len</span>
    <span class="c-info">Info</span>
  </div>

  {#if err}
    <div class="err">⚠ {err}</div>
  {/if}

  <div class="body" bind:this={container} bind:clientHeight={viewportH} onscroll={onScroll}>
    {#if total === 0}
      <div class="empty">Aucun paquet ne correspond.</div>
    {:else}
      <div class="spacer" style="height:{total * ROW}px;">
        {#each rows as row (row.i)}
          <div
            class="row mono"
            class:selected={row.p && row.p.num === selected}
            style="top:{row.i * ROW}px; height:{ROW}px;"
            onclick={() => row.p && onselect(row.p.num)}
            onkeydown={(e) => e.key === "Enter" && row.p && onselect(row.p.num)}
            role="button"
            tabindex="-1"
          >
            {#if row.p}
              <span class="c-num">{row.p.num}</span>
              <span class="c-time">{clock(row.p.time)}</span>
              <span class="c-addr" title={row.p.src}>{row.p.src}</span>
              <span class="c-addr" title={row.p.dst}>{row.p.dst}</span>
              <span class="c-proto">
                <span class="badge" style="background:{protoColor(row.p.proto)}">{row.p.proto}</span>
              </span>
              <span class="c-len">{row.p.length}</span>
              <span class="c-info" title={row.p.info}>{row.p.info}</span>
            {:else}
              <span class="c-num muted">{row.i + 1}</span>
              <span class="loading muted">…</span>
            {/if}
          </div>
        {/each}
      </div>
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
  .head,
  .row {
    display: grid;
    grid-template-columns: 64px 110px 1fr 1fr 70px 56px 2.4fr;
    gap: 8px;
    align-items: center;
    padding: 0 10px;
    white-space: nowrap;
  }
  .head {
    height: 30px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }
  .body {
    flex: 1;
    overflow-y: auto;
    position: relative;
    min-height: 0;
  }
  .spacer {
    position: relative;
    width: 100%;
  }
  .row {
    position: absolute;
    left: 0;
    right: 0;
    cursor: pointer;
    border-bottom: 1px solid #1b2536;
    font-size: 12px;
  }
  .row:hover {
    background: var(--panel-2);
  }
  .row.selected {
    background: #0c3a52;
  }
  .c-len {
    text-align: right;
  }
  .c-addr,
  .c-info {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    color: #04263a;
    font-weight: 700;
    font-size: 10px;
  }
  .muted {
    color: var(--muted);
  }
  .empty,
  .err {
    padding: 16px;
    color: var(--muted);
  }
  .err {
    color: #f87171;
  }
</style>
