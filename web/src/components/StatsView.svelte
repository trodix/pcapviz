<script lang="ts">
  import { getStats, type Stats } from "../lib/api";
  import { bytes, protoColor } from "../lib/format";

  let stats = $state<Stats | null>(null);
  let err = $state("");

  $effect(() => {
    getStats()
      .then((s) => (stats = s))
      .catch((e) => (err = String(e)));
  });

  let maxBucket = $derived(
    stats ? Math.max(1, ...stats.timeline.map((b) => b.packets)) : 1,
  );
  let protoMax = $derived(
    stats ? Math.max(1, ...stats.protocols.map((p) => p.packets)) : 1,
  );
</script>

{#if err}
  <div class="err">⚠ {err}</div>
{:else if !stats}
  <div class="muted pad">Calcul…</div>
{:else}
  <div class="grid">
    <section class="card span2">
      <h3>Vue d'ensemble</h3>
      <div class="kpis">
        <div class="kpi"><b>{stats.totalPackets}</b><span>paquets</span></div>
        <div class="kpi"><b>{bytes(stats.totalBytes)}</b><span>volume</span></div>
        <div class="kpi"><b>{stats.protocols.length}</b><span>protocoles</span></div>
        <div class="kpi"><b>{stats.conversations.length}</b><span>conversations</span></div>
      </div>
      <div class="timeline">
        {#each stats.timeline as b}
          <div
            class="tbar"
            style="height:{(b.packets / maxBucket) * 100}%"
            title="{b.packets} paquets / {bytes(b.bytes)}"
          ></div>
        {/each}
      </div>
      <div class="muted small">Timeline du trafic (paquets par tranche)</div>
    </section>

    <section class="card">
      <h3>Protocoles</h3>
      {#each stats.protocols as p}
        <div class="bar-row">
          <span class="badge" style="background:{protoColor(p.proto)}">{p.proto}</span>
          <div class="bar-track">
            <div
              class="bar-fill"
              style="width:{(p.packets / protoMax) * 100}%; background:{protoColor(p.proto)}"
            ></div>
          </div>
          <span class="num mono">{p.packets}</span>
        </div>
      {/each}
    </section>

    <section class="card">
      <h3>Top talkers</h3>
      <table>
        <thead><tr><th>Adresse</th><th>Paquets</th><th>Volume</th></tr></thead>
        <tbody>
          {#each stats.topTalkers as t}
            <tr>
              <td class="mono">{t.addr}</td>
              <td class="num">{t.packets}</td>
              <td class="num">{bytes(t.bytes)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>

    <section class="card span2">
      <h3>Conversations</h3>
      <table>
        <thead><tr><th>Point A</th><th>Point B</th><th>Proto</th><th>Paquets</th><th>Volume</th></tr></thead>
        <tbody>
          {#each stats.conversations as c}
            <tr>
              <td class="mono">{c.a}</td>
              <td class="mono">{c.b}</td>
              <td><span class="badge" style="background:{protoColor(c.proto)}">{c.proto}</span></td>
              <td class="num">{c.packets}</td>
              <td class="num">{bytes(c.bytes)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    padding: 14px;
  }
  .span2 {
    grid-column: 1 / -1;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
  }
  h3 {
    margin: 0 0 12px;
    font-size: 13px;
    color: var(--accent);
  }
  .kpis {
    display: flex;
    gap: 24px;
    margin-bottom: 14px;
  }
  .kpi {
    display: flex;
    flex-direction: column;
  }
  .kpi b {
    font-size: 22px;
  }
  .kpi span {
    color: var(--muted);
    font-size: 11px;
  }
  .timeline {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 90px;
    background: #0b1220;
    border-radius: 6px;
    padding: 6px;
  }
  .tbar {
    flex: 1;
    min-height: 1px;
    background: var(--accent);
    border-radius: 2px 2px 0 0;
    opacity: 0.85;
  }
  .small {
    font-size: 11px;
    margin-top: 6px;
  }
  .bar-row {
    display: grid;
    grid-template-columns: 70px 1fr 50px;
    gap: 10px;
    align-items: center;
    margin-bottom: 6px;
  }
  .bar-track {
    background: #0b1220;
    border-radius: 4px;
    height: 14px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 4px;
  }
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    color: #04263a;
    font-weight: 700;
    font-size: 10px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    border-bottom: 1px solid var(--border);
    padding: 4px 8px;
  }
  td {
    padding: 4px 8px;
    border-bottom: 1px solid #1b2536;
  }
  .num {
    text-align: right;
  }
  .pad {
    padding: 14px;
  }
  .muted {
    color: var(--muted);
  }
  .err {
    padding: 14px;
    color: #f87171;
  }
</style>
