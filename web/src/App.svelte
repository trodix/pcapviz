<script lang="ts">
  import { getStatus, uploadFile } from "./lib/api";
  import PacketList from "./components/PacketList.svelte";
  import PacketDetail from "./components/PacketDetail.svelte";
  import StatsView from "./components/StatsView.svelte";
  import LogsView from "./components/LogsView.svelte";

  let loaded = $state(false);
  let count = $state(0);
  let view: "packets" | "stats" | "logs" = $state("packets");
  let filterInput = $state("");
  let activeFilter = $state("");
  let selected = $state<number | null>(null);
  let error = $state("");
  let busy = $state(false);
  let fileInput = $state<HTMLInputElement | null>(null);

  async function refresh() {
    const s = await getStatus();
    loaded = s.loaded;
    count = s.count;
  }
  refresh();

  async function onFile(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    error = "";
    busy = true;
    try {
      await uploadFile(file);
      selected = null;
      await refresh();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
      input.value = "";
    }
  }

  function applyFilter() {
    activeFilter = filterInput.trim();
    selected = null;
    error = "";
  }

  function onFilterKey(e: KeyboardEvent) {
    if (e.key === "Enter") applyFilter();
  }
</script>

<div class="toolbar">
  <span class="brand">pcapviz</span>
  <button onclick={() => fileInput?.click()} disabled={busy}>
    {busy ? "Chargement…" : "Ouvrir un .pcap"}
  </button>
  <input
    bind:this={fileInput}
    type="file"
    accept=".pcap,.pcapng,.cap"
    style="display:none"
    onchange={onFile}
  />

  {#if loaded}
    <input
      type="text"
      class="mono grow"
      placeholder="Filtre — ex: tcp.port == 443 && ip.addr == 10.0.0.1"
      bind:value={filterInput}
      onkeydown={onFilterKey}
    />
    <button onclick={applyFilter}>Filtrer</button>
    <button class:active={view === "packets"} onclick={() => (view = "packets")}>Paquets</button>
    <button class:active={view === "stats"} onclick={() => (view = "stats")}>Statistiques</button>
  {:else}
    <span class="grow muted">Aucune capture chargée. Ouvrez un fichier .pcap / .pcapng.</span>
  {/if}
  <button class:active={view === "logs"} onclick={() => (view = "logs")} title="Logs & rapports de crash">Logs</button>
  {#if loaded}<span class="muted">{count} paquets</span>{/if}
</div>

{#if error}
  <div class="error">⚠ {error}</div>
{/if}

{#if view === "logs"}
  <div style="flex:1; min-height:0;">
    <LogsView />
  </div>
{:else if loaded}
  {#if view === "packets"}
    <div style="flex:1; display:flex; min-height:0;">
      <div style="flex:1; min-width:0; border-right:1px solid var(--border);">
        <PacketList filter={activeFilter} onselect={(n) => (selected = n)} {selected} />
      </div>
      {#if selected !== null}
        <div style="width:40%; min-width:340px; overflow:auto;">
          <PacketDetail num={selected} onclose={() => (selected = null)} />
        </div>
      {/if}
    </div>
  {:else}
    <div style="flex:1; overflow:auto;">
      <StatsView />
    </div>
  {/if}
{:else}
  <div style="flex:1; display:flex; align-items:center; justify-content:center; color:var(--muted);">
    <div style="text-align:center;">
      <p style="font-size:15px;">Glissez ou ouvrez un fichier de capture pour commencer.</p>
      <button onclick={() => fileInput?.click()}>Choisir un fichier…</button>
    </div>
  </div>
{/if}
