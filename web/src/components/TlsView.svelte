<script lang="ts">
  import { decryptTls, type TlsSession } from "../lib/api";
  import { bytes } from "../lib/format";

  let sessions = $state<TlsSession[]>([]);
  let loaded = $state(false);
  let busy = $state(false);
  let err = $state("");
  let fileInput = $state<HTMLInputElement | null>(null);
  let fileName = $state("");

  async function onFile(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    fileName = file.name;
    busy = true;
    err = "";
    try {
      const text = await file.text();
      sessions = await decryptTls(text);
      loaded = true;
    } catch (e) {
      err = String(e);
    } finally {
      busy = false;
      input.value = "";
    }
  }

  let decryptedCount = $derived(sessions.filter((s) => s.decrypted).length);
</script>

<div class="wrap">
  <div class="bar">
    <button onclick={() => fileInput?.click()} disabled={busy}>
      {busy ? "Déchiffrement…" : "Charger un SSLKEYLOGFILE"}
    </button>
    <input
      bind:this={fileInput}
      type="file"
      accept=".log,.keys,.txt,*"
      style="display:none"
      onchange={onFile}
    />
    {#if fileName}<span class="muted mono">{fileName}</span>{/if}
    <span class="grow"></span>
    {#if loaded}
      <span class="muted">{decryptedCount}/{sessions.length} sessions déchiffrées</span>
    {/if}
  </div>

  {#if err}
    <div class="err">⚠ {err}</div>
  {/if}

  <div class="body">
    {#if !loaded}
      <div class="intro">
        <p>
          Charge un <b>SSLKEYLOGFILE</b> (format NSS) pour déchiffrer le TLS de la capture.
          Génère-le côté client en définissant la variable d'environnement
          <code class="mono">SSLKEYLOGFILE=/chemin/keys.log</code> avant de lancer le navigateur
          ou <code class="mono">curl</code>, puis recapture le trafic.
        </p>
        <p class="muted">
          Pris en charge dans cette version : <b>TLS 1.2</b> avec suites <b>AES-GCM</b>
          (la clé privée RSA seule ne suffit pas pour l'ECDHE/TLS 1.3 — d'où le key log).
        </p>
      </div>
    {:else if sessions.length === 0}
      <div class="intro muted">Aucune session TLS détectée dans la capture.</div>
    {:else}
      {#each sessions as s}
        <div class="session" class:ok={s.decrypted}>
          <div class="shead mono">
            <span class="flow">{s.client} → {s.server}</span>
            <span class="meta">{s.version} · {s.cipherSuite}</span>
            {#if s.decrypted}
              <span class="tag ok">déchiffré</span>
            {:else}
              <span class="tag ko" title={s.note}>non déchiffré</span>
            {/if}
          </div>
          {#if s.decrypted}
            <div class="panes">
              <div class="pane">
                <div class="plabel">Client → Serveur · {bytes(s.clientBytes)}</div>
                <pre class="mono">{s.clientText || "(vide)"}</pre>
              </div>
              <div class="pane">
                <div class="plabel">Serveur → Client · {bytes(s.serverBytes)}</div>
                <pre class="mono">{s.serverText || "(vide)"}</pre>
              </div>
            </div>
          {:else}
            <div class="note muted">{s.note}</div>
          {/if}
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
    gap: 12px;
    align-items: center;
    padding: 10px 14px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .grow {
    flex: 1;
  }
  .muted {
    color: var(--muted);
  }
  .body {
    flex: 1;
    overflow: auto;
    padding: 14px;
  }
  .intro {
    max-width: 720px;
    line-height: 1.5;
  }
  code {
    background: #0b1220;
    padding: 1px 5px;
    border-radius: 4px;
  }
  .session {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 12px;
    overflow: hidden;
  }
  .session.ok {
    border-color: #16623c;
  }
  .shead {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: 8px 12px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }
  .flow {
    font-weight: 600;
  }
  .meta {
    color: var(--muted);
  }
  .tag {
    margin-left: auto;
    padding: 1px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .tag.ok {
    background: #22c55e;
    color: #052e16;
  }
  .tag.ko {
    background: #475569;
    color: #e2e8f0;
  }
  .panes {
    display: grid;
    grid-template-columns: 1fr 1fr;
  }
  .pane {
    min-width: 0;
    border-right: 1px solid var(--border);
  }
  .pane:last-child {
    border-right: none;
  }
  .plabel {
    padding: 6px 12px;
    color: var(--muted);
    font-size: 11px;
    border-bottom: 1px solid #1b2536;
  }
  pre {
    margin: 0;
    padding: 10px 12px;
    font-size: 11.5px;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 320px;
    overflow: auto;
    color: #cbd5e1;
  }
  .note {
    padding: 10px 12px;
    font-size: 12px;
  }
  .err {
    padding: 12px 14px;
    color: #f87171;
  }
</style>
