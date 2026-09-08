/* ═══════════════════════════════════════════════════════════════════════════
   KRAKEN GUI -- Alpine.js Application
   ═══════════════════════════════════════════════════════════════════════════ */

function app() {
  return {
    // ── Navigation ──
    view: 'dashboard',

    // ── Server state ──
    serverOnline: false,
    uptime: '--',
    loading: false,

    // ── Dashboard ──
    stats: {},
    config: {},
    cascadeConfig: {},
    history: [],

    // ── Solve ──
    solveForm: {
      challenge_path: '',
      flag_format: 'flag\\{[a-zA-Z0-9_]+\\}',
      challenge_description: '',
      timeout_minutes: 30,
    },
    solveState: 'idle',   // idle | running | completed | failed
    solveJobId: null,
    solveEvents: [],
    solveResult: null,
    solveError: '',
    solveStartTime: null,
    solveElapsed: '0.0s',
    solveTimer: null,
    ws: null,
    triageResult: null,
    decompileResult: null,
    decompileLoading: false,
    selectedFunction: '',

    // ── Challenge Browser ──
    showBrowser: false,
    browserPath: 'challenges',
    browserEntries: [],

    // ── Tools ──
    availableTools: [],
    toolForm: {
      tool_name: '',
      challenge_path: '',
      flag_format: 'flag\\{[a-zA-Z0-9_]+\\}',
    },
    toolResult: null,
    toolRunning: false,
    cascadeRunning: false,
    toolSearch: '',
    historySearch: '',
    historyStatusFilter: '',

    // ── Batch Solve ──
    batchMode: false,
    batchId: null,
    batchJobs: [],
    batchRunning: false,

    // ── Pipeline ──
    pipelineNodes: [],
    completedNodes: new Set(),
    activeNode: '',
    nodeTimings: {},
    expandedNode: '',
    _seenEventKeys: new Set(),

    // ── Computed ──
    get activeSolve() {
      return this.solveState === 'running';
    },

    get activeJobCount() {
      return this.history.filter(s => s.status === 'running').length;
    },

    get successRate() {
      const g = this.stats.global || {};
      const total = (g.total_solves || 0) + (g.total_failures || 0);
      if (total === 0) return '--';
      return Math.round((g.total_solves || 0) / total * 100) + '%';
    },

    get filteredTools() {
      if (!this.toolSearch) return this.availableTools;
      const q = this.toolSearch.toLowerCase();
      return this.availableTools.filter(t =>
        t.toLowerCase().includes(q) || this.toolCategory(t).toLowerCase().includes(q)
      );
    },

    get filteredHistory() {
      let items = this.history;
      if (this.historyStatusFilter) {
        items = items.filter(s => s.status === this.historyStatusFilter);
      }
      if (this.historySearch) {
        const q = this.historySearch.toLowerCase();
        items = items.filter(s =>
          s.challenge_path.toLowerCase().includes(q) ||
          (s.flag || '').toLowerCase().includes(q) ||
          (s.challenge_type || '').toLowerCase().includes(q) ||
          s.id.toLowerCase().includes(q)
        );
      }
      return items;
    },

    get batchStats() {
      const total = this.batchJobs.length;
      const completed = this.batchJobs.filter(j => j.status === 'completed').length;
      const failed = this.batchJobs.filter(j => j.status === 'failed').length;
      const running = this.batchJobs.filter(j => j.status === 'running' || j.status === 'pending').length;
      const flags = this.batchJobs.filter(j => j.flag).length;
      return { total, completed, failed, running, flags };
    },

    // ── Init ──
    async init() {
      this.navigate(window.location.hash.slice(1) || 'dashboard');
      await this.checkHealth();
      await Promise.all([
        this.loadStats(),
        this.loadConfig(),
        this.loadCascadeConfig(),
        this.loadHistory(),
        this.loadPipeline(),
        this.loadTools(),
      ]);
      setInterval(() => this.checkHealth(), 30000);

      // Keyboard shortcuts
      document.addEventListener('keydown', (e) => {
        if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
          if (e.key === 'Escape') { e.target.blur(); this.showBrowser = false; }
          if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            if (this.view === 'solve' && this.solveForm.challenge_path && this.solveState === 'idle') this.startSolve();
          }
          return;
        }
        if (e.key === '1') this.navigate('dashboard');
        else if (e.key === '2') this.navigate('solve');
        else if (e.key === '3') this.navigate('tools');
        else if (e.key === '4') this.navigate('history');
        else if (e.key === '5') this.navigate('settings');
        else if (e.key === 'r') { this.loadStats(); this.loadHistory(); this.checkHealth(); this.toast('Refreshed', 'info'); }
        else if (e.key === 'Escape') { this.showBrowser = false; this.toolResult = null; this.expandedNode = ''; }
      });
    },

    navigate(view) {
      const valid = ['dashboard', 'solve', 'tools', 'history', 'settings'];
      this.view = valid.includes(view) ? view : 'dashboard';
      window.location.hash = this.view;
    },

    // ── API helpers ──
    async api(path, options = {}) {
      const resp = await fetch(`/api${path}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || err.error || `HTTP ${resp.status}`);
      }
      return await resp.json();
    },

    async apiSafe(path, options = {}) {
      try {
        return await this.api(path, options);
      } catch (e) {
        console.error(`API ${path}:`, e);
        return null;
      }
    },

    async apiWithToast(path, options = {}) {
      try {
        return await this.api(path, options);
      } catch (e) {
        console.error(`API ${path}:`, e);
        this.toast(e.message, 'error');
        throw e;
      }
    },

    async checkHealth() {
      try {
        const data = await this.api('/health');
        this.serverOnline = data.status === 'ok';
        const secs = Math.floor(data.uptime_s || 0);
        if (secs < 60) this.uptime = secs + 's';
        else if (secs < 3600) this.uptime = Math.floor(secs / 60) + 'm';
        else this.uptime = Math.floor(secs / 3600) + 'h';
      } catch {
        this.serverOnline = false;
        this.uptime = '--';
      }
    },

    async loadStats() { this.stats = await this.apiSafe('/stats') || {}; },
    async loadConfig() { this.config = await this.apiSafe('/config') || {}; },
    async loadCascadeConfig() { this.cascadeConfig = await this.apiSafe('/stats/cascade') || {}; },
    async loadHistory() {
      const data = await this.apiSafe('/solves');
      if (data) this.history = data.solves || [];
    },
    async loadPipeline() {
      const data = await this.apiSafe('/pipeline');
      if (data) this.pipelineNodes = data.nodes || [];
    },
    async loadTools() {
      const data = await this.apiSafe('/tools');
      if (data) this.availableTools = data.tools || [];
    },

    // ── Solve ──
    async startSolve() {
      if (!this.solveForm.challenge_path) return;
      this.loading = true;
      this.solveState = 'running';
      this.solveEvents = [];
      this.solveResult = null;
      this.solveError = '';
      this.completedNodes = new Set();
      this.activeNode = '';
      this.nodeTimings = {};
      this.triageResult = null;
      this.decompileResult = null;
      this.expandedNode = '';

      try {
        const data = await this.apiWithToast('/solve', {
          method: 'POST',
          body: JSON.stringify(this.solveForm),
        });
        this.solveJobId = data.job_id;
        this.solveStartTime = Date.now();
        this.startTimer();
        this.connectWS(data.job_id);
        this.toast('Solve started', 'info');
      } catch (e) {
        this.solveState = 'failed';
        this.solveError = e.message;
        this.loading = false;
      }
    },

    async cancelSolve() {
      if (!this.solveJobId) return;
      try {
        await this.apiWithToast('/solve/' + this.solveJobId, { method: 'DELETE' });
        this.solveState = 'failed';
        this.solveError = 'Cancelled by user';
        this.loading = false;
        this.stopTimer();
        if (this.ws) { this.ws.close(); this.ws = null; }
        this.toast('Solve cancelled', 'info');
      } catch {}
    },

    connectWS(jobId) {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${window.location.host}/ws/solve/${jobId}`;

      const connect = () => {
        this.ws = new WebSocket(url);

        this.ws.onmessage = (msg) => {
          const data = JSON.parse(msg.data);
          if (data.type === 'init') {
            const job = data.job;
            if (job.events) {
              job.events.forEach(e => this.processEvent(e));
            }
          } else if (data.type === 'event') {
            this.processEvent(data.event);
          }
        };

        this.ws.onclose = () => {
          if (this.solveState === 'running') {
            setTimeout(() => {
              if (this.solveState === 'running') connect();
            }, 2000);
          }
        };

        this.ws.onerror = () => {};
      };

      connect();
    },

    processEvent(evt) {
      const evtKey = evt.node + ':' + evt.status + ':' + Math.floor(evt.timestamp || 0);
      if (this._seenEventKeys.has(evtKey)) return;
      this._seenEventKeys.add(evtKey);

      if (evt.node === '__done__') {
        const isSuccess = evt.status === 'completed';
        this.solveState = isSuccess ? 'completed' : 'failed';
        this.loading = false;
        this.stopTimer();
        if (evt.data?.flag) {
          this.solveResult = {
            flag: evt.data.flag,
            elapsed_s: evt.data.elapsed_s,
            challenge_type: this.solveEvents.find(e => e.data?.challenge_type)?.data?.challenge_type || '',
            tools_run: this.solveEvents.filter(e => e.data?.tools_run).reduce((max, e) => Math.max(max, e.data.tools_run), 0),
          };
          this.toast('Flag found: ' + evt.data.flag, 'success');
        } else {
          this.toast('Solve ' + (evt.status === 'cancelled' ? 'cancelled' : 'failed'), 'error');
        }
        this.loadHistory();
        return;
      }

      if (evt.node === 'error') {
        this.solveError = evt.data?.error || 'Unknown error';
        return;
      }

      this.solveEvents.push(evt);

      if (evt.status === 'completed') {
        this.completedNodes.add(evt.node);
        if (evt.duration_s > 0) {
          this.nodeTimings[evt.node] = (this.nodeTimings[evt.node] || 0) + evt.duration_s;
        }
        this.activeNode = '';
      } else if (evt.status === 'started') {
        this.activeNode = evt.node;
      }

      if (evt.data?.flag) {
        this.solveResult = {
          flag: evt.data.flag,
          challenge_type: evt.data.challenge_type || '',
          tools_run: evt.data.tools_run || 0,
          elapsed_s: this.solveElapsed,
        };
      }

      // Auto-scroll event log
      this.$nextTick(() => {
        const log = document.querySelector('.event-log');
        if (log) log.scrollTop = 0; // Events are displayed in reverse, so scroll to top
      });
    },

    startTimer() {
      this.solveTimer = setInterval(() => {
        if (this.solveStartTime) {
          const elapsed = (Date.now() - this.solveStartTime) / 1000;
          this.solveElapsed = elapsed.toFixed(1) + 's';
        }
      }, 100);
    },

    stopTimer() {
      if (this.solveTimer) {
        clearInterval(this.solveTimer);
        this.solveTimer = null;
      }
    },

    resetSolve() {
      if (this.ws) { this.ws.close(); this.ws = null; }
      this.stopTimer();
      this.solveState = 'idle';
      this.solveJobId = null;
      this.solveEvents = [];
      this.solveResult = null;
      this.solveError = '';
      this.solveElapsed = '0.0s';
      this.completedNodes = new Set();
      this.activeNode = '';
      this.nodeTimings = {};
      this.loading = false;
      this._seenEventKeys = new Set();
      this.expandedNode = '';
      this.decompileResult = null;
      this.triageResult = null;
    },

    viewSolve(s) {
      this.navigate('solve');
      this.solveJobId = s.id;
      this.solveState = s.status;
      this.solveEvents = s.events || [];
      this.solveResult = s.flag ? {
        flag: s.flag,
        challenge_type: s.challenge_type,
        tools_run: s.tools_run,
        elapsed_s: s.elapsed_s,
      } : null;
      this.solveError = s.error || '';
      this.solveForm.challenge_path = s.challenge_path || '';

      this.completedNodes = new Set();
      this.nodeTimings = {};
      (s.events || []).forEach(e => {
        if (e.status === 'completed') {
          this.completedNodes.add(e.node);
          if (e.duration_s > 0) {
            this.nodeTimings[e.node] = (this.nodeTimings[e.node] || 0) + e.duration_s;
          }
        }
      });
    },

    // ── Pipeline Status ──
    nodeStatus(nodeId) {
      if (this.activeNode === nodeId) return 'active';
      if (this.completedNodes.has(nodeId)) return 'completed';
      if (this.solveState === 'idle') return 'pending';
      if (['completed', 'failed'].includes(this.solveState) && !this.completedNodes.has(nodeId)) return 'skipped';
      return 'pending';
    },

    connectorStatus(nodeId) {
      if (this.completedNodes.has(nodeId)) return 'completed';
      if (this.activeNode === nodeId) return 'active';
      return '';
    },

    nodeTime(nodeId) {
      const t = this.nodeTimings[nodeId];
      if (!t) return '';
      return t.toFixed(2) + 's';
    },

    toggleNode(nodeId) {
      this.expandedNode = this.expandedNode === nodeId ? '' : nodeId;
    },

    nodeDetails(nodeId) {
      const events = this.solveEvents.filter(e => e.node === nodeId);
      if (events.length === 0) return null;
      return events[events.length - 1].data || null;
    },

    // ── Triage Only ──
    async runTriageOnly() {
      if (!this.solveForm.challenge_path) return;
      this.loading = true;
      try {
        this.triageResult = await this.apiWithToast('/pipeline/triage', {
          method: 'POST',
          body: JSON.stringify({
            challenge_path: this.solveForm.challenge_path,
            flag_format: this.solveForm.flag_format,
            challenge_description: this.solveForm.challenge_description,
          }),
        });
        this.toast('Triage complete', 'success');
      } catch (e) {
        this.triageResult = { error: e.message };
      }
      this.loading = false;
    },

    // ── Decompile ──
    async runDecompile() {
      if (!this.solveForm.challenge_path) return;
      this.decompileLoading = true;
      try {
        this.decompileResult = await this.apiWithToast('/pipeline/decompile', {
          method: 'POST',
          body: JSON.stringify({
            challenge_path: this.solveForm.challenge_path,
            flag_format: this.solveForm.flag_format,
          }),
        });
        const fns = Object.keys(this.decompileResult.decompiled_functions || {});
        if (fns.length > 0) this.selectedFunction = fns.find(f => f.startsWith('main')) || fns[0];
        this.toast('Decompile complete -- ' + fns.length + ' functions', 'success');
      } catch (e) {
        this.decompileResult = { error: e.message };
      }
      this.decompileLoading = false;
    },

    // ── Challenge Browser ──
    async browseChallenges() {
      this.showBrowser = true;
      await this.loadChallenges();
    },

    async loadChallenges() {
      const data = await this.apiSafe(`/challenges?path=${encodeURIComponent(this.browserPath)}`);
      if (data) {
        this.browserEntries = data.entries || [];
        this.browserPath = data.path || this.browserPath;
      } else {
        this.browserEntries = [];
      }
    },

    navigateDir(path) {
      this.browserPath = path;
      this.loadChallenges();
    },

    selectChallenge(path) {
      this.solveForm.challenge_path = path;
      this.toolForm.challenge_path = path;
      this.showBrowser = false;
      this.toast('Selected: ' + path.split('/').pop(), 'info');
    },

    // ── Tools ──
    async runTool() {
      if (!this.toolForm.challenge_path || !this.toolForm.tool_name) return;
      this.toolRunning = true;
      this.toolResult = null;
      try {
        this.toolResult = await this.apiWithToast('/pipeline/tool', {
          method: 'POST',
          body: JSON.stringify({
            tool_name: this.toolForm.tool_name,
            challenge_path: this.toolForm.challenge_path,
            flag_format: this.toolForm.flag_format,
            timeout: 120,
          }),
        });
        if (this.toolResult.flag_found) this.toast('Flag found: ' + this.toolResult.flag, 'success');
        else this.toast('Tool finished -- no flag', 'info');
      } catch (e) {
        this.toolResult = { error: e.message, tool: this.toolForm.tool_name };
      }
      this.toolRunning = false;
    },

    async runCascade() {
      if (!this.toolForm.challenge_path) return;
      this.cascadeRunning = true;
      this.toolResult = null;
      try {
        this.toolResult = await this.apiWithToast('/pipeline/tool-cascade', {
          method: 'POST',
          body: JSON.stringify({
            challenge_path: this.toolForm.challenge_path,
            flag_format: this.toolForm.flag_format,
          }),
        });
        if (this.toolResult.flag_found) this.toast('Cascade found flag: ' + this.toolResult.flag, 'success');
        else this.toast('Cascade complete -- ' + this.toolResult.tools_run + ' tools, no flag', 'info');
      } catch (e) {
        this.toolResult = { error: e.message };
      }
      this.cascadeRunning = false;
    },

    // ── Batch Solve ──
    async startBatchSolve() {
      if (!this.solveForm.challenge_path) return;
      this.batchRunning = true;
      this.batchJobs = [];
      this.batchId = null;
      try {
        const data = await this.apiWithToast('/batch-solve', {
          method: 'POST',
          body: JSON.stringify({
            directory: this.solveForm.challenge_path,
            flag_format: this.solveForm.flag_format,
            timeout_minutes: this.solveForm.timeout_minutes,
          }),
        });
        this.batchJobs = data.jobs || [];
        this.batchId = data.batch_id;
        this.batchMode = true;
        this.toast(data.batch_size + ' solves started', 'info');
        this._pollBatch();
      } catch {}
      this.batchRunning = false;
    },

    async _pollBatch() {
      if (!this.batchMode || !this.batchId) return;
      try {
        const data = await this.apiSafe('/batch/' + this.batchId);
        if (data && data.jobs) {
          this.batchJobs = data.jobs;
        }
        if (data && data.running > 0) {
          setTimeout(() => this._pollBatch(), 3000);
        } else {
          this.loadHistory();
          this.toast(`Batch complete -- ${data?.flags_found || 0}/${data?.total || 0} flags`, 'success');
        }
      } catch {
        setTimeout(() => this._pollBatch(), 5000);
      }
    },

    // ── Export ──
    exportHistory() {
      const data = JSON.stringify(this.history, null, 2);
      this._downloadJSON(data, 'kraken-history-' + new Date().toISOString().slice(0, 10) + '.json');
      this.toast('History exported', 'info');
    },

    exportSolveResult() {
      if (!this.solveJobId) return;
      const job = this.history.find(j => j.id === this.solveJobId);
      const data = JSON.stringify(
        job || { id: this.solveJobId, events: this.solveEvents, result: this.solveResult },
        null, 2
      );
      this._downloadJSON(data, 'kraken-solve-' + this.solveJobId + '.json');
      this.toast('Solve result exported', 'info');
    },

    _downloadJSON(data, filename) {
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    },

    toolCategory(tool) {
      const categories = {
        auto_angr: 'symbolic', auto_angr_advanced: 'symbolic',
        auto_regex_z3: 'constraint', auto_constraint_extract: 'constraint',
        auto_gdb_cmp: 'dynamic', auto_gdb_solve: 'dynamic', auto_dynamic_trace: 'dynamic',
        auto_run_static: 'dynamic', auto_memory_dump: 'dynamic',
        auto_c_brute: 'brute force',
        auto_xor_brute: 'crypto', auto_crypto: 'crypto', auto_c_rand: 'crypto',
        auto_table_reverse: 'crypto', auto_ec_vigenere: 'crypto',
        auto_hash_crack: 'crypto', auto_substitution_cipher: 'crypto',
        auto_rsa_attack: 'crypto', auto_lattice_attack: 'crypto',
        auto_c_source_eval: 'static', auto_python_reverse: 'static',
        auto_cpp_compile: 'static', auto_focused_decompile: 'static',
        auto_source_decode: 'decoder', auto_deobfuscate: 'decoder',
        auto_qr_decode: 'misc', auto_maze_solver: 'misc', auto_vm_analyze: 'misc',
        auto_archive_search: 'forensics', auto_git_extract: 'forensics',
        auto_pdf_extract: 'forensics', auto_pcap_extract: 'forensics',
        auto_file_carve: 'forensics', auto_forensics_advanced: 'forensics',
        auto_steg_extract: 'steg',
        auto_normalize: 'utility', auto_patcher: 'utility', auto_binary_diff: 'utility',
        auto_pwn_template: 'pwn', auto_rop_extract: 'pwn',
        auto_pwn_solve: 'pwn', auto_heap_exploit: 'pwn', auto_kernel_pwn: 'pwn',
        auto_web_exploit: 'web', auto_jwt_crack: 'web', auto_directory_scan: 'web',
        auto_remote_interact: 'network', auto_timing_attack: 'network',
        auto_service_interact: 'network', auto_process_interact: 'network',
        auto_docker_solve: 'infra',
      };
      return categories[tool] || 'general';
    },

    // ── Syntax Highlighting ──
    highlightOutput(text) {
      if (!text) return '';
      let html = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      html = html.replace(/((?:flag|FLAG|ctf|CTF|byuctf|picoCTF)\{[^}]+\})/g, '<span class="hl-flag">$1</span>');
      html = html.replace(/(\/[\w/._-]+)/g, '<span class="hl-path">$1</span>');
      html = html.replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span class="hl-hex">$1</span>');
      html = html.replace(/\b(Success|SUCCESS|FOUND|Found|Correct)\b/g, '<span class="hl-success">$1</span>');
      html = html.replace(/\b(Error|ERROR|FAIL|Failed|Incorrect|WRONG)\b/g, '<span class="hl-error">$1</span>');
      return html;
    },

    // ── Formatters ──
    formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    },

    formatEventTime(timestamp) {
      if (!timestamp) return '';
      const d = new Date(timestamp * 1000);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    },

    formatEventData(data) {
      if (!data || Object.keys(data).length === 0) return '';
      const parts = [];
      if (data.challenge_type) parts.push(`type: ${data.challenge_type}`);
      if (data.file_type) parts.push(`file: ${data.file_type}`);
      if (data.arch) parts.push(`arch: ${data.arch}`);
      if (data.functions_count) parts.push(`${data.functions_count} functions`);
      if (data.tools_run) parts.push(`${data.tools_run} tools`);
      if (data.flag) parts.push(`FLAG: ${data.flag}`);
      if (data.flag_candidate) parts.push(`candidate: ${data.flag_candidate}`);
      if (data.error) parts.push(`error: ${data.error}`);
      if (data.tools) {
        const found = data.tools.filter(t => t.flag_found);
        if (found.length > 0) parts.push(`found by: ${found.map(t => t.tool).join(', ')}`);
      }
      return parts.join(' | ');
    },

    // ── Toast Notifications ──
    toast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      if (!container) return;
      const el = document.createElement('div');
      el.className = `toast toast-${type}`;
      el.textContent = message;
      container.appendChild(el);
      const timeout = type === 'error' ? 6000 : 4000;
      setTimeout(() => {
        el.classList.add('dismissing');
        setTimeout(() => el.remove(), 200);
      }, timeout);
    },

    // ── Copy to Clipboard ──
    async copyFlag(text) {
      try {
        await navigator.clipboard.writeText(text);
        this.toast('Copied to clipboard', 'success');
      } catch {
        this.toast('Copy failed', 'error');
      }
    },
  };
}
