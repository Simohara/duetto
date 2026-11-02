"use strict";
// Browser-only stand-in for the Rust backend (never embedded in the exe):
// same snapshot shape and commands, sample speakers, sped-up timings.
(() => {
  const state = {
    run: "idle", busy: false, connected: false, measuring: false, scanning: false, testMode: 0, transition: false,
    status: "选择音响及声道，桥接使用同一个 CABLE Output。",
    master: 100, testVolume: 100, bufferMs: 2000, reconnect: true, theme: new URLSearchParams(location.search).get("theme") || "light",
    // ?nocable previews the missing-driver state.
    devices: new URLSearchParams(location.search).has("nocable") ? [] : ["CABLE Output (VB-Audio Virtual Cable)"], device: 0, mics: ["麦克风 (USB Audio Device)"], mic: 0,
    host: "192.168.1.31:7000", pinRequested: false, repairConfirm: false, cpu: "AMD x64 · SSE2", webview: "浏览器预览（模拟后端）",
    progress: null, lastResult: null, inputLevel: null, droppedPackets: 0, checks: { pair: true, mic: true }, session: [], calPair: { left: null, right: null },
    editable: true, volumeEditable: true, masterEditable: true, testVolumeEditable: true,
    speakers: [
      { address: "192.168.1.31:7000", name: "客厅 HomePod", selected: true, mode: 1, delay: 0, trim: -1.2, volume: 35, partner: "192.168.1.32:7000", homePair: null, needsPassword: false },
      { address: "192.168.1.32:7000", name: "卧室 HomePod", selected: true, mode: 2, delay: 12.4, trim: 0, volume: 35, partner: "192.168.1.31:7000", homePair: null, needsPassword: false },
      { address: "192.168.1.40:7000", name: "书房 HomePod mini", selected: false, mode: 0, delay: 0, trim: 0, volume: 30, partner: null, homePair: "B71C", needsPassword: false },
      { address: "192.168.1.41:7000", name: "书房 HomePod mini (2)", selected: false, mode: 0, delay: 0, trim: 0, volume: 30, partner: null, homePair: "B71C", needsPassword: true },
    ],
  };
  // Speakers that already hold a credential: pairing them asks for confirmation.
  const paired = new Set(["192.168.1.31:7000"]);
  const find = (a) => state.speakers.find((s) => s.address === a);
  const level = (s) => (state.master === 0 || s.volume === 0 ? "静音" : `${(v => (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(1))(-30 + s.volume * 0.3 + s.trim + 20 * Math.log10(state.master / 100))} dB`);
  let transitionEnd = 0, transitionStarting = true, measureStart = 0, toneId = 0;
  function snapshot() {
    const selected = state.speakers.filter((s) => s.selected);
    const pool = state.busy ? state.session.map(find) : selected;
    const l = pool.find((s) => s.mode === 1), r = pool.find((s) => s.mode === 2);
    state.calPair = { left: l ? l.address : null, right: r ? r.address : null };
    state.checks = { pair: pool.length === 2 && !!l && !!r, mic: state.mics.length > 0 };
    const now = performance.now();
    if (state.transition) {
      const left = Math.max(0, transitionEnd - now);
      state.progress = { fraction: 1 - left / 5000, label: `${transitionStarting ? "等待播放缓冲排空" : "正在恢复播放音量"} · 剩 ${Math.ceil(left / 1000)} 秒` };
    } else if (state.measuring) {
      const t = (now - measureStart) / 6000;
      state.progress = { fraction: Math.min(t, 0.97), label: `正在测量延迟和音量，请保持安静 · 约 ${Math.max(1, Math.ceil(17 * (1 - t)))} 秒` };
    } else state.progress = null;
    state.editable = !state.measuring && !state.transition;
    state.volumeEditable = state.testMode === 0;
    state.masterEditable = state.editable;
    state.speakers.forEach((s) => { s.level = level(s); s.target = s.address === state.host; });
    // Whole dB peaks while live, like the backend; a rare congestion drop.
    state.inputLevel = state.connected ? Math.round(-18 + 6 * Math.sin(now / 400) + Math.random() * 4) : null;
    if (state.connected && Math.random() < 0.004) state.droppedPackets += 1;
    return JSON.parse(JSON.stringify(state));
  }
  const push = () => window.duetto.update(snapshot());
  setInterval(() => {
    if (state.transition && performance.now() >= transitionEnd) {
      state.transition = false;
      if (transitionStarting) state.status = "连续测试音已开启；两台使用相同测试电平。";
      else { state.testMode = 0; state.status = "连续测试已结束，恢复应用声音。"; }
    }
    if (state.measuring && performance.now() - measureStart >= 6000) {
      state.measuring = false;
      const l = find(state.calPair.left), r = find(state.calPair.right);
      // The first pass corrects; measuring again verifies within the limits.
      const again = !!state.lastResult;
      state.lastResult = again ? { ms: 0.08, db: 0.2 } : { ms: 1.23, db: -0.8 };
      if (l && r) { l.delay = 0; r.delay = again ? 11.3 : 11.2; l.trim = -2.0; r.trim = 0; }
      state.status = again
        ? "测得右侧比左侧晚 +0.08 ms、响 +0.2 dB；已立即应用：延迟左 0.0、右 11.3 ms，电平修正左 −2.0、右 +0.0 dB。"
        : "测得右侧比左侧晚 +1.23 ms、响 −0.8 dB；已立即应用：延迟左 0.0、右 11.2 ms，电平修正左 −2.0、右 +0.0 dB。";
    }
    push();
  }, 100);
  const unpair = (s) => { if (s.partner) state.lastResult = null; const p = find(s.partner); s.partner = null; s.mode = 0; if (p) { p.partner = null; p.mode = 0; } };
  window.mockBackend = (message) => {
    const c = JSON.parse(message);
    const s = c.address && find(c.address);
    switch (c.cmd) {
      case "route":
        if (!s) break;
        if (c.selected !== undefined) { s.selected = c.selected; const p = find(s.partner); if (p) p.selected = c.selected; }
        if (c.mode !== undefined) { if (s.partner && (c.mode === 0 || c.mode === 3)) unpair(s); s.mode = c.mode; }
        const before = [s.delay, s.trim];
        if (c.delay !== undefined) s.delay = Math.min(2000, Math.max(0, c.delay));
        if (c.trim !== undefined) s.trim = Math.min(0, Math.max(-24, c.trim));
        // Values that were never measured must not show as aligned.
        if (s.delay !== before[0] || s.trim !== before[1]) state.lastResult = null;
        if (c.volume !== undefined) s.volume = c.volume;
        break;
      case "makePair": {
        const l = find(c.left), r = find(c.right);
        [l, r].forEach((x) => x.partner && unpair(x));
        state.lastResult = null;
        Object.assign(l, { mode: 1, partner: r.address }); Object.assign(r, { mode: 2, partner: l.address });
        const on = l.selected || r.selected; l.selected = r.selected = on;
        state.status = `「${l.name}」与「${r.name}」已组成立体声对：左、右声道。`;
        break;
      }
      case "swapPair": { const p = find(s.partner); state.lastResult = null; [s.mode, p.mode] = [p.mode, s.mode]; state.status = "已互换左右声道。"; break; }
      case "unpair": unpair(s); state.status = "已拆分立体声对，两台恢复为立体声。"; break;
      case "setTarget": if (c.address !== state.host) state.repairConfirm = false; state.host = c.address; break;
      case "setHost": if (c.host.trim() !== state.host) state.repairConfirm = false; state.host = c.host.trim(); break;
      case "setTheme": state.theme = c.theme; break;
      case "setMaster": state.master = c.value; break;
      case "setTestVolume": state.testVolume = c.value; break;
      case "setBuffer": state.bufferMs = c.value; break;
      case "setReconnect": state.reconnect = c.on; break;
      case "scan":
        state.scanning = true;
        setTimeout(() => {
          state.scanning = false;
          if (!find("192.168.1.44:7000")) state.speakers.push({ address: "192.168.1.44:7000", name: "厨房 HomePod mini", selected: false, mode: 0, delay: 0, trim: 0, volume: 35, partner: null, homePair: null, needsPassword: false });
          state.status = `扫描完成：找到 ${state.speakers.length} 台音响。`;
        }, 1500);
        break;
      case "start":
        if (state.busy) break;
        if (!state.devices.length) { state.status = "未找到 CABLE Output，请先安装驱动并刷新。"; break; }
        state.busy = true; state.run = "connecting"; state.status = "正在连接音响…"; state.lastResult = null; state.droppedPackets = 0;
        state.session = state.speakers.filter((x) => x.selected).map((x) => x.address);
        setTimeout(() => { if (!state.busy) return; state.connected = true; state.run = "live"; state.status = `${state.session.length} 台音响已连接，正在采集 CABLE Output。`; }, 1200);
        break;
      case "stop": {
        const status = state.run !== "pairing" ? "已停止。" : paired.has(state.host) ? "已取消配对。旧凭据未更改。" : "已取消配对。";
        Object.assign(state, { busy: false, connected: false, run: "idle", testMode: 0, transition: false, measuring: false, session: [], status, pinRequested: false, repairConfirm: false });
        break;
      }
      case "toggleTest":
        transitionEnd = performance.now() + 5000; state.transition = true;
        transitionStarting = state.testMode === 0;
        if (transitionStarting) { state.testMode = 1; state.status = "正在切换测试音，等待播放缓冲排空…"; } else state.status = "正在恢复播放音量，随后恢复应用声音…";
        break;
      case "measure": state.measuring = true; measureStart = performance.now(); state.status = "正在测量延迟和音量，约需 20 秒，请保持安静。"; break;
      case "tone":
        if (state.busy) break;
        state.busy = true; state.run = "tone"; state.lastResult = null; state.droppedPackets = 0; state.status = "协议发送已开始；实际发声需现场确认。";
        // Only this tone's timer may end it, not one from a tone stopped earlier.
        setTimeout((id) => { if (state.run !== "tone" || id !== toneId) return; Object.assign(state, { busy: false, run: "idle", status: "已停止。" }); }, 6000, ++toneId);
        break;
      case "pairDevice":
        if (state.busy) break;
        if (paired.has(state.host) && !(c.replace && state.repairConfirm)) { state.repairConfirm = true; state.status = "这台音响已有配对凭据。重新配对成功后才替换旧凭据；失败、超时或取消都保留旧凭据。"; break; }
        state.repairConfirm = false; state.busy = true; state.run = "pairing"; state.pinRequested = true; state.status = "请在下方输入音响显示的 PIN。"; break;
      case "cancelPair": if (state.repairConfirm) { state.repairConfirm = false; state.status = "已取消重新配对，旧凭据未更改。"; } break;
      case "importLegacyCredentials": state.status = "旧版凭据中没有与已扫描音响对应的配对凭据。"; break;
      case "submitPin":
        // Like the backend, an invalid PIN keeps the prompt and the pairing.
        if (!/^\d{4}$/.test(c.pin)) { state.status = "PIN 必须为四位数字。"; break; }
        Object.assign(state, { pinRequested: false, busy: false, run: "idle" });
        state.status = paired.has(state.host) ? "重新配对完成，已替换旧凭据。" : "配对完成，凭据已使用 Windows 当前用户加密保存。"; paired.add(state.host);
        break;
      case "openDriverPage": state.status = "已在浏览器打开 VB-CABLE 官方下载页；安装后点击「刷新」。"; break;
      case "exportDiagnostics": state.status = "诊断已导出（预览）。"; break;
      case "addHost": state.status = "已添加。"; break;
    }
    push();
  };
  push();
})();
