"use strict";
// Browser-only stand-in for the Rust backend (never embedded in the exe):
// same snapshot shape and commands, sample speakers, sped-up timings.
(() => {
  const query = new URLSearchParams(location.search);
  const want = query.get("lang") || "zh";
  // Like the Rust tr!: one text per language, picked when the message is made.
  const M = (zh, en, ja) => ({ zh, en, ja })[state.lang] || zh;
  const state = {
    language: want, lang: want === "system" ? "zh" : want,
    run: "idle", busy: false, connected: false, measuring: false, scanning: false, testMode: 0, transition: false,
    status: "",
    master: 100, testVolume: 100, bufferMs: 2000, reconnect: true, mcp: { enabled: true, listening: true, command: 'claude mcp add duetto -- "E:\\Apps\\Duetto.exe" --mcp', last: { at: Date.now() - 120000, action: want === "en" ? "master volume 30%" : want === "ja" ? "全体音量 30%" : "总音量 30%" } }, theme: new URLSearchParams(location.search).get("theme") || "light",
    // ?nocable previews the missing-driver state.
    devices: new URLSearchParams(location.search).has("nocable") ? [] : ["CABLE Output (VB-Audio Virtual Cable)"], device: 0, mics: [want === "en" ? "Microphone (USB Audio Device)" : want === "ja" ? "マイク (USB Audio Device)" : "麦克风 (USB Audio Device)"], mic: 0,
    host: "192.168.1.31:7000", pinRequested: false, repairConfirm: false, cpu: "AMD x64 · SSE2", webview: "",
    progress: null, lastResult: null, inputLevel: null, droppedPackets: 0, checks: { pair: true, mic: true }, session: [], calPair: { left: null, right: null },
    editable: true, volumeEditable: true, masterEditable: true, testVolumeEditable: true,
    speakers: [
      { address: "192.168.1.31:7000", name: want === "en" ? "Living Room" : want === "ja" ? "リビング" : "客厅 HomePod", selected: true, mode: 1, delay: 0, trim: -1.2, volume: 35, partner: "192.168.1.32:7000", homePair: null, needsPassword: false },
      { address: "192.168.1.32:7000", name: want === "en" ? "Bedroom" : want === "ja" ? "寝室" : "卧室 HomePod", selected: true, mode: 2, delay: 12.4, trim: 0, volume: 35, partner: "192.168.1.31:7000", homePair: null, needsPassword: false },
      { address: "192.168.1.40:7000", name: want === "en" ? "Study mini" : want === "ja" ? "書斎 mini" : "书房 HomePod mini", selected: false, mode: 0, delay: 0, trim: 0, volume: 30, partner: null, homePair: "B71C", needsPassword: false },
      { address: "192.168.1.41:7000", name: want === "en" ? "Study mini (2)" : want === "ja" ? "書斎 mini (2)" : "书房 HomePod mini (2)", selected: false, mode: 0, delay: 0, trim: 0, volume: 30, partner: null, homePair: "B71C", needsPassword: true },
    ],
  };
  state.webview = M("浏览器预览（模拟后端）", "Browser preview (mock backend)", "ブラウザープレビュー（模擬バックエンド）");
  state.status = M("选择音响及声道，桥接使用同一个 CABLE Output。", "Choose speakers and channels; they all stream from the same CABLE Output.", "スピーカーとチャンネルを選んでください。すべて同じ CABLE Output から送信します。");
  // Speakers that already hold a credential: pairing them asks for confirmation.
  const paired = new Set(["192.168.1.31:7000"]);
  const find = (a) => state.speakers.find((s) => s.address === a);
  const level = (s) => (state.master === 0 || s.volume === 0 ? M("静音", "Muted", "ミュート") : `${(v => (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(1))(-30 + s.volume * 0.3 + s.trim + 20 * Math.log10(state.master / 100))} dB`);
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
      state.progress = { fraction: 1 - left / 5000, label: `${transitionStarting ? M("等待播放缓冲排空", "Waiting for the playback buffer to drain", "再生バッファが空になるのを待っています") : M("正在恢复播放音量", "Restoring the playback volume", "再生音量を戻しています")}${M(" · 剩 ", " · ", "・残り ")}${Math.ceil(left / 1000)}${M(" 秒", " s left", " 秒")}` };
    } else if (state.measuring) {
      const t = (now - measureStart) / 6000;
      state.progress = { fraction: Math.min(t, 0.97), label: `${M("正在测量延迟和音量，请保持安静 · 约 ", "Measuring delay and level, please keep quiet · about ", "遅延と音量を測定中です。静かにしてください・約 ")}${Math.max(1, Math.ceil(17 * (1 - t)))}${M(" 秒", " s", " 秒")}` };
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
      if (transitionStarting) state.status = M("连续测试音已开启；两台使用相同测试电平。", "Continuous test tone on; both speakers play it at the same level.", "連続テスト音を開始しました。2 台とも同じテストレベルです。");
      else { state.testMode = 0; state.status = M("连续测试已结束，恢复应用声音。", "Continuous test ended; app audio is back.", "連続テストを終了し、アプリの音声に戻しました。"); }
    }
    if (state.measuring && performance.now() - measureStart >= 6000) {
      state.measuring = false;
      const l = find(state.calPair.left), r = find(state.calPair.right);
      // The first pass corrects; measuring again verifies within the limits.
      const again = !!state.lastResult;
      state.lastResult = again ? { ms: 0.08, db: 0.2 } : { ms: 1.23, db: -0.8 };
      if (l && r) { l.delay = 0; r.delay = again ? 11.3 : 11.2; l.trim = -2.0; r.trim = 0; }
      const [ms, db, dr] = again ? ["+0.08", "+0.2", "11.3"] : ["+1.23", "-0.8", "11.2"];
      state.status = M(
        `测得右侧比左侧晚 ${ms} ms、响 ${db} dB；已立即应用：延迟左 0.0、右 ${dr} ms，电平修正左 -2.0、右 +0.0 dB。`,
        `Measured right vs. left: ${ms} ms in arrival, ${db} dB in level. Applied right away: delay L 0.0 / R ${dr} ms, trim L -2.0 / R +0.0 dB.`,
        `測定結果：左に対する右の差は、到達 ${ms} ms、音量 ${db} dB です。すぐに適用しました：遅延 左 0.0・右 ${dr} ms、レベル補正 左 -2.0・右 +0.0 dB。`);
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
        state.status = M(`「${l.name}」与「${r.name}」已组成立体声对：左、右声道。`, `“${l.name}” and “${r.name}” are now a stereo pair: left and right.`, `「${l.name}」と「${r.name}」をステレオペア（左・右）にしました。`);
        break;
      }
      case "swapPair": { const p = find(s.partner); state.lastResult = null; [s.mode, p.mode] = [p.mode, s.mode]; state.status = M("已互换左右声道。", "Left and right swapped.", "左右を入れ替えました。"); break; }
      case "unpair": unpair(s); state.status = M("已拆分立体声对，两台恢复为立体声。", "Stereo pair split; both speakers are back to stereo.", "ステレオペアを解除し、2 台ともステレオに戻しました。"); break;
      case "setTarget": if (c.address !== state.host) state.repairConfirm = false; state.host = c.address; break;
      case "setHost": if (c.host.trim() !== state.host) state.repairConfirm = false; state.host = c.host.trim(); break;
      case "setTheme": state.theme = c.theme; break;
      case "setLanguage":
        state.language = c.language;
        state.lang = c.language === "system" ? (navigator.language.startsWith("ja") ? "ja" : navigator.language.startsWith("zh") ? "zh" : "en") : c.language;
        state.status = M("界面语言已切换为中文。", "The interface is now in English.", "表示言語を日本語に切り替えました。");
        break;
      case "setMaster": state.master = c.value; break;
      case "setTestVolume": state.testVolume = c.value; break;
      case "setBuffer": state.bufferMs = c.value; break;
      case "setReconnect": state.reconnect = c.on; break;
      case "setMcp": state.mcp.enabled = c.on; break;
      case "scan":
        state.scanning = true;
        setTimeout(() => {
          state.scanning = false;
          if (!find("192.168.1.44:7000")) state.speakers.push({ address: "192.168.1.44:7000", name: M("厨房 HomePod mini", "Kitchen mini", "キッチン mini"), selected: false, mode: 0, delay: 0, trim: 0, volume: 35, partner: null, homePair: null, needsPassword: false });
          state.status = M(`扫描完成：找到 ${state.speakers.length} 台音响。`, `Scan finished: ${state.speakers.length} speakers found.`, `検索が完了しました：スピーカーが ${state.speakers.length} 台見つかりました。`);
        }, 1500);
        break;
      case "start":
        if (state.busy) break;
        if (!state.devices.length) { state.status = M("未找到 CABLE Output，请先安装驱动并刷新。", "CABLE Output not found; install the driver, then refresh.", "CABLE Output が見つかりません。ドライバーをインストールしてから更新してください。"); break; }
        state.busy = true; state.run = "connecting"; state.status = M("正在连接音响…", "Connecting to speakers…", "スピーカーに接続しています…"); state.lastResult = null; state.droppedPackets = 0;
        state.session = state.speakers.filter((x) => x.selected).map((x) => x.address);
        setTimeout(() => { if (!state.busy) return; state.connected = true; state.run = "live"; state.status = M(`${state.session.length} 台音响已连接，正在采集 CABLE Output。`, `${state.session.length} speakers connected; capturing CABLE Output.`, `スピーカー ${state.session.length} 台に接続しました。CABLE Output から取り込んでいます。`); }, 1200);
        break;
      case "stop": {
        const status = state.run !== "pairing" ? M("已停止。", "Stopped.", "停止しました。")
          : paired.has(state.host) ? M("已取消配对。旧凭据未更改。", "Pairing cancelled. The old credentials are unchanged.", "ペアリングを中止しました。以前の認証情報はそのままです。")
          : M("已取消配对。", "Pairing cancelled.", "ペアリングを中止しました。");
        Object.assign(state, { busy: false, connected: false, run: "idle", testMode: 0, transition: false, measuring: false, session: [], status, pinRequested: false, repairConfirm: false });
        break;
      }
      case "toggleTest":
        transitionEnd = performance.now() + 5000; state.transition = true;
        transitionStarting = state.testMode === 0;
        if (transitionStarting) { state.testMode = 1; state.status = M("正在切换测试音，等待播放缓冲排空…", "Switching to the test tone; waiting for the playback buffer to drain…", "テスト音に切り替えています。再生バッファが空になるのを待っています…"); } else state.status = M("正在恢复播放音量，随后恢复应用声音…", "Restoring the playback volume; app audio comes back next…", "再生音量を戻しています。このあとアプリの音声に戻ります…");
        break;
      case "measure": state.measuring = true; measureStart = performance.now(); state.status = M("正在测量延迟和音量，约需 20 秒，请保持安静。", "Measuring delay and level; this takes about 20 seconds. Please keep quiet.", "遅延と音量を測定しています。約 20 秒かかります。静かにしてお待ちください。"); break;
      case "tone":
        if (state.busy) break;
        state.busy = true; state.run = "tone"; state.lastResult = null; state.droppedPackets = 0; state.status = M("协议发送已开始；实际发声需现场确认。", "Sending has started; listen to confirm the speaker actually plays.", "送信を開始しました。実際に音が出ているかはその場で確認してください。");
        // Only this tone's timer may end it, not one from a tone stopped earlier.
        setTimeout((id) => { if (state.run !== "tone" || id !== toneId) return; Object.assign(state, { busy: false, run: "idle", status: M("已停止。", "Stopped.", "停止しました。") }); }, 6000, ++toneId);
        break;
      case "pairDevice":
        if (state.busy) break;
        if (paired.has(state.host) && !(c.replace && state.repairConfirm)) { state.repairConfirm = true; state.status = M("这台音响已有配对凭据。重新配对成功后才替换旧凭据；失败、超时或取消都保留旧凭据。", "This speaker is already paired. The old credentials are replaced only once re-pairing succeeds; if it fails, times out or is cancelled, they are kept.", "このスピーカーはペアリング済みです。再ペアリングが成功したときだけ認証情報を置き換え、失敗・タイムアウト・中止の場合は以前の認証情報を残します。"); break; }
        state.repairConfirm = false; state.busy = true; state.run = "pairing"; state.pinRequested = true; state.status = M("请在下方输入音响显示的 PIN。", "Enter the PIN shown on the speaker below.", "スピーカーに表示された PIN を下に入力してください。"); break;
      case "cancelPair": if (state.repairConfirm) { state.repairConfirm = false; state.status = M("已取消重新配对，旧凭据未更改。", "Re-pairing cancelled; the old credentials are unchanged.", "再ペアリングを中止しました。以前の認証情報はそのままです。"); } break;
      case "importLegacyCredentials": state.status = M("旧版凭据中没有与已扫描音响对应的配对凭据。", "The old credentials include none for the scanned speakers.", "旧バージョンの認証情報に、検索したスピーカーのものはありません。"); break;
      case "submitPin":
        // Like the backend, an invalid PIN keeps the prompt and the pairing.
        if (!/^\d{4}$/.test(c.pin)) { state.status = M("PIN 必须为四位数字。", "The PIN must be four digits.", "PIN は 4 桁の数字で入力してください。"); break; }
        Object.assign(state, { pinRequested: false, busy: false, run: "idle" });
        state.status = paired.has(state.host) ? M("重新配对完成，已替换旧凭据。", "Re-paired; the old credentials were replaced.", "再ペアリングが完了し、認証情報を置き換えました。") : M("配对完成，凭据已使用 Windows 当前用户加密保存。", "Paired. The credentials are saved, encrypted for the current Windows user.", "ペアリングが完了しました。認証情報は現在の Windows ユーザーで暗号化して保存しました。"); paired.add(state.host);
        break;
      case "openDriverPage": state.status = M("已在浏览器打开 VB-CABLE 官方下载页；安装后点击「刷新」。", "Opened the VB-CABLE download page in your browser; after installing, click Refresh.", "VB-CABLE の公式ダウンロードページをブラウザーで開きました。インストール後に「更新」をクリックしてください。"); break;
      case "exportDiagnostics": state.status = M("诊断已导出（预览）。", "Diagnostics exported (preview).", "診断情報を書き出しました（プレビュー）。"); break;
      case "addHost": state.status = M("已添加。", "Added.", "追加しました。"); break;
    }
    push();
  };
  push();
})();
