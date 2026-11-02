"use strict";
// Duetto front end. The Rust side owns all state and pushes a full snapshot
// through window.duetto.update(); every user action is one JSON command.
gsap.registerPlugin(Flip, SplitText, MotionPathPlugin, DrawSVGPlugin);

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const CHANNELS = ["立体声", "左", "右", "单声道"];
const SINGLE_MODES = [0, 3, 1, 2];
const esc = (text) => String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const send = (cmd, args = {}) => {
  const message = JSON.stringify({ cmd, ...args });
  if (window.ipc) window.ipc.postMessage(message);
  else if (window.mockBackend) window.mockBackend(message);
};

let S = null;
let page = "speakers";
let pairing = null; // address whose partner chooser is open
const keys = {};
const changed = (name, value) => {
  const key = JSON.stringify(value);
  if (keys[name] === key) return false;
  keys[name] = key;
  return true;
};
const busyField = (el) => el === document.activeElement || el.dataset.dragging === "1";

/* ---------- theme: CSS variables tween from the old palette to the new ---------- */
const THEME_VARS = ["--ground", "--sheet", "--raised", "--hover", "--active", "--border", "--line", "--ink", "--muted",
  "--left", "--left-tint", "--right", "--right-tint", "--positive", "--warning", "--warning-tint", "--primary",
  "--primary-ink", "--primary-hover", "--chip", "--badge-ink", "--lamp-idle", "--tile-edge"];
const systemDark = matchMedia("(prefers-color-scheme: dark)");
const resolveTheme = (theme) => (theme === "dark" || (theme === "system" && systemDark.matches) ? "dark" : "light");
function applyTheme(theme, animate) {
  const root = document.documentElement;
  const want = resolveTheme(theme);
  morphThemeIcon(want, animate);
  if (root.dataset.theme === want) return;
  if (!animate || reduce) { root.dataset.theme = want; return; }
  const read = () => { const style = getComputedStyle(root); return Object.fromEntries(THEME_VARS.map((v) => [v, style.getPropertyValue(v).trim()])); };
  const from = read();
  root.dataset.theme = want;
  const to = read();
  gsap.fromTo(root, from, { ...to, duration: 0.7, ease: "power2.inOut", onComplete: () => THEME_VARS.forEach((v) => root.style.removeProperty(v)) });
  gsap.fromTo(".sheet", { scale: 0.995 }, { scale: 1, duration: 0.7, ease: "power2.out" });
}
function morphThemeIcon(want, animate) {
  const dark = want === "dark";
  const d = animate && !reduce ? 0.5 : 0;
  gsap.to("#theme-toggle .sun", { scale: dark ? 0.4 : 1, rotate: dark ? -90 : 0, autoAlpha: dark ? 0 : 1, transformOrigin: "50% 50%", duration: d, ease: "back.out(2)" });
  gsap.to("#theme-toggle .moon", { scale: dark ? 1 : 0.4, rotate: dark ? 0 : 90, autoAlpha: dark ? 1 : 0, transformOrigin: "50% 50%", duration: d, ease: "back.out(2)" });
  $("#theme-toggle").setAttribute("aria-label", dark ? "切换到浅色模式" : "切换到深色模式");
}
systemDark.addEventListener("change", () => S && S.theme === "system" && applyTheme("system", true));
$("#theme-toggle").addEventListener("click", () => {
  const next = resolveTheme(S ? S.theme : "light") === "dark" ? "light" : "dark";
  gsap.fromTo("#theme-toggle", { rotate: 0 }, { rotate: 360, duration: 0.6, ease: "power3.out" });
  applyTheme(next, true);
  send("setTheme", { theme: next });
});

/* ---------- small motion helpers ---------- */
function swapLabel(button, text) {
  const label = $(".label", button) || button;
  if (label.textContent === text) return;
  if (reduce) { label.textContent = text; return; }
  gsap.timeline()
    .to(label, { yPercent: -120, autoAlpha: 0, duration: 0.16, ease: "power2.in" })
    .add(() => { label.textContent = text; })
    .fromTo(label, { yPercent: 120, autoAlpha: 0 }, { yPercent: 0, autoAlpha: 1, duration: 0.42, ease: "back.out(2)" });
}
function setChecked(check, on, animate = true) {
  const was = check.getAttribute("aria-checked") === "true";
  check.setAttribute("aria-checked", on);
  const path = $("path", check);
  if (!animate || reduce || was === on) { gsap.set(path, { drawSVG: on ? "100%" : "0%" }); return; }
  gsap.timeline()
    .to(check, { scale: 0.8, duration: 0.08 })
    .to(check, { scale: 1, duration: 0.55, ease: "elastic.out(1.2, 0.45)" })
    .to(path, { drawSVG: on ? "100%" : "0%", duration: 0.3, ease: "power2.out" }, 0.05);
}
function fillRange(input) {
  input.style.setProperty("--fill", `${((input.value - input.min) / (input.max - input.min)) * 100}%`);
}
function placeThumb(seg, animate = true) {
  const on = $('[aria-checked="true"]', seg);
  const thumb = $(".thumb", seg);
  if (!on || !thumb) return;
  const vars = { x: on.offsetLeft - 2, width: on.offsetWidth };
  if (animate && !reduce) gsap.to(thumb, { ...vars, duration: 0.5, ease: "back.out(1.7)" });
  else gsap.set(thumb, vars);
}
function setText(el, text) {
  if (el.textContent === text) return false;
  el.textContent = text;
  return true;
}
function flash(el) {
  if (reduce) return;
  gsap.fromTo(el, { backgroundColor: "var(--left-tint)" }, { backgroundColor: "rgba(0,0,0,0)", duration: 1.4, ease: "power2.out", clearProps: "backgroundColor" });
}
// Press squash and hover lift for every button-like control.
const PRESSABLE = ".btn, .chip, .check, .seg button, .icon-btn, .nav button";
document.addEventListener("pointerdown", (e) => {
  const b = e.target.closest(PRESSABLE);
  if (b && !b.disabled && !reduce) gsap.to(b, { scale: 0.95, duration: 0.08, overwrite: "auto" });
});
const release = (e) => {
  const b = e.target.closest && e.target.closest(PRESSABLE);
  if (b && !reduce) gsap.to(b, { scale: 1, duration: 0.5, ease: "elastic.out(1, 0.5)", overwrite: "auto" });
};
document.addEventListener("pointerup", release);
document.addEventListener("pointerout", (e) => {
  const b = e.target.closest && e.target.closest(".btn");
  if (b && !b.contains(e.relatedTarget) && !reduce) gsap.to(b, { y: 0, scale: 1, duration: 0.3, overwrite: "auto" });
});
document.addEventListener("pointerover", (e) => {
  const b = e.target.closest(".btn");
  if (b && !b.disabled && !b.contains(e.relatedTarget) && !reduce) gsap.to(b, { y: -1.5, duration: 0.25, ease: "power2.out", overwrite: "auto" });
});
document.addEventListener("pointerdown", (e) => { if (e.target.type === "range") e.target.dataset.dragging = "1"; });
document.addEventListener("pointerup", () => $$('[data-dragging="1"]').forEach((el) => { delete el.dataset.dragging; }));

/* ---------- navigation ---------- */
function movePill(animate) {
  const b = $(`.nav button[data-tab="${page}"]`);
  gsap.to(".nav .pill", { y: b.offsetTop, duration: animate && !reduce ? 0.55 : 0, ease: "back.out(1.5)" });
}
function enterPage(section) {
  if (reduce) return gsap.timeline();
  const tl = gsap.timeline();
  const h1 = $("[data-split]", section);
  if (!h1.split) h1.split = SplitText.create(h1, { type: "chars", charsClass: "char" });
  tl.from(h1.split.chars, { yPercent: 110, rotate: 8, autoAlpha: 0, duration: 0.6, ease: "back.out(1.8)", stagger: 0.05 })
    .from($$("[data-enter]", section), { y: 22, autoAlpha: 0, duration: 0.6, ease: "power3.out", stagger: 0.05 }, "<0.1");
  if (section.id === "page-speakers") tl.from($$(".unit", section), { y: 26, autoAlpha: 0, duration: 0.6, ease: "power3.out", stagger: 0.07 }, "<0.2");
  if (section.id === "page-calibrate") tl.from($$(".checks > div", section), { x: -14, autoAlpha: 0, duration: 0.45, ease: "power2.out", stagger: 0.07 }, "<0.1");
  if (section.id === "page-settings") tl.from($$(".setting", section), { x: 18, autoAlpha: 0, duration: 0.5, ease: "power3.out", stagger: 0.06 }, "<0.05");
  return tl;
}
function showPage(name) {
  if (name === page) return;
  const from = $(`#page-${page}`);
  const to = $(`#page-${name}`);
  page = name;
  $$(".nav button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === name));
  movePill(true);
  gsap.timeline()
    .to(from, { y: -12, autoAlpha: 0, duration: reduce ? 0 : 0.2, ease: "power2.in" })
    .add(() => {
      from.hidden = true;
      gsap.set(from, { clearProps: "all" });
      to.hidden = false;
      $("#body").scrollTop = 0;
      $$(".seg", to).forEach((seg) => placeThumb(seg, false));
      if (name === "speakers") { keys.map = null; drawMap(true); }
      if (name === "calibrate") placePhantom(false);
      enterPage(to);
    });
}
$$(".nav button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.tab)));

/* ---------- speakers: pairs and singles ---------- */
function units(speakers) {
  const byAddress = new Map(speakers.map((s) => [s.address, s]));
  const seen = new Set();
  const out = [];
  for (const s of speakers) {
    if (seen.has(s.address)) continue;
    const p = s.partner && byAddress.get(s.partner);
    if (p && p.partner === s.address) {
      const [l, r] = s.mode === 1 ? [s, p] : [p, s];
      out.push({ kind: "pair", l, r, id: `pair:${[l.address, r.address].sort().join("|")}`, selected: l.selected && r.selected });
      seen.add(l.address); seen.add(r.address);
    } else {
      out.push({ kind: "single", s, id: s.address, selected: s.selected });
      seen.add(s.address);
    }
  }
  // Stereo pairs are the main way to play, so they lead the list.
  return [...out.filter((u) => u.kind === "pair"), ...out.filter((u) => u.kind === "single")];
}
const unpaired = (exclude) => S.speakers.filter((s) => !s.partner && s.address !== exclude);
const controlsHtml = (s, side) => `
  <span class="ctl">延迟 <input class="num-in" data-field="delay" data-addr="${esc(s.address)}" type="number" min="0" max="2000" step="0.1" value="${s.delay.toFixed(1)}" ${S.editable ? "" : "disabled"} aria-label="${esc(s.name)} 延迟（毫秒）"> ms</span>
  <span class="ctl">电平修正 <input class="num-in" data-field="trim" data-addr="${esc(s.address)}" type="number" min="-24" max="0" step="0.1" value="${s.trim.toFixed(1)}" ${S.editable ? "" : "disabled"} aria-label="${esc(s.name)} 电平修正（dB）" title="校准写入的 PCM 衰减，只降低较响的一台"> dB</span>
  <span class="ctl">独立音量 <input data-field="volume" data-addr="${esc(s.address)}" type="range" min="0" max="100" value="${s.volume}" aria-label="${esc(s.name)} 独立音量" ${S.volumeEditable ? "" : "disabled"} ${side ? `style="--track: var(--${side})"` : ""}><span class="vol-out num" data-out="${esc(s.address)}">${s.volume}%</span></span>`;
const checkHtml = (address, on, label) => `<button class="check" role="checkbox" aria-checked="${on}" data-act="select" data-addr="${esc(address)}" aria-label="${esc(label)}" ${S.editable ? "" : "disabled"}><svg viewBox="0 0 14 14"><path d="M3 7.5 6 10l5-6"/></svg></button>`;
const passwordHtml = (s) => (s.needsPassword ? '<span class="tag" title="音响开启了连接密码；可在家庭 App 调整访问设置">需要连接密码（暂不支持）</span>' : "");
const targetHtml = (s) => `<button class="chip" data-act="target" data-addr="${esc(s.address)}" aria-pressed="${s.target}" title="播放测试音和 PIN 配对使用这台音响">测试目标</button>`;
function memberHtml(s, side) {
  return `<div class="member ${side} ${s.target ? "target" : ""}" data-flip-id="${esc(s.address)}">
    <span class="badge ${side}">${side === "left" ? "左" : "右"}</span>
    <span class="m-name"><b>${esc(s.name)}</b><span class="addr num">${esc(s.address)}</span></span>
    ${passwordHtml(s)}
    ${controlsHtml(s, side)}
    <span class="level num" data-level="${esc(s.address)}">${esc(s.level)}</span>
    ${targetHtml(s)}
  </div>`;
}
function unitHtml(u) {
  if (u.kind === "pair") {
    return `<article class="unit pair" data-flip-id="${esc(u.id)}">
      <header class="unit-head">
        ${checkHtml(u.l.address, u.selected, `桥接立体声对 ${u.l.name} 与 ${u.r.name}`)}
        <span class="unit-title"><b>${esc(u.l.name)} + ${esc(u.r.name)}</b><span class="tag">立体声对</span></span>
        <span class="spacer"></span>
        <button class="btn small" data-act="swap" data-addr="${esc(u.l.address)}" ${S.editable ? "" : "disabled"}>左右互换</button>
        <button class="btn small" data-act="unpair" data-addr="${esc(u.l.address)}" ${S.editable ? "" : "disabled"}>拆分</button>
      </header>
      <div class="members">${memberHtml(u.l, "left")}${memberHtml(u.r, "right")}</div>
    </article>`;
  }
  const s = u.s;
  const orphan = s.mode === 1 || s.mode === 2;
  const side = s.mode === 1 ? "left" : s.mode === 2 ? "right" : "";
  const candidates = unpaired(s.address);
  const chooser = pairing === s.address && candidates.length
    ? `<div class="chooser" data-flip-id="chooser:${esc(s.address)}"><p>这台作为${s.mode === 2 ? "右" : "左"}声道，选择另一台作为${s.mode === 2 ? "左" : "右"}声道：</p>
        ${candidates.map((c) => `<button class="btn small" data-act="pick" data-addr="${esc(s.address)}" data-partner="${esc(c.address)}">${esc(c.name)}</button>`).join("")}
        <button class="chip" data-act="cancel-pick">取消</button></div>`
    : "";
  return `<article class="unit single ${orphan ? "orphan" : ""} ${s.target ? "target" : ""}" data-flip-id="${esc(u.id)}">
    <header class="unit-head">
      ${checkHtml(s.address, s.selected, `桥接到 ${s.name}`)}
      <span class="unit-title" data-flip-id="name:${esc(s.address)}"><b>${esc(s.name)}</b><span class="addr num">${esc(s.address)}</span>${passwordHtml(s)}</span>
      <span class="spacer"></span>
      <span class="level num" data-level="${esc(s.address)}">${esc(s.level)}</span>
      ${targetHtml(s)}
    </header>
    <div class="unit-body">
      <div class="seg" role="radiogroup" aria-label="${esc(s.name)} 声道"><span class="thumb"></span>
        ${SINGLE_MODES.map((m) => `<button role="radio" data-act="mode" data-addr="${esc(s.address)}" data-mode="${m}" aria-checked="${m === s.mode}" ${S.editable ? "" : "disabled"}>${CHANNELS[m]}</button>`).join("")}
      </div>
      ${candidates.length && pairing !== s.address ? `<button class="btn small" data-act="pairwith" data-addr="${esc(s.address)}" ${S.editable ? "" : "disabled"}>组成立体声对</button>` : ""}
      ${controlsHtml(s, side)}
    </div>
    ${orphan && pairing !== s.address ? `<p class="warn-line">这台只播放${side === "left" ? "左" : "右"}声道，缺少${side === "left" ? "右" : "左"}声道搭档；组成立体声对或改回立体声。</p>` : ""}
    ${chooser}
  </article>`;
}
function renderUnits(animate) {
  const host = $("#units");
  const flipState = animate && !reduce && host.children.length ? Flip.getState("#units [data-flip-id]") : null;
  const list = units(S.speakers);
  host.innerHTML = list.length ? list.map(unitHtml).join("") : `<div class="empty">还没有音响：点击「扫描音响」，或在下方输入 IP 地址添加。</div>`;
  $$(".seg", host).forEach((seg) => placeThumb(seg, false));
  $$('input[type="range"]', host).forEach(fillRange);
  $$(".check", host).forEach((c) => gsap.set($("path", c), { drawSVG: c.getAttribute("aria-checked") === "true" ? "100%" : "0%" }));
  if (flipState) {
    Flip.from(flipState, {
      targets: "#units [data-flip-id]", duration: 0.65, ease: "power3.inOut", nested: true, prune: true,
      onEnter: (els) => gsap.fromTo(els, { autoAlpha: 0, y: 18 }, { autoAlpha: 1, y: 0, duration: 0.5, ease: "power3.out", stagger: 0.05 }),
    });
  }
}
function updateUnitValues() {
  for (const s of S.speakers) {
    const level = $(`[data-level="${CSS.escape(s.address)}"]`);
    if (level && setText(level, s.level) && !reduce) gsap.fromTo(level, { y: -3, autoAlpha: 0.4 }, { y: 0, autoAlpha: 1, duration: 0.3 });
    for (const field of ["delay", "trim", "volume"]) {
      const input = $(`[data-field="${field}"][data-addr="${CSS.escape(s.address)}"]`);
      if (!input) continue;
      if (field !== "volume") input.disabled = !S.editable;
      if (busyField(input)) continue;
      const value = field === "volume" ? String(s.volume) : s[field].toFixed(1);
      if (input.value !== value) { input.value = value; if (field === "volume") fillRange(input); else flash(input); }
      if (field === "volume") { input.disabled = !S.volumeEditable; setText($(`[data-out="${CSS.escape(s.address)}"]`), `${s.volume}%`); }
    }
  }
}
$("#units").addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el || el.disabled) return;
  const address = el.dataset.addr;
  const s = S.speakers.find((x) => x.address === address);
  switch (el.dataset.act) {
    case "select": {
      const on = el.getAttribute("aria-checked") !== "true";
      setChecked(el, on);
      send("route", { address, selected: on });
      break;
    }
    case "mode": {
      const mode = Number(el.dataset.mode);
      $$("button", el.parentElement).forEach((b) => b.setAttribute("aria-checked", b === el));
      placeThumb(el.parentElement);
      send("route", { address, mode });
      // Choosing one side of the stereo image means finding its other half.
      pairing = (mode === 1 || mode === 2) && unpaired(address).length ? address : null;
      if (pairing) { keys.units = null; }
      break;
    }
    case "pairwith": pairing = address; keys.units = null; render(); break;
    case "cancel-pick": pairing = null; keys.units = null; render(); break;
    case "pick": {
      const partner = el.dataset.partner;
      const right = s && s.mode === 2;
      send("makePair", right ? { left: partner, right: address } : { left: address, right: partner });
      pairing = null;
      break;
    }
    case "swap": send("swapPair", { address }); break;
    case "unpair": send("unpair", { address }); break;
    case "target": send("setTarget", { address }); break;
  }
});
$("#units").addEventListener("input", (e) => {
  const input = e.target;
  if (input.dataset.field !== "volume") return;
  fillRange(input);
  setText($(`[data-out="${CSS.escape(input.dataset.addr)}"]`), `${input.value}%`);
  send("route", { address: input.dataset.addr, volume: Number(input.value) });
});
$("#units").addEventListener("focusout", () => setTimeout(render));
$("#units").addEventListener("change", (e) => {
  const input = e.target;
  if (input.dataset.field !== "delay" && input.dataset.field !== "trim") return;
  const value = Number(input.value);
  if (Number.isFinite(value)) send("route", { address: input.dataset.addr, [input.dataset.field]: value });
});

/* ---------- input meter: the captured CABLE Output peak while live ---------- */
const meterTo = gsap.quickTo("#meter-bar", "scaleX", { duration: 0.15, ease: "power2.out" });
function renderMeter() {
  const meter = $("#meter");
  const on = S.inputLevel !== null && S.inputLevel !== undefined;
  if (meter.hidden === on) { meter.hidden = !on; if (on && !reduce) gsap.from(meter, { x: -6, autoAlpha: 0, duration: 0.35, ease: "power3.out" }); }
  if (!on) { meterTo(0); return; }
  const fraction = Math.max(0, Math.min(1, (S.inputLevel + 60) / 60));
  if (reduce) gsap.set("#meter-bar", { scaleX: fraction }); else meterTo(fraction);
  setText($("#meter-db"), S.inputLevel <= -60 ? "无信号" : `${Math.round(S.inputLevel)} dB`);
  setText($("#dropped"), S.droppedPackets ? `丢包 ${S.droppedPackets}` : "");
}

/* ---------- notices: Home App pairs and channels without a partner ---------- */
function renderNotices() {
  const notes = [];
  const groups = new Map();
  for (const s of S.speakers) if (s.homePair && !s.partner) groups.set(s.homePair, [...(groups.get(s.homePair) || []), s]);
  for (const members of groups.values()) {
    if (members.length === 2) notes.push({ kind: "info", text: `「${members[0].name}」与「${members[1].name}」在家庭 App 中是一个立体声对，建议在这里也组成立体声对。`, act: "home", a: members[0].address, b: members[1].address });
  }
  for (const s of S.speakers) {
    if (s.selected && !s.partner && (s.mode === 1 || s.mode === 2)) {
      const side = s.mode === 1 ? "左" : "右";
      notes.push({ kind: "warn", text: `「${s.name}」只播放${side}声道，另一半声音没有音响播放。`, act: "orphan", a: s.address });
    }
  }
  if (!changed("notices", notes)) return;
  const host = $("#notices");
  host.innerHTML = notes.map((n) => `<div class="notice ${n.kind === "info" ? "info" : ""}"><span class="lamp"><i></i></span><p>${esc(n.text)}</p>${
    n.act === "home" ? `<button class="btn small" data-note="home" data-a="${esc(n.a)}" data-b="${esc(n.b)}">组成立体声对</button>`
      : `<button class="btn small" data-note="partner" data-a="${esc(n.a)}">选择搭档</button><button class="btn small" data-note="stereo" data-a="${esc(n.a)}">改回立体声</button>`}</div>`).join("");
  if (!reduce && notes.length) gsap.from($$(".notice", host), { height: 0, paddingTop: 0, paddingBottom: 0, autoAlpha: 0, duration: 0.5, ease: "power3.out", stagger: 0.06, clearProps: "height,paddingTop,paddingBottom" });
}
$("#notices").addEventListener("click", (e) => {
  const b = e.target.closest("[data-note]");
  if (!b) return;
  if (b.dataset.note === "home") send("makePair", { left: b.dataset.a, right: b.dataset.b });
  if (b.dataset.note === "stereo") send("route", { address: b.dataset.a, mode: 0 });
  if (b.dataset.note === "partner") { pairing = b.dataset.a; keys.units = null; render(); }
});

/* ---------- route map: the source splits into each pair's two channels ---------- */
let flows = [];
function mapRows() {
  const inSession = new Set(S.session);
  const live = S.busy && S.session.length;
  return units(S.speakers).filter((u) => (live
    ? (u.kind === "pair" ? inSession.has(u.l.address) : inSession.has(u.s.address))
    : u.selected));
}
function drawMap(animate) {
  const rows = mapRows();
  const live = S.run === "live";
  const source = S.devices[S.device] ? "CABLE Output" : "未发现 CABLE Output";
  const signature = [rows.map((u) => u.kind === "pair" ? [u.l.name, u.r.name] : [u.s.name, u.s.mode]), live, source, document.documentElement.dataset.theme, $("#map").clientWidth];
  if (!changed("map", signature)) return;
  flows.forEach((t) => t.kill());
  flows = [];
  const svg = $("#map");
  const ns = "http://www.w3.org/2000/svg";
  const el = (tag, attrs, parent = svg) => {
    const node = document.createElementNS(ns, tag);
    for (const k in attrs) node.setAttribute(k, attrs[k]);
    parent.appendChild(node);
    return node;
  };
  const width = Math.max($(".map").clientWidth, 480);
  const ROW = 46, GAP = 14;
  const slots = rows.reduce((n, u) => n + (u.kind === "pair" ? 2 : 1), 0);
  const height = Math.max(slots * ROW + Math.max(rows.length - 1, 0) * GAP + 40, 118);
  svg.innerHTML = "";
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);
  svg.classList.toggle("live", live);
  const wires = el("g", {});
  const pill = (x, y, text, anchorRight, cls, tag) => {
    const g = el("g", {});
    const rect = el("rect", { class: `node ${cls || ""}`, height: 32, rx: 16, "stroke-width": live && cls ? 1.4 : 0 }, g);
    const label = el("text", {}, g);
    label.textContent = text;
    const tagWidth = tag ? 26 : 0;
    const w = label.getComputedTextLength() + 30 + tagWidth;
    const left = anchorRight ? x - w : x;
    rect.setAttribute("x", left); rect.setAttribute("y", y - 16); rect.setAttribute("width", w);
    label.setAttribute("x", left + 15 + tagWidth); label.setAttribute("y", y);
    if (tag) {
      el("circle", { cx: left + 22, cy: y, r: 10, class: tag.cls }, g);
      const t = el("text", { x: left + 22, y, class: "tag-ink" }, g);
      t.textContent = tag.text;
    }
    return { g, left, right: left + w };
  };
  const cy = height / 2;
  const src = pill(18, cy, source, false);
  if (!rows.length) {
    const t = el("text", { x: src.right + 28, y: cy, class: "muted" });
    t.textContent = "勾选音响或立体声对后，这里显示声音的去向";
    if (animate && !reduce) gsap.from([src.g, t], { autoAlpha: 0, x: -10, duration: 0.5, stagger: 0.1 });
    return;
  }
  const start = [src.right, cy];
  const curve = (a, b) => { const bend = (b[0] - a[0]) / 2; return `C${a[0] + bend},${a[1]} ${b[0] - bend},${b[1]} ${b[0]},${b[1]}`; };
  let y = cy - (slots * ROW + (rows.length - 1) * GAP) / 2;
  const branches = [];
  rows.forEach((u) => {
    if (u.kind === "pair") {
      const yl = y + ROW / 2, yr = y + ROW * 1.5;
      const l = pill(width - 18, yl, u.l.name, true, "node-live-left", { text: "左", cls: "tag-left" });
      const r = pill(width - 18, yr, u.r.name, true, "node-live-right", { text: "右", cls: "tag-right" });
      const nodeLeft = Math.min(l.left, r.left);
      const junction = [start[0] + (nodeLeft - start[0]) * 0.52, (yl + yr) / 2];
      const trunk = el("path", { class: "wire", d: `M${start} ${curve(start, junction)}` }, wires);
      const toL = el("path", { class: "wire wire-left", d: `M${junction} ${curve(junction, [l.left, yl])}` }, wires);
      const toR = el("path", { class: "wire wire-right", d: `M${junction} ${curve(junction, [r.left, yr])}` }, wires);
      el("circle", { class: "junction", cx: junction[0], cy: junction[1], r: 4 }, wires);
      const label = el("text", { class: "pair-label", x: junction[0], y: junction[1] - 16 });
      label.textContent = "立体声对";
      branches.push({ parts: [trunk, toL, toR], nodes: [l.g, r.g], extra: [label],
        flows: [[`M${start} ${curve(start, junction)} ${curve(junction, [l.left, yl])}`, "dot-left"], [`M${start} ${curve(start, junction)} ${curve(junction, [r.left, yr])}`, "dot-right"]] });
      y += ROW * 2 + GAP;
    } else {
      const s = u.s;
      const side = s.mode === 1 ? "left" : s.mode === 2 ? "right" : "";
      const yy = y + ROW / 2;
      const node = pill(width - 18, yy, `${s.name} · ${CHANNELS[s.mode]}`, true, side ? `node-live-${side}` : "node-live", side ? { text: CHANNELS[s.mode], cls: `tag-${side}` } : null);
      const d = `M${start} ${curve(start, [node.left, yy])}`;
      const wire = el("path", { class: `wire ${side ? `wire-${side}` : ""}`, d }, wires);
      branches.push({ parts: [wire], nodes: [node.g], extra: [], flows: [[d, side ? `dot-${side}` : "dot"]] });
      y += ROW + GAP;
    }
  });
  if (animate && !reduce) {
    gsap.from(src.g, { x: -16, autoAlpha: 0, duration: 0.5, ease: "power3.out" });
    branches.forEach((b, i) => {
      gsap.from(b.parts, { drawSVG: "0%", duration: 0.85, ease: "power2.inOut", delay: 0.1 + i * 0.1, stagger: 0.25 });
      gsap.from(b.nodes, { x: 26, autoAlpha: 0, duration: 0.6, ease: "back.out(1.6)", delay: 0.45 + i * 0.1, stagger: 0.08 });
      if (b.extra.length) gsap.from(b.extra, { autoAlpha: 0, y: 6, duration: 0.4, delay: 0.6 + i * 0.1 });
    });
  }
  if (live && !reduce) {
    branches.forEach((b, i) => b.flows.forEach(([d, cls], j) => {
      const path = el("path", { d, fill: "none", stroke: "none" }, wires);
      for (let k = 0; k < 3; k++) {
        const dot = el("circle", { r: 3.4, class: cls }, wires);
        flows.push(gsap.timeline({ repeat: -1, delay: k * 0.8 + i * 0.17 + j * 0.4 })
          .fromTo(dot, { autoAlpha: 0 }, { autoAlpha: 1, duration: 0.3 }, 0)
          .to(dot, { motionPath: { path, align: path, alignOrigin: [0.5, 0.5] }, duration: 2.4, ease: "none" }, 0)
          .to(dot, { autoAlpha: 0, duration: 0.3 }, 2.1));
      }
    }));
  }
}
window.addEventListener("resize", () => S && drawMap(false));

/* ---------- calibration: where the stereo image sits between the pair ---------- */
let shownResult = null;
const resultLabel = (r) => (Math.abs(r.ms) <= 0.2 && Math.abs(r.db) <= 0.5 ? "声像居中（已对齐）" : "已应用修正，请再次测量验证");
function phantomX(ms) {
  // The earlier speaker pulls the image towards itself (precedence effect);
  // about 1.5 ms already moves it most of the way.
  return 320 - Math.max(-1, Math.min(1, ms / 1.5)) * 200;
}
function placePhantom(animate) {
  const r = S && S.lastResult;
  gsap.set("#phantom", { x: 320, y: 64 });
  gsap.to("#phantom", { autoAlpha: r ? 1 : 0.35, duration: animate ? 0.4 : 0 });
  setText($("#phantom-label"), r ? resultLabel(r) : S && S.calPair.left ? "等待测量" : "需要一个立体声对");
}
function showResult(r) {
  const ms = $("#fig-ms"), db = $("#fig-db");
  const shown = { ms: 0, db: 0 };
  const write = () => {
    ms.textContent = `${r.ms >= 0 ? "晚" : "早"} ${Math.abs(shown.ms).toFixed(2)} ms`;
    db.textContent = `${shown.db > 0 ? "+" : shown.db < 0 ? "−" : ""}${Math.abs(shown.db).toFixed(1)} dB`;
  };
  if (reduce) { shown.ms = r.ms; shown.db = r.db; write(); return; }
  gsap.to(shown, { ms: r.ms, db: r.db, duration: 1.2, ease: "power3.out", onUpdate: write });
  gsap.from([ms, db], { y: 14, scale: 0.92, duration: 0.7, ease: "back.out(2)", stagger: 0.1 });
  // Show where the image was, then let it settle in the centre the trims create.
  const before = phantomX(r.ms);
  const side = r.ms > 0.05 ? "偏左" : r.ms < -0.05 ? "偏右" : "居中";
  gsap.timeline()
    .set("#phantom", { autoAlpha: 1 })
    .add(() => setText($("#phantom-label"), `校准前声像${side}`))
    .to("#phantom", { x: before, duration: 0.7, ease: "power3.out" })
    .to("#phantom .phantom-halo", { scale: 1.6, transformOrigin: "50% 50%", duration: 0.35, yoyo: true, repeat: 1 }, "<0.3")
    .to("#phantom", { x: 320, duration: 1.1, ease: "elastic.out(1, 0.55)" }, "+=0.5")
    .add(() => setText($("#phantom-label"), resultLabel(r)), "<0.2");
}
function renderCalibrate(first) {
  const checks = [
    [S.connected, "桥接已连接", "在左侧点击「开始桥接」"],
    [S.checks.pair, "一个立体声对，没有其他音响", "在「音响」页只勾选一个立体声对"],
    [S.checks.mic, "已找到物理麦克风", "连接麦克风后点击刷新"],
  ];
  if (changed("checks", checks)) {
    $("#checks").innerHTML = checks.map(([ok, done, todo]) => `<div class="${ok ? "ok" : "todo"}"><span class="lamp"><i></i></span><span>${ok ? done : todo}</span></div>`).join("");
    if (!first && !reduce) gsap.from("#checks .lamp", { scale: 0, duration: 0.5, ease: "back.out(3)", stagger: 0.06 });
  }
  const toggle = $("#test-toggle"), measure = $("#measure");
  const ready = S.connected && !S.measuring && !S.transition;
  toggle.disabled = !ready;
  swapLabel(toggle, S.testMode ? "结束连续测试" : "开启连续测试");
  measure.disabled = !(ready && S.testMode === 1 && S.testVolume > 0);
  measure.classList.toggle("primary", S.busy && !measure.disabled);
  $("#mic").disabled = S.measuring;
  const tv = $("#test-volume");
  tv.disabled = !S.testVolumeEditable;
  if (!busyField(tv) && tv.value !== String(S.testVolume)) { tv.value = S.testVolume; fillRange(tv); }
  setText($("#test-volume-out"), `${busyField(tv) ? tv.value : S.testVolume}%`);
  const box = $("#progress");
  if (S.progress) {
    if (box.hidden) { box.hidden = false; if (!reduce) gsap.fromTo(box, { autoAlpha: 0, y: 8 }, { autoAlpha: 1, y: 0, duration: 0.35 }); }
    setText($("#progress-label"), S.progress.label);
    gsap.to("#progress-bar", { scaleX: S.progress.fraction, duration: 0.2, ease: "none", overwrite: true });
  } else if (!box.hidden && !box.dataset.leaving) {
    box.dataset.leaving = "1";
    gsap.to("#progress-bar", { scaleX: 1, duration: 0.2 });
    gsap.to(box, { autoAlpha: 0, y: -6, duration: 0.3, delay: 0.2, onComplete: () => { box.hidden = true; delete box.dataset.leaving; gsap.set(box, { clearProps: "all" }); gsap.set("#progress-bar", { scaleX: 0 }); } });
  }
  const find = (address) => S.speakers.find((s) => s.address === address);
  for (const [side, address] of [["l", S.calPair.left], ["r", S.calPair.right]]) {
    const s = find(address);
    setText($(`#cal-${side}-name`), s ? s.name : "—");
    setText($(`#stage-${side}-name`), s ? s.name : "—");
    for (const [field, text] of [["delay", s ? `${s.delay.toFixed(1)} ms` : "—"], ["trim", s ? `${s.trim > 0 ? "+" : s.trim < 0 ? "−" : ""}${Math.abs(s.trim).toFixed(1)} dB` : "—"]]) {
      const cell = $(`#cal-${side}-${field}`);
      if (setText(cell, text) && !first) flash(cell);
    }
  }
  const result = JSON.stringify(S.lastResult);
  if (result !== shownResult) {
    const firstSight = shownResult === null;
    shownResult = result;
    if (S.lastResult && !firstSight) showResult(S.lastResult);
    else if (S.lastResult) { const r = S.lastResult; $("#fig-ms").textContent = `${r.ms >= 0 ? "晚" : "早"} ${Math.abs(r.ms).toFixed(2)} ms`; $("#fig-db").textContent = `${r.db > 0 ? "+" : r.db < 0 ? "−" : ""}${Math.abs(r.db).toFixed(1)} dB`; placePhantom(false); }
    else { $("#fig-ms").textContent = "—"; $("#fig-db").textContent = "—"; placePhantom(false); }
  }
  if (first) placePhantom(false);
}
$("#test-toggle").addEventListener("click", () => send("toggleTest"));
$("#measure").addEventListener("click", () => send("measure"));
$("#test-volume").addEventListener("input", (e) => { fillRange(e.target); setText($("#test-volume-out"), `${e.target.value}%`); });
$("#test-volume").addEventListener("change", (e) => send("setTestVolume", { value: Number(e.target.value) }));
$("#mic").addEventListener("change", (e) => send("setMic", { index: Number(e.target.value) }));

/* ---------- sidebar run state ---------- */
let lampPulse = null;
function renderRun(first) {
  const [label, color] = {
    live: ["正在播放", "var(--positive)"],
    connecting: ["正在连接", "var(--warning)"],
    pairing: ["正在配对", "var(--warning)"],
    tone: ["正在播放测试音", "var(--warning)"],
  }[S.run] || ["已停止", "var(--lamp-idle)"];
  if (!changed("run", S.run) && !first) return;
  gsap.to("#state", { color, duration: 0.4 });
  gsap.to("#strip-lamp", { color, duration: 0.4 });
  const stateLabel = $("#state-label");
  if (first || reduce) stateLabel.textContent = label;
  else gsap.timeline().to(stateLabel, { autoAlpha: 0, x: -6, duration: 0.15 }).add(() => { stateLabel.textContent = label; }).to(stateLabel, { autoAlpha: 1, x: 0, duration: 0.35, ease: "power3.out" });
  if (lampPulse) lampPulse.kill();
  const ring = $("#state .ring");
  gsap.set(ring, { scale: 1, autoAlpha: 0 });
  if (S.run !== "idle" && !reduce) lampPulse = gsap.fromTo(ring, { scale: 0.6, autoAlpha: 0.8 }, { scale: 2.2, autoAlpha: 0, duration: S.run === "live" ? 1.6 : 0.8, ease: "power2.out", repeat: -1 });
  const start = $("#start");
  swapLabel(start, S.busy ? "停止" : "开始桥接");
  start.classList.toggle("primary", !S.busy);
}
$("#start").addEventListener("click", () => send(S && S.busy ? "stop" : "start"));
$("#master").addEventListener("input", (e) => { fillRange(e.target); setText($("#master-out"), `${e.target.value}%`); send("setMaster", { value: Number(e.target.value) }); });

/* ---------- status strip ---------- */
function renderStatus(first) {
  const p = $("#status");
  if (!changed("status", S.status) && !first) return;
  if (first || reduce) { p.textContent = S.status; return; }
  gsap.timeline()
    .to(p, { y: -8, autoAlpha: 0, duration: 0.16, ease: "power2.in" })
    .add(() => { p.textContent = S.status; })
    .fromTo(p, { y: 8, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.42, ease: "power3.out" });
}

/* ---------- top-level render ---------- */
function options(select, names, index, empty) {
  if (changed(`opt:${select.id}`, [names, index])) {
    select.innerHTML = names.length ? names.map((n, i) => `<option value="${i}">${esc(n)}</option>`).join("") : `<option>${esc(empty)}</option>`;
    select.value = String(index);
  }
}
function render(first = false) {
  if (!S) return;
  renderRun(first);
  renderStatus(first);
  const master = $("#master");
  master.disabled = !S.masterEditable;
  if (!busyField(master) && master.value !== String(S.master)) { master.value = S.master; fillRange(master); setText($("#master-out"), `${S.master}%`); }
  // Speakers page
  const list = units(S.speakers);
  const pairs = list.filter((u) => u.kind === "pair" && u.selected).length;
  const singles = list.filter((u) => u.kind === "single" && u.selected).length;
  const parts = [pairs && `${pairs} 个立体声对`, singles && `${singles} 台音响`].filter(Boolean).join("、");
  const lede = !S.speakers.length ? "局域网内的 AirPlay 音响会出现在这里。"
    : S.run === "live" ? `正在播放到 ${parts || "所选音响"}。`
    : parts ? `已选 ${parts}，共 ${S.speakers.length} 台音响。` : `共 ${S.speakers.length} 台音响，尚未选择。`;
  setText($("#lede"), lede);
  const scan = $("#scan");
  scan.disabled = S.scanning;
  swapLabel(scan, S.scanning ? "正在扫描…" : "扫描音响");
  options($("#device"), S.devices, S.device, "未发现 CABLE Output");
  $("#driver-page").hidden = S.devices.length > 0;
  renderMeter();
  options($("#mic"), S.mics, S.mic, "未发现麦克风");
  const host = $("#host");
  if (!busyField(host) && host.value !== S.host) host.value = S.host;
  $("#tone").disabled = S.busy;
  $("#pair-device").disabled = S.busy;
  const pinRow = $("#pin-row");
  if (pinRow.hidden === S.pinRequested) {
    pinRow.hidden = !S.pinRequested;
    if (S.pinRequested) { $("#pin").focus(); if (!reduce) gsap.from(pinRow, { y: 10, autoAlpha: 0, duration: 0.4, ease: "back.out(2)" }); }
  }
  const repairRow = $("#repair-row");
  if (repairRow.hidden === S.repairConfirm) {
    repairRow.hidden = !S.repairConfirm;
    if (S.repairConfirm) { $("#repair-confirm").focus(); if (!reduce) gsap.from(repairRow, { y: 10, autoAlpha: 0, duration: 0.4, ease: "back.out(2)" }); }
  }
  const structure = [S.speakers.map((s) => [s.address, s.name, s.selected, s.mode, s.partner, s.target, s.needsPassword]), S.editable, S.volumeEditable, pairing];
  // Rebuilding would wipe the value being typed or dragged; focusout renders again.
  const active = document.activeElement;
  const editing = ($("#units").contains(active) && active.matches(".num-in")) || $('#units [data-dragging="1"]');
  if (!editing && changed("units", structure)) renderUnits(!first);
  else updateUnitValues();
  renderNotices();
  if (page === "speakers") drawMap(!first);
  renderCalibrate(first);
  // Settings
  const seg = $("#theme-seg");
  $$("button", seg).forEach((b) => b.setAttribute("aria-checked", b.dataset.theme === S.theme));
  if (changed("themeSeg", S.theme)) placeThumb(seg, !first && page === "settings");
  const buffer = $("#buffer");
  buffer.disabled = S.busy;
  if (!busyField(buffer) && buffer.value !== String(S.bufferMs)) { buffer.value = S.bufferMs; fillRange(buffer); }
  setText($("#buffer-out"), `${busyField(buffer) ? buffer.value : S.bufferMs} ms`);
  const reconnect = $("#reconnect");
  reconnect.disabled = S.busy;
  $("#import-legacy").disabled = S.busy;
  setChecked(reconnect, S.reconnect, !first);
  setText($("#diag-cpu"), S.cpu);
  setText($("#diag-webview"), S.webview);
}
$("#scan").addEventListener("click", () => send("scan"));
$("#device").addEventListener("change", (e) => send("setDevice", { index: Number(e.target.value) }));
$("#host").addEventListener("change", (e) => send("setHost", { host: e.target.value }));
$("#host").addEventListener("keydown", (e) => { if (e.key === "Enter") { send("setHost", { host: e.target.value }); send("addHost"); } });
$("#pin-submit").addEventListener("click", () => { send("submitPin", { pin: $("#pin").value }); $("#pin").value = ""; });
$("#repair-confirm").addEventListener("click", () => send("pairDevice", { replace: true }));
$("#pin").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#pin-submit").click(); });
$$("[data-cmd]").forEach((b) => b.addEventListener("click", () => {
  if (b.dataset.cmd === "addHost" || b.dataset.cmd === "tone" || b.dataset.cmd === "pairDevice") send("setHost", { host: $("#host").value });
  send(b.dataset.cmd);
}));
$$("#theme-seg button").forEach((b) => b.addEventListener("click", () => {
  $$("#theme-seg button").forEach((x) => x.setAttribute("aria-checked", x === b));
  placeThumb($("#theme-seg"));
  applyTheme(b.dataset.theme, true);
  send("setTheme", { theme: b.dataset.theme });
}));
$("#buffer").addEventListener("input", (e) => { fillRange(e.target); setText($("#buffer-out"), `${e.target.value} ms`); });
$("#buffer").addEventListener("change", (e) => send("setBuffer", { value: Number(e.target.value) }));
$("#reconnect").addEventListener("click", (e) => {
  const on = e.currentTarget.getAttribute("aria-checked") !== "true";
  setChecked(e.currentTarget, on);
  send("setReconnect", { on });
});

/* ---------- the opening ---------- */
function intro() {
  if (reduce) return;
  const tl = gsap.timeline({ defaults: { ease: "power3.out" } });
  tl.from(".sheet", { x: 36, autoAlpha: 0, duration: 0.8 })
    .from(".logo", { scale: 0.4, rotate: -20, autoAlpha: 0, transformOrigin: "50% 50%", duration: 0.7, ease: "back.out(2)" }, 0.05)
    .from(".logo-l", { x: -70, duration: 0.9, ease: "elastic.out(1, 0.6)" }, 0.2)
    .from(".logo-r", { x: 70, duration: 0.9, ease: "elastic.out(1, 0.6)" }, 0.2)
    .from(".logo-lens", { scale: 0, transformOrigin: "50% 50%", duration: 0.5, ease: "back.out(3)" }, 0.65)
    .from(".wordmark > *", { x: -10, autoAlpha: 0, duration: 0.5, stagger: 0.08 }, 0.3)
    .from("#theme-toggle", { scale: 0, duration: 0.5, ease: "back.out(2)" }, 0.45)
    .from(".nav button, .side-foot > *", { x: -16, autoAlpha: 0, duration: 0.5, stagger: 0.06 }, 0.4)
    .from(".nav .pill", { scaleX: 0, transformOrigin: "left center", duration: 0.5 }, 0.55)
    .add(enterPage($("#page-speakers")), 0.45)
    .from(".strip", { yPercent: 100, autoAlpha: 0, duration: 0.6 }, 0.7);
}

window.duetto = {
  update(state) {
    const first = S === null;
    const themeChanged = S && S.theme !== state.theme;
    S = state;
    if (first || themeChanged) applyTheme(S.theme, !first);
    if (first) {
      movePill(false);
      $$(".seg").forEach((seg) => placeThumb(seg, false));
    }
    render(first);
    if (first) document.fonts.ready.then(() => { keys.map = null; drawMap(true); intro(); });
  },
};
gsap.set(["#theme-toggle .sun", "#theme-toggle .moon"], { transformOrigin: "50% 50%" });
if (window.ipc) send("ready");
else {
  // Development in a plain browser: a scripted backend stands in for Rust.
  const script = document.createElement("script");
  script.src = "mock.js";
  document.body.appendChild(script);
}
