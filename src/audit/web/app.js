"use strict";

const state = {
  token: sessionStorage.getItem("auditToken") || "", range: "24h", customStart: "", customEnd: "",
  page: 1, pages: 1, usagePage: 1, usagePages: 1, configUsagePage: 1, configUsagePages: 1,
  timer: null, dashboardLoading: false, detailsLoading: false, series: [], flowItems: [], chartHover: null,
};
const $ = (id) => document.getElementById(id);
const rangeLabels = { "1h": "最近 1 小时", "6h": "最近 6 小时", "24h": "最近 24 小时", "7d": "最近 7 天", "30d": "最近 30 天", all: "全部时间" };
const svgNamespace = "http://www.w3.org/2000/svg";

function formatBytes(value, suffix = "") {
  let number = Number(value) || 0;
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let unit = 0;
  while (Math.abs(number) >= 1024 && unit < units.length - 1) { number /= 1024; unit += 1; }
  const digits = unit === 0 ? 0 : number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits)} ${units[unit]}${suffix}`;
}

function formatTime(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value));
}

function localInputValue(date) {
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function timeParams() {
  const params = new URLSearchParams({ range: state.range === "custom" ? "24h" : state.range });
  if (state.range === "custom" && state.customStart && state.customEnd) {
    params.set("start", new Date(state.customStart).toISOString());
    params.set("end", new Date(state.customEnd).toISOString());
  }
  return params;
}

function timeLabel() {
  if (state.range !== "custom") return rangeLabels[state.range];
  return `${formatTime(state.customStart)} 至 ${formatTime(state.customEnd)}`;
}

function escapeHtml(value) {
  const node = document.createElement("span");
  node.textContent = value == null ? "" : String(value);
  return node.innerHTML;
}

function shortLabel(value, length = 16) {
  const label = String(value || "—");
  return label.length > length ? `${label.slice(0, length - 1)}…` : label;
}

const requestTimeout = 12000;

// Browsers describe network-level failures with opaque English messages such as
// "Failed to fetch". Translate them so the status text stays actionable.
function failureMessage(error) {
  const message = String((error && error.message) || "");
  if (error && error.name === "AbortError") return "请求超时";
  if (/failed to fetch|networkerror|load failed|network error/i.test(message)) return "无法连接审计服务";
  return message || "无法连接审计服务";
}

// Fire-and-forget user actions still need a visible failure instead of an
// unhandled promise rejection in the console.
function runAction(promise) {
  promise.catch((error) => toast(failureMessage(error)));
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), requestTimeout);
  let response;
  try {
    response = await fetch(path, { ...options, headers, cache: "no-store", signal: controller.signal });
  } catch (error) {
    throw new Error(failureMessage(error));
  } finally {
    window.clearTimeout(timer);
  }
  if (response.status === 401) {
    sessionStorage.removeItem("auditToken");
    showTokenDialog();
    throw new Error("访问令牌无效");
  }
  if (!response.ok) throw new Error(`请求失败 (${response.status})`);
  try {
    return await response.json();
  } catch (error) {
    throw new Error("审计服务返回了无效数据");
  }
}

function showTokenDialog(message = "") {
  $("tokenError").textContent = message;
  const dialog = $("tokenDialog");
  if (!dialog.open) dialog.showModal();
}

// Schedule the next refresh only once the current round has finished, so a slow
// response cannot stack parallel rounds on top of each other.
function startRefreshTimer() {
  if (state.timer) window.clearTimeout(state.timer);
  state.timer = window.setTimeout(async () => {
    await loadDashboard();
    startRefreshTimer();
  }, 5000);
}

let lastToast = { message: "", at: 0 };

function toast(message) {
  const text = String(message || "");
  const now = Date.now();
  if (text === lastToast.message && now - lastToast.at < 5000) return;
  lastToast = { message: text, at: now };
  const element = $("toast");
  element.textContent = text;
  element.classList.add("show");
  window.setTimeout(() => element.classList.remove("show"), 2200);
}

function collectorDetail(collector) {
  const reason = (collector && collector.last_error) || "无法连接 sing-box API";
  const failures = Number(collector && collector.failures) || 0;
  return failures > 1 ? `${reason} · 已连续失败 ${failures} 次，重试中` : reason;
}

function setHealth(collector) {
  const element = $("health");
  const connected = Boolean(collector && collector.connected);
  const detail = connected ? `每 ${collector.interval} 秒采集` : collectorDetail(collector);
  element.className = `health ${connected ? "ok" : "error"}`;
  element.querySelector("span").textContent = connected ? "采集正常" : "采集异常";
  element.title = detail;
  $("collectorStatus").textContent = connected ? "采集正常" : "采集异常";
  $("collectorCopy").textContent = connected ? `所有节点正常 · 每 ${collector.interval} 秒更新` : detail;
  document.querySelector(".pulse-panel").classList.toggle("error", !connected);
}

// The browser cannot reach the audit service at all: a different failure than
// the collector failing to read the sing-box Clash API.
function setServiceHealth(message) {
  const element = $("health");
  element.className = "health error";
  element.querySelector("span").textContent = "服务异常";
  element.title = message || "无法连接审计服务";
}

function renderSummary(data) {
  const total = Math.max(0, Number(data.total) || 0);
  const download = Math.max(0, Number(data.download) || 0);
  const upload = Math.max(0, Number(data.upload) || 0);
  const downloadPercent = total ? download / total * 100 : 50;
  $("totalTraffic").textContent = formatBytes(total);
  $("downloadTraffic").textContent = formatBytes(download);
  $("uploadTraffic").textContent = formatBytes(upload);
  $("activeConnections").textContent = new Intl.NumberFormat("zh-CN").format(data.active_connections || 0);
  $("allConnections").textContent = new Intl.NumberFormat("zh-CN").format(data.connections || 0);
  $("uniqueClients").textContent = new Intl.NumberFormat("zh-CN").format(data.unique_clients || 0);
  $("uniqueDestinations").textContent = new Intl.NumberFormat("zh-CN").format(data.unique_destinations || 0);
  $("downRate").textContent = formatBytes(data.download_speed, "/s");
  $("upRate").textContent = formatBytes(data.upload_speed, "/s");
  $("liveRate").textContent = formatBytes((data.upload_speed || 0) + (data.download_speed || 0), "/s");
  $("downloadShare").style.width = `${downloadPercent}%`;
  $("uploadShare").style.width = `${100 - downloadPercent}%`;
  $("rangeCopy").textContent = timeLabel();
  setHealth(data.collector);
}

function drawTrafficChart(points = state.series, hoverIndex = state.chartHover) {
  state.series = points || [];
  const canvas = $("trafficChart");
  const empty = $("emptyChart");
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  const context = canvas.getContext("2d");
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  const width = rect.width;
  const height = rect.height;
  const pad = { top: 16, right: 14, bottom: 27, left: 52 };
  context.clearRect(0, 0, width, height);
  if (!state.series.length || !state.series.some((point) => point.upload || point.download)) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  const max = Math.max(...state.series.flatMap((point) => [point.upload, point.download]), 1);
  const baseline = height - pad.bottom;
  const x = (index) => pad.left + index * (width - pad.left - pad.right) / Math.max(1, state.series.length - 1);
  const y = (value) => pad.top + (1 - value / max) * (height - pad.top - pad.bottom);
  context.font = "9px ui-monospace, monospace";
  context.textAlign = "left";
  context.lineWidth = 1;
  for (let index = 0; index <= 4; index += 1) {
    const gridY = pad.top + index * (height - pad.top - pad.bottom) / 4;
    context.strokeStyle = "rgba(37,57,91,.09)";
    context.beginPath();
    context.moveTo(pad.left, gridY);
    context.lineTo(width - pad.right, gridY);
    context.stroke();
    context.fillStyle = "#7a8498";
    context.fillText(formatBytes(max * (4 - index) / 4), 0, gridY + 3);
  }

  const series = [
    { key: "download", color: "#3568d4", fill: "rgba(53,104,212,.2)" },
    { key: "upload", color: "#3a9de0", fill: "rgba(58,157,224,.13)" },
  ];
  series.forEach(({ key, color, fill }) => {
    context.beginPath();
    context.moveTo(x(0), baseline);
    state.series.forEach((point, index) => context.lineTo(x(index), y(point[key])));
    context.lineTo(x(state.series.length - 1), baseline);
    context.closePath();
    const gradient = context.createLinearGradient(0, pad.top, 0, baseline);
    gradient.addColorStop(0, fill);
    gradient.addColorStop(1, "rgba(255,255,255,0)");
    context.fillStyle = gradient;
    context.fill();
    context.beginPath();
    state.series.forEach((point, index) => index ? context.lineTo(x(index), y(point[key])) : context.moveTo(x(index), y(point[key])));
    context.strokeStyle = color;
    context.lineWidth = 1.8;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.stroke();
  });

  const labelCount = Math.min(6, state.series.length);
  for (let index = 0; index < labelCount; index += 1) {
    const pointIndex = Math.round(index * (state.series.length - 1) / Math.max(1, labelCount - 1));
    const date = new Date(state.series[pointIndex].ts * 1000);
    const label = state.range === "1h" || state.range === "6h" || state.range === "24h"
      ? date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })
      : date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
    context.fillStyle = "#7a8498";
    context.textAlign = index === 0 ? "left" : index === labelCount - 1 ? "right" : "center";
    context.fillText(label, x(pointIndex), height - 4);
  }

  if (hoverIndex != null && state.series[hoverIndex]) {
    const hoverX = x(hoverIndex);
    context.strokeStyle = "rgba(53,104,212,.3)";
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(hoverX, pad.top);
    context.lineTo(hoverX, baseline);
    context.stroke();
    series.forEach(({ key, color }) => {
      context.fillStyle = "#fff";
      context.strokeStyle = color;
      context.lineWidth = 2;
      context.beginPath();
      context.arc(hoverX, y(state.series[hoverIndex][key]), 4, 0, Math.PI * 2);
      context.fill();
      context.stroke();
    });
  }
}

function renderDestinations(items) {
  const container = $("destinations");
  const sorted = (items || []).filter((item) => item.upload + item.download > 0).sort((a, b) => (b.upload + b.download) - (a.upload + a.download));
  container.replaceChildren();
  if (!sorted.length) {
    const empty = document.createElement("div");
    empty.className = "visual-empty";
    empty.textContent = "暂无目标记录";
    container.append(empty);
    return;
  }
  const rows = [[], []];
  const sums = [0, 0];
  sorted.forEach((item) => {
    const rowIndex = sums[0] <= sums[1] ? 0 : 1;
    rows[rowIndex].push(item);
    sums[rowIndex] += item.upload + item.download;
  });
  const grandTotal = sums[0] + sums[1];
  const colors = ["#315fca", "#3e70d6", "#557fe0", "#6689e3", "#7897e6", "#8ba7e8", "#9ab3ea", "#a9beeb"];
  rows.filter((row) => row.length).forEach((row, rowIndex) => {
    const rowElement = document.createElement("div");
    rowElement.className = "treemap-row";
    const rowTotal = sums[rowIndex] || 1;
    row.forEach((item, itemIndex) => {
      const total = item.upload + item.download;
      const cell = document.createElement("div");
      cell.className = "treemap-cell";
      cell.style.flexGrow = String(Math.max(1, total / rowTotal * 100));
      cell.style.flexBasis = "0";
      cell.style.background = colors[(itemIndex + rowIndex * 3) % colors.length];
      cell.title = `${item.name} · ${formatBytes(total)}`;
      const name = document.createElement("strong");
      name.textContent = item.name || "未知目标";
      const value = document.createElement("small");
      value.textContent = `${(total / grandTotal * 100).toFixed(1)}% · ${formatBytes(total)}`;
      cell.append(name, value);
      rowElement.append(cell);
    });
    container.append(rowElement);
  });
}

function renderConfigChart(items) {
  const container = $("configChart");
  const rows = (items || []).filter((item) => item.total > 0).slice(0, 6);
  container.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "visual-empty";
    empty.textContent = "等待配置流量数据";
    container.append(empty);
    return;
  }
  const maximum = Math.max(...rows.map((item) => item.total), 1);
  rows.forEach((item) => {
    const row = document.createElement("div");
    row.className = "config-row";
    const name = document.createElement("span");
    name.className = "config-name";
    name.textContent = item.config_name || "未识别";
    name.title = item.config_name || "未识别";
    const track = document.createElement("span");
    track.className = "config-track";
    track.style.width = `${Math.max(2, item.total / maximum * 100)}%`;
    track.title = `下载 ${formatBytes(item.download)} · 上传 ${formatBytes(item.upload)}`;
    const download = document.createElement("i");
    const upload = document.createElement("b");
    download.style.width = `${item.total ? item.download / item.total * 100 : 50}%`;
    upload.style.width = `${item.total ? item.upload / item.total * 100 : 50}%`;
    track.append(download, upload);
    const total = document.createElement("span");
    total.className = "config-total";
    total.textContent = formatBytes(item.total);
    row.append(name, track, total);
    container.append(row);
  });
}

function renderHeatmap(cells) {
  const container = $("heatmap");
  const values = new Map((cells || []).map((cell) => [`${cell.weekday}:${cell.hour}`, cell.total]));
  container.replaceChildren();
  if (!values.size || ![...values.values()].some(Boolean)) {
    const empty = document.createElement("div");
    empty.className = "visual-empty";
    empty.textContent = "等待时间分布数据";
    container.append(empty);
    return;
  }
  const maximum = Math.max(...values.values(), 1);
  const blank = document.createElement("span");
  blank.className = "heatmap-hour";
  container.append(blank);
  for (let hour = 0; hour < 24; hour += 1) {
    const label = document.createElement("span");
    label.className = "heatmap-hour";
    label.textContent = hour % 3 === 0 ? String(hour).padStart(2, "0") : "";
    container.append(label);
  }
  const weekdays = [[1, "周一"], [2, "周二"], [3, "周三"], [4, "周四"], [5, "周五"], [6, "周六"], [0, "周日"]];
  weekdays.forEach(([day, dayLabel]) => {
    const label = document.createElement("span");
    label.className = "heatmap-label";
    label.textContent = dayLabel;
    container.append(label);
    for (let hour = 0; hour < 24; hour += 1) {
      const value = values.get(`${day}:${hour}`) || 0;
      const cell = document.createElement("span");
      cell.className = "heatmap-cell";
      const intensity = value ? .12 + value / maximum * .88 : 0;
      cell.style.background = value ? `rgba(53,104,212,${intensity.toFixed(2)})` : "#eef2f8";
      cell.title = `${dayLabel} ${String(hour).padStart(2, "0")}:00 · ${formatBytes(value)}`;
      cell.setAttribute("aria-label", cell.title);
      container.append(cell);
    }
  });
}

function svgElement(name, attributes = {}, text = "") {
  const element = document.createElementNS(svgNamespace, name);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  if (text) element.textContent = text;
  return element;
}

function renderFlow(items = state.flowItems) {
  state.flowItems = items || [];
  const svg = $("flowChart");
  const empty = $("flowEmpty");
  svg.replaceChildren();
  if (!state.flowItems.length || !state.flowItems.some((item) => item.total > 0)) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  const rect = svg.getBoundingClientRect();
  const width = Math.max(600, rect.width);
  const height = Math.max(230, rect.height);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const stages = ["source", "config", "route", "target"];
  const stageLabels = ["来源 IP", "配置", "路由", "目标"];
  const stageColors = ["#3568d4", "#6d68d8", "#ef9b3d", "#3a9de0"];
  const columns = stages.map(() => new Map());
  const links = new Map();
  state.flowItems.forEach((item) => {
    const total = Math.max(0, Number(item.total) || 0);
    const nodes = stages.map((stage, index) => {
      const label = item[stage] || "未识别";
      const id = `${stage}:${label}`;
      if (!columns[index].has(id)) columns[index].set(id, { id, label, value: 0, stage: index });
      const node = columns[index].get(id);
      node.value += total;
      return node;
    });
    for (let index = 0; index < nodes.length - 1; index += 1) {
      const key = `${nodes[index].id}\u0000${nodes[index + 1].id}`;
      if (!links.has(key)) links.set(key, { from: nodes[index].id, to: nodes[index + 1].id, value: 0, stage: index });
      links.get(key).value += total;
    }
  });
  const xPositions = [10, width * .28, width * .55, width * .8];
  const nodeWidth = 9;
  const nodePositions = new Map();
  columns.forEach((column, columnIndex) => {
    const nodes = [...column.values()].sort((a, b) => b.value - a.value);
    const top = 29;
    const bottom = 10;
    const gap = 7;
    const usable = Math.max(1, height - top - bottom - Math.max(0, nodes.length - 1) * gap);
    const minimum = Math.min(15, usable / Math.max(1, nodes.length));
    const extra = Math.max(0, usable - minimum * nodes.length);
    const total = nodes.reduce((sum, node) => sum + node.value, 0) || 1;
    let y = top;
    nodes.forEach((node) => {
      const nodeHeight = minimum + extra * node.value / total;
      nodePositions.set(node.id, { ...node, x: xPositions[columnIndex], y, width: nodeWidth, height: nodeHeight });
      y += nodeHeight + gap;
    });
    svg.append(svgElement("text", { x: xPositions[columnIndex], y: 12, fill: "#6f788b", "font-size": 8, "font-weight": 700 }, stageLabels[columnIndex]));
  });

  const maximumLink = Math.max(...[...links.values()].map((link) => link.value), 1);
  links.forEach((link) => {
    const from = nodePositions.get(link.from);
    const to = nodePositions.get(link.to);
    if (!from || !to) return;
    const startX = from.x + from.width;
    const endX = to.x;
    const startY = from.y + from.height / 2;
    const endY = to.y + to.height / 2;
    const curve = Math.max(24, (endX - startX) * .48);
    const path = svgElement("path", {
      d: `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`,
      fill: "none", stroke: stageColors[link.stage], "stroke-opacity": .17,
      "stroke-width": Math.max(1.5, link.value / maximumLink * 13), "stroke-linecap": "round",
    });
    path.append(svgElement("title", {}, formatBytes(link.value)));
    svg.append(path);
  });
  columns.forEach((column, columnIndex) => {
    column.forEach((node) => {
      const position = nodePositions.get(node.id);
      svg.append(svgElement("rect", {
        x: position.x, y: position.y, width: position.width, height: position.height,
        rx: 2, fill: stageColors[columnIndex], opacity: .9,
      }));
      const label = svgElement("text", {
        x: position.x + 14, y: position.y + position.height / 2,
        fill: "#3d475a", "font-size": 8.5, "dominant-baseline": "middle",
      }, shortLabel(position.label, 15));
      label.append(svgElement("title", {}, `${position.label} · ${formatBytes(position.value)}`));
      svg.append(label);
    });
  });
}

function renderConnections(data) {
  state.pages = data.pages;
  state.page = data.page;
  $("pageInfo").textContent = `第 ${data.page} / ${data.pages} 页 · ${data.total} 条`;
  $("prevPage").disabled = data.page <= 1;
  $("nextPage").disabled = data.page >= data.pages;
  const body = $("connectionRows");
  if (!data.items.length) { body.innerHTML = '<tr><td colspan="9" class="empty-row">当前筛选条件下没有审计记录</td></tr>'; return; }
  body.innerHTML = data.items.map((item) => {
    const target = item.host || item.destination || item.destination_ip || "—";
    const source = `${item.source_ip || "—"}${item.source_port ? `:${item.source_port}` : ""}`;
    const user = item.user || item.config_name || "匿名";
    const config = item.config_name || item.inbound || "—";
    const route = item.chains && item.chains.length ? item.chains.join(" → ") : (item.outbound || "—");
    return `<tr><td>${formatTime(item.start)}</td><td title="${escapeHtml(source)}">${escapeHtml(source)}</td><td title="${escapeHtml(target)}">${escapeHtml(target)}<small>${item.destination_port ? `端口 ${item.destination_port}` : ""}</small></td><td title="${escapeHtml(user)}">${escapeHtml(user)}<small>${escapeHtml(config)}</small></td><td>${escapeHtml(item.protocol || item.network || "—")}</td><td title="${escapeHtml(route)}">${escapeHtml(route)}</td><td class="number upload">${formatBytes(item.upload)}</td><td class="number download">${formatBytes(item.download)}</td><td><span class="status-pill ${item.status}">${item.status === "active" ? "活动" : "已结束"}</span></td></tr>`;
  }).join("");
}

function renderUsage(data) {
  state.usagePages = data.pages;
  state.usagePage = data.page;
  $("usagePageInfo").textContent = `第 ${data.page} / ${data.pages} 页 · ${data.total} 组`;
  $("usagePrevPage").disabled = data.page <= 1;
  $("usageNextPage").disabled = data.page >= data.pages;
  const body = $("usageRows");
  if (!data.items.length) { body.innerHTML = '<tr><td colspan="9" class="empty-row">当前时间段没有可归属的 IP 流量</td></tr>'; return; }
  body.innerHTML = data.items.map((item) => `<tr><td>${escapeHtml(item.source_ip || "未知")}</td><td title="${escapeHtml(item.config_name)}">${escapeHtml(item.config_name || "未识别")}</td><td title="${escapeHtml(item.user)}">${escapeHtml(item.user || "—")}</td><td>${formatTime(item.first_seen_at)}</td><td>${formatTime(item.last_seen_at)}</td><td class="number">${new Intl.NumberFormat("zh-CN").format(item.connections)}</td><td class="number upload">${formatBytes(item.upload)}</td><td class="number download">${formatBytes(item.download)}</td><td class="number total-value">${formatBytes(item.total)}</td></tr>`).join("");
}

function renderConfigUsage(data) {
  state.configUsagePages = data.pages;
  state.configUsagePage = data.page;
  $("configUsagePageInfo").textContent = `第 ${data.page} / ${data.pages} 页 · ${data.total} 个配置`;
  $("configUsagePrevPage").disabled = data.page <= 1;
  $("configUsageNextPage").disabled = data.page >= data.pages;
  const body = $("configUsageRows");
  if (!data.items.length) { body.innerHTML = '<tr><td colspan="9" class="empty-row">当前时间段没有可归属的配置流量</td></tr>'; return; }
  body.innerHTML = data.items.map((item) => `<tr><td title="${escapeHtml(item.config_name)}">${escapeHtml(item.config_name || "未识别")}</td><td>${formatTime(item.first_seen_at)}</td><td>${formatTime(item.last_seen_at)}</td><td class="number">${new Intl.NumberFormat("zh-CN").format(item.clients)}</td><td class="number">${new Intl.NumberFormat("zh-CN").format(item.users)}</td><td class="number">${new Intl.NumberFormat("zh-CN").format(item.connections)}</td><td class="number upload">${formatBytes(item.upload)}</td><td class="number download">${formatBytes(item.download)}</td><td class="number total-value">${formatBytes(item.total)}</td></tr>`).join("");
}

async function loadOptions() {
  const data = await api(`/api/options?${timeParams()}`);
  const select = $("protocol");
  const selected = select.value;
  select.innerHTML = '<option value="">全部协议</option>' + data.protocols.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  select.value = selected;
}

function connectionQuery() {
  const params = timeParams();
  params.set("page", String(state.page));
  params.set("limit", "50");
  if ($("search").value.trim()) params.set("search", $("search").value.trim());
  if ($("protocol").value) params.set("protocol", $("protocol").value);
  if ($("status").value) params.set("status", $("status").value);
  return params;
}

function usageQuery() {
  const params = timeParams();
  params.set("page", String(state.usagePage));
  params.set("limit", "50");
  if ($("usageSearch").value.trim()) params.set("search", $("usageSearch").value.trim());
  return params;
}

function configUsageQuery() {
  const params = timeParams();
  params.set("page", String(state.configUsagePage));
  params.set("limit", "50");
  if ($("configUsageSearch").value.trim()) params.set("config_search", $("configUsageSearch").value.trim());
  return params;
}

async function loadConnections() { renderConnections(await api(`/api/connections?${connectionQuery()}`)); }
async function loadUsage() { renderUsage(await api(`/api/client-usage?${usageQuery()}`)); }
async function loadConfigUsage() { renderConfigUsage(await api(`/api/config-usage?${configUsageQuery()}`)); }

async function loadDetailData() {
  if (state.detailsLoading) return;
  state.detailsLoading = true;
  try {
    await Promise.all([loadConfigUsage(), loadUsage(), loadConnections(), loadOptions()]);
  } finally {
    state.detailsLoading = false;
  }
}

async function loadDashboard(showNotice = false) {
  if (state.dashboardLoading) return;
  state.dashboardLoading = true;
  try {
    const query = timeParams();
    const activityQuery = new URLSearchParams(query);
    activityQuery.set("timezone_offset", String(new Date().getTimezoneOffset()));
    const configQuery = new URLSearchParams(query);
    configQuery.set("page", "1");
    configQuery.set("limit", "6");
    const [summary, series, destinations, activity, flow, configs] = await Promise.all([
      api(`/api/summary?${query}`),
      api(`/api/timeseries?${query}`),
      api(`/api/top-destinations?${query}`),
      api(`/api/activity?${activityQuery}`),
      api(`/api/traffic-flow?${query}`),
      api(`/api/config-usage?${configQuery}`),
    ]);
    renderSummary(summary);
    state.chartHover = null;
    $("chartTooltip").hidden = true;
    drawTrafficChart(series.points);
    renderDestinations(destinations.items);
    renderConfigChart(configs.items);
    renderHeatmap(activity.cells);
    renderFlow(flow.items);
    if ($("recordsDrawer").open) await loadDetailData();
    if (showNotice) toast("数据已刷新");
  } catch (error) {
    if (error.message !== "访问令牌无效") {
      setServiceHealth(error.message);
      // Background refreshes already report the problem in the header, so only
      // surface the toast for a refresh the user explicitly asked for.
      if (showNotice) toast(error.message);
    }
  } finally {
    state.dashboardLoading = false;
  }
}

function downloadConnections(format) {
  const params = connectionQuery();
  params.delete("page");
  params.delete("limit");
  params.set("format", format);
  fetch(`/api/export?${params}`, { headers: { Authorization: `Bearer ${state.token}` } })
    .then((response) => { if (!response.ok) throw new Error("导出失败"); const disposition = response.headers.get("Content-Disposition") || ""; const name = disposition.match(/filename="([^"]+)"/)?.[1] || `sing-box-audit.${format}`; return Promise.all([response.blob(), name]); })
    .then(([blob, name]) => { const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url); toast(`已导出 ${format.toUpperCase()}`); })
    .catch((error) => toast(failureMessage(error)));
}

function downloadUsage(format) {
  const params = usageQuery();
  params.delete("page");
  params.delete("limit");
  params.set("format", format);
  fetch(`/api/usage-export?${params}`, { headers: { Authorization: `Bearer ${state.token}` } })
    .then((response) => { if (!response.ok) throw new Error("导出失败"); const disposition = response.headers.get("Content-Disposition") || ""; const name = disposition.match(/filename="([^"]+)"/)?.[1] || `sing-box-audit-usage.${format}`; return Promise.all([response.blob(), name]); })
    .then(([blob, name]) => { const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url); toast(`已导出 IP / 配置用量 ${format.toUpperCase()}`); })
    .catch((error) => toast(failureMessage(error)));
}

function downloadConfigUsage(format) {
  const params = configUsageQuery();
  params.delete("page");
  params.delete("limit");
  params.set("format", format);
  fetch(`/api/config-usage-export?${params}`, { headers: { Authorization: `Bearer ${state.token}` } })
    .then((response) => { if (!response.ok) throw new Error("导出失败"); const disposition = response.headers.get("Content-Disposition") || ""; const name = disposition.match(/filename="([^"]+)"/)?.[1] || `sing-box-audit-config-usage.${format}`; return Promise.all([response.blob(), name]); })
    .then(([blob, name]) => { const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url); toast(`已导出配置文件用量 ${format.toUpperCase()}`); })
    .catch((error) => toast(failureMessage(error)));
}

let searchTimer;
let usageSearchTimer;
let configUsageSearchTimer;
$("range").addEventListener("change", () => {
  state.range = $("range").value;
  state.page = 1;
  state.usagePage = 1;
  state.configUsagePage = 1;
  $("customRange").hidden = state.range !== "custom";
  if (state.range !== "custom") loadDashboard();
});
$("applyRange").addEventListener("click", () => {
  const start = $("rangeStart").value;
  const end = $("rangeEnd").value;
  if (!start || !end || new Date(start) > new Date(end)) { toast("请选择有效的开始和结束时间"); return; }
  state.customStart = start;
  state.customEnd = end;
  state.page = 1;
  state.usagePage = 1;
  state.configUsagePage = 1;
  loadDashboard(true);
});
$("refresh").addEventListener("click", () => loadDashboard(true));
$("protocol").addEventListener("change", () => { state.page = 1; runAction(loadConnections()); });
$("status").addEventListener("change", () => { state.page = 1; runAction(loadConnections()); });
$("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { state.page = 1; runAction(loadConnections()); }, 280); });
$("usageSearch").addEventListener("input", () => { clearTimeout(usageSearchTimer); usageSearchTimer = setTimeout(() => { state.usagePage = 1; runAction(loadUsage()); }, 280); });
$("configUsageSearch").addEventListener("input", () => { clearTimeout(configUsageSearchTimer); configUsageSearchTimer = setTimeout(() => { state.configUsagePage = 1; runAction(loadConfigUsage()); }, 280); });
$("prevPage").addEventListener("click", () => { if (state.page > 1) { state.page -= 1; runAction(loadConnections()); } });
$("nextPage").addEventListener("click", () => { if (state.page < state.pages) { state.page += 1; runAction(loadConnections()); } });
$("usagePrevPage").addEventListener("click", () => { if (state.usagePage > 1) { state.usagePage -= 1; runAction(loadUsage()); } });
$("usageNextPage").addEventListener("click", () => { if (state.usagePage < state.usagePages) { state.usagePage += 1; runAction(loadUsage()); } });
$("configUsagePrevPage").addEventListener("click", () => { if (state.configUsagePage > 1) { state.configUsagePage -= 1; runAction(loadConfigUsage()); } });
$("configUsageNextPage").addEventListener("click", () => { if (state.configUsagePage < state.configUsagePages) { state.configUsagePage += 1; runAction(loadConfigUsage()); } });
$("exportCsv").addEventListener("click", () => downloadConnections("csv"));
$("usageExportCsv").addEventListener("click", () => downloadUsage("csv"));
$("usageExportJson").addEventListener("click", () => downloadUsage("json"));
$("configUsageExportCsv").addEventListener("click", () => downloadConfigUsage("csv"));
$("configUsageExportJson").addEventListener("click", () => downloadConfigUsage("json"));
$("exportJson").addEventListener("click", () => downloadConnections("json"));
$("recordsDrawer").addEventListener("toggle", () => { if ($("recordsDrawer").open) runAction(loadDetailData()); });
document.querySelectorAll("[data-record-tab]").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll("[data-record-tab]").forEach((item) => {
    const selected = item === button;
    item.classList.toggle("active", selected);
    item.setAttribute("aria-selected", String(selected));
  });
  document.querySelectorAll("[data-record-panel]").forEach((panel) => {
    const selected = panel.dataset.recordPanel === button.dataset.recordTab;
    panel.hidden = !selected;
    panel.classList.toggle("active", selected);
  });
}));
$("trafficChart").addEventListener("pointermove", (event) => {
  if (!state.series.length) return;
  const rect = $("trafficChart").getBoundingClientRect();
  const padLeft = 52;
  const padRight = 14;
  const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left - padLeft) / Math.max(1, rect.width - padLeft - padRight)));
  const index = Math.round(ratio * (state.series.length - 1));
  const point = state.series[index];
  state.chartHover = index;
  drawTrafficChart();
  const tooltip = $("chartTooltip");
  tooltip.innerHTML = `<strong>${formatTime(point.time || point.ts * 1000)}</strong><span class="download">下载 ${formatBytes(point.download)}</span><br><span class="upload">上传 ${formatBytes(point.upload)}</span>`;
  tooltip.hidden = false;
  tooltip.style.left = `${Math.max(8, Math.min(rect.width - 150, event.clientX - rect.left + 14))}px`;
  tooltip.style.top = "32px";
});
$("trafficChart").addEventListener("pointerleave", () => {
  state.chartHover = null;
  $("chartTooltip").hidden = true;
  drawTrafficChart();
});
$("tokenForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = $("tokenInput").value.trim();
  try {
    const response = await fetch("/api/auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
    if (!response.ok) throw new Error("访问令牌无效，请重新输入");
    state.token = token;
    sessionStorage.setItem("auditToken", token);
    $("tokenDialog").close();
    $("tokenError").textContent = "";
    loadDashboard();
    startRefreshTimer();
  } catch (error) {
    $("tokenError").textContent = failureMessage(error);
  }
});
window.addEventListener("resize", () => {
  clearTimeout(window.__chartResize);
  window.__chartResize = setTimeout(() => { drawTrafficChart(); renderFlow(); }, 120);
});

async function boot() {
  const now = new Date();
  const yesterday = new Date(now.getTime() - 86400000);
  $("rangeStart").value = localInputValue(yesterday);
  $("rangeEnd").value = localInputValue(now);
  state.customStart = $("rangeStart").value;
  state.customEnd = $("rangeEnd").value;
  try {
    const health = await fetch("/api/health", { cache: "no-store" }).then((response) => response.json());
    if (health.auth_required && !state.token) { showTokenDialog(); return; }
    await loadDashboard();
  } catch (error) {
    const message = failureMessage(error);
    setServiceHealth(message);
    toast(message);
  }
  // A service that is still restarting when the page loads must recover on its
  // own instead of staying dead until the next manual reload.
  startRefreshTimer();
}

boot();
