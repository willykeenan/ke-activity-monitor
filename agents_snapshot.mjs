#!/usr/bin/env node

import { readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const CPU_PRODUCT = "cpu-workers";
const GPU_PRODUCT = "gpu-workers";
const CACHE_ROOT = join(homedir(), ".codex", "plugins", "cache", "personal");
const MAX_POOLS = 64;
const MAX_WORKERS = 256;
const MAX_JOBS = 256;
const MAX_HINTS = 64;
function existing(path) {
  try {
    return statSync(path).isFile() ? path : null;
  } catch {
    return null;
  }
}

function newestCachedLib(product) {
  const root = join(CACHE_ROOT, product);
  try {
    return readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
      .map((entry) => {
        const lib = join(root, entry.name, "scripts", "lib.mjs");
        try {
          return { lib: existing(lib), modified: statSync(lib).mtimeMs };
        } catch {
          return null;
        }
      })
      .filter((entry) => entry?.lib)
      .sort((a, b) => b.modified - a.modified)[0]?.lib || null;
  } catch {
    return null;
  }
}

function resolveLib(product, envName) {
  const candidates = [
    process.env[envName],
    newestCachedLib(product),
    join(homedir(), "plugins", product, "scripts", "lib.mjs"),
  ];
  for (const candidate of candidates) {
    const path = candidate && existing(candidate);
    if (path) return path;
  }
  throw new Error(`${product} observer is not installed`);
}

function bounded(items, max) {
  return Array.isArray(items) ? items.slice(0, max) : [];
}

function compactWorker(worker) {
  return {
    id: worker?.id ?? null,
    label: worker?.label ?? null,
    pid: worker?.pid ?? null,
    ppid: worker?.ppid ?? null,
    state: worker?.state ?? null,
    osState: worker?.osState ?? null,
    cpuPercent: worker?.cpuPercent ?? null,
    rssBytes: worker?.rssBytes ?? null,
    elapsed: worker?.elapsed ?? null,
    assignment: worker?.assignment ?? null,
    executable: worker?.executable ?? null,
    source: worker?.source ?? null,
  };
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function compactCpu(snapshot) {
  return {
    kind: snapshot?.kind ?? "cpu-workers-snapshot",
    schemaVersion: snapshot?.schemaVersion ?? null,
    generatedAt: snapshot?.generatedAt ?? null,
    collectionMs: snapshot?.collectionMs ?? null,
    host: snapshot?.host ?? null,
    discovery: snapshot?.discovery ? {
      state: snapshot.discovery.state ?? null,
      mode: snapshot.discovery.mode ?? null,
      detail: snapshot.discovery.detail ?? null,
    } : null,
    counts: snapshot?.counts ?? null,
    pools: bounded(snapshot?.pools, MAX_POOLS).map((pool) => ({
        id: pool?.id ?? null,
        title: pool?.title ?? null,
        source: pool?.source ?? null,
        registered: pool?.registered === true,
        runState: pool?.runState ?? null,
        parent: pool?.parent ? {
          pid: pool.parent.pid ?? null,
          processAlive: pool.parent.processAlive === true,
          state: pool.parent.state ?? null,
        } : null,
        totals: pool?.totals ?? null,
        progress: pool?.progress ?? null,
        failures: pool?.failures ?? null,
        retries: pool?.retries ?? null,
        handoff: pool?.handoff ?? null,
        workers: bounded(pool?.workers, MAX_WORKERS).map(compactWorker),
      })),
    boundary: snapshot?.boundary ?? null,
  };
}

function compactGpu(snapshot) {
  return {
    kind: snapshot?.kind ?? "gpu-workers-snapshot",
    schemaVersion: snapshot?.schemaVersion ?? null,
    generatedAt: snapshot?.generatedAt ?? null,
    collectionMs: snapshot?.collectionMs ?? null,
    host: snapshot?.host ?? null,
    devices: bounded(snapshot?.devices, 8),
    lane: snapshot?.lane ?? null,
    counts: snapshot?.counts ?? null,
    jobs: bounded(snapshot?.jobs, MAX_JOBS).map((job) => ({
      id: job?.id ?? null,
      jobId: job?.jobId ?? null,
      title: job?.title ?? null,
      description: job?.description ?? null,
      pid: job?.pid ?? null,
      childPids: bounded(job?.childPids, 128),
      processAlive: job?.processAlive ?? null,
      process: job?.process ?? null,
      framework: job?.framework ?? null,
      backend: job?.backend ?? null,
      deviceId: job?.deviceId ?? null,
      workload: job?.workload ?? null,
      owner: job?.owner ?? null,
      ownerTaskId: job?.ownerTaskId ?? null,
      state: job?.state ?? null,
      publishedState: job?.publishedState ?? null,
      lifecycle: job?.lifecycle ?? null,
      queue: job?.queue ?? null,
      lease: job?.lease ?? null,
      progress: job?.progress ?? null,
      metrics: job?.metrics ?? null,
      registration: job?.registration ? {
        updatedAt: job.registration.updatedAt ?? null,
        ageSeconds: job.registration.ageSeconds ?? null,
        source: job.registration.source ?? null,
        confidence: job.registration.confidence ?? null,
        issues: bounded(job.registration.issues, 16),
      } : null,
    })),
    hints: bounded(snapshot?.hints, MAX_HINTS),
    registry: snapshot?.registry ?? null,
    boundary: snapshot?.boundary ?? null,
  };
}

function observerIdentity(path) {
  const version = basename(dirname(dirname(path)));
  return version === "gpu-workers" || version === "cpu-workers" ? "source" : version;
}

function cleanError(error) {
  const text = String(error?.message || error || "observer failed")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.slice(0, 240) || "observer failed";
}

async function collect(product, envName, compact) {
  try {
    const path = resolveLib(product, envName);
    const module = await import(pathToFileURL(path).href);
    if (typeof module.buildSnapshot !== "function") throw new Error("buildSnapshot export is unavailable");
    return {
      ok: true,
      observerVersion: observerIdentity(path),
      snapshot: compact(module.buildSnapshot()),
    };
  } catch (error) {
    return { ok: false, error: cleanError(error), snapshot: null };
  }
}

function requestedSection() {
  const argument = process.argv.find((value) => value.startsWith("--section="));
  const section = argument ? argument.slice("--section=".length) : "all";
  if (!["all", "cpu", "gpu"].includes(section)) {
    throw new Error(`Unsupported observer section: ${section}`);
  }
  return section;
}

const startedAt = Date.now();
const section = requestedSection();
const [cpu, gpu] = await Promise.all([
  section === "gpu" ? null : collect(CPU_PRODUCT, "KE_ACTIVITY_CPU_LIB", compactCpu),
  section === "cpu" ? null : collect(GPU_PRODUCT, "KE_ACTIVITY_GPU_LIB", compactGpu),
]);

process.stdout.write(`${JSON.stringify({
  schemaVersion: "ke.activity-monitor-agents.v1",
  generatedAt: new Date().toISOString(),
  collectionMs: Date.now() - startedAt,
  section,
  cpu,
  gpu,
})}\n`);
