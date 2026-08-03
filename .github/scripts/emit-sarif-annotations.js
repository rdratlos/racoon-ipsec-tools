// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
//
// Turn GCC's SARIF diagnostic output (-fdiagnostics-format=sarif-file,
// GCC >= 13) into a GitHub Checks API check run with real `annotations`
// entries -- not the ::error::/::warning:: workflow-command form, which
// caps out at 10 errors + 10 warnings + 10 notices per step and 50 per
// run. The Checks API accepts 50 annotations per request but has no
// overall cap: additional `checks.update` calls just append more, which
// is what batchAndPublish() below does.
//
// Deliberately shared between main's and develop's workflow files (and
// openssl-deprecation-canary.yml) rather than duplicated inline in each
// actions/github-script step -- same reasoning parse_gcc_json/parse_sarif
// in tools/gen_deprecation_report.py are factored out for: one place to
// fix if GCC's SARIF shape ever changes.
//
// No SARIF file present is not an error -- it just means the toolchain
// that ran this build doesn't support -fdiagnostics-format=sarif-file
// (older GCC, e.g. anything before 13), which the calling workflow's
// configure-command already probes for and falls back on gracefully.
// This module never assumes SARIF availability.

const fs = require('fs');
const path = require('path');

// Recursively collect files under dir for which predicate(entryName) is
// true. Skips .git -- the only directory worth pruning for either of
// this module's two walks (SARIF sidecars, source-file basename index).
function findFiles(dir, predicate) {
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return results;
  }
  for (const entry of entries) {
    if (entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFiles(full, predicate));
    } else if (predicate(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

function findSarifFiles(dir) {
  return findFiles(dir, (name) => name.endsWith('.sarif'));
}

// Map basename -> repo-root-relative path, for resolving a bare filename
// (e.g. Valgrind's debug-info-derived "vmbuf.c", with no directory) back
// to a real path Checks API annotations can point at. First match wins
// on a basename collision (rare in this codebase; logged by the caller
// if it matters).
function buildBasenameIndex(repoRoot, extensions) {
  const index = new Map();
  const files = findFiles(repoRoot, (name) => extensions.some((ext) => name.endsWith(ext)));
  for (const full of files) {
    const base = path.basename(full);
    if (!index.has(base)) {
      index.set(base, path.relative(repoRoot, full));
    }
  }
  return index;
}

// SARIF's `level` is one of error/warning/note (or absent, which SARIF
// 2.1.0 defines as "warning" for a rule-based result). Checks API's
// annotation_level is failure/warning/notice.
function levelToAnnotationLevel(level) {
  if (level === 'error') return 'failure';
  if (level === 'note') return 'notice';
  return 'warning';
}

// GCC writes each result's location relative to the working directory it
// was invoked from, which for a recursive automake build is normally the
// same directory the .sarif sidecar file itself lands in (not the repo
// root). Resolve against the .sarif file's own directory, then make that
// relative to repoRoot -- correct for this project's normal layout;
// falls back to the raw URI if resolution fails, so a path oddity here
// degrades to a slightly-off annotation location rather than throwing.
function resolveArtifactPath(uri, sarifFilePath, repoRoot) {
  let rel = uri;
  if (rel.startsWith('file://')) {
    rel = decodeURIComponent(rel.slice('file://'.length));
  }
  if (path.isAbsolute(rel)) {
    return path.relative(repoRoot, rel);
  }
  const resolved = path.resolve(path.dirname(sarifFilePath), rel);
  return path.relative(repoRoot, resolved);
}

function parseSarifFile(sarifFilePath, repoRoot) {
  const findings = [];
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(sarifFilePath, 'utf8'));
  } catch (e) {
    return findings;
  }
  for (const run of doc.runs || []) {
    for (const result of run.results || []) {
      const location = (result.locations || [])[0];
      const physical = location && location.physicalLocation;
      if (!physical) continue;
      const uri = (physical.artifactLocation || {}).uri;
      if (!uri) continue;
      const region = physical.region || {};
      const startLine = region.startLine || 1;
      findings.push({
        path: resolveArtifactPath(uri, sarifFilePath, repoRoot),
        start_line: startLine,
        end_line: region.endLine || startLine,
        annotation_level: levelToAnnotationLevel(result.level),
        message: (result.message && result.message.text) || '(no message)',
        title: result.ruleId || 'compiler diagnostic',
      });
    }
  }
  return findings;
}

// Collect every *.sarif file under sarifDir into a flat findings array.
function collectFindings(sarifDir, repoRoot) {
  const findings = [];
  for (const file of findSarifFiles(sarifDir)) {
    findings.push(...parseSarifFile(file, repoRoot));
  }
  return findings;
}

// Publish (or extend) a Checks API check run with the given findings,
// batched at the API's 50-annotations-per-request limit. `text` is
// optional (Checks API's longer output.text body, separate from the
// short output.summary).
//
// Conclusion: by default derived from the findings themselves (any
// failure-level annotation -> 'failure', else conclusionIfClean, which
// defaults to 'success'). Pass `conclusion` explicitly instead when the
// caller has its own authoritative pass/fail signal that doesn't
// depend on this function's own parsing -- e.g. Valgrind's actual exit
// code, versus the regex-based log parser that built `findings` here,
// which could in principle miss a error shape it doesn't recognize and
// silently under-report. An explicit `conclusion` always wins, so a
// parser gap never downgrades a real failure to a green check.
//
// Returns counts by level for the caller to build its own summary/title
// from either way.
async function publishAnnotations({
  github, context, core, findings, checkName, sha, title, summary, text,
  conclusionIfClean = 'success', conclusion: conclusionOverride,
}) {
  const counts = { failure: 0, warning: 0, notice: 0 };
  for (const f of findings) counts[f.annotation_level] = (counts[f.annotation_level] || 0) + 1;

  const conclusion = conclusionOverride || (counts.failure > 0 ? 'failure' : conclusionIfClean);
  const output = { title, summary };
  if (text) output.text = text;

  const { data: checkRun } = await github.rest.checks.create({
    owner: context.repo.owner,
    repo: context.repo.repo,
    name: checkName,
    head_sha: sha,
    status: 'completed',
    conclusion,
    output: { ...output, annotations: findings.slice(0, 50) },
  });

  for (let i = 50; i < findings.length; i += 50) {
    await github.rest.checks.update({
      owner: context.repo.owner,
      repo: context.repo.repo,
      check_run_id: checkRun.id,
      output: { ...output, annotations: findings.slice(i, i + 50) },
    });
  }

  core.info(`${checkName}: published ${findings.length} annotation(s) ` +
    `(${counts.failure} error, ${counts.warning} warning, ${counts.notice} notice)`);

  return counts;
}

module.exports = { findSarifFiles, buildBasenameIndex, collectFindings, publishAnnotations };
