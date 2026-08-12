import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const repo = path.resolve(import.meta.dirname, '..');
const artifacts = path.join(repo, 'artifacts');
const sqlite = process.env.SQLITE3_PATH || 'sqlite3.exe';
const expectedAttachments = {
  '输入数据包.zip': 'f2428e05e16a29933078607d79d8ce5d302eb4af3dabf04090332e5a3d93024b',
  'reference.zip': '487653834fdc5bcc365dd295951b840e5bfd1886dba3e911138883da20c63a1a',
  '关键标准答案.xlsx': 'fe8ecc93636d8ce50aff182a54c5dd049f4f03be5b41fb324da2d69833006b9c',
  '任务规格转化.xlsx': '76668c84e01f55eb51cd98fa35c39fcc614409ab3b21112de0574fe06a35c0f3'
};
const deliveryFiles = [
  'output/device_risk_review.db',
  'output/sql/rebuild_device_review.sql',
  'output/reports/risk_paths.csv',
  'output/reports/action_queue.csv',
  'output/reports/rejected_links.csv'
];

function sha256(file) {
  return fs.readFile(file).then((data) => crypto.createHash('sha256').update(data).digest('hex'));
}

function spawn(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 30000, windowsHide: true, ...options });
  if (result.error) throw result.error;
  return result;
}

function requireSuccess(result, label) {
  if (result.status !== 0) throw new Error(`${label}失败，退出码${result.status ?? 'signal'}\n${result.stdout}\n${result.stderr}`);
}

async function extract(zip, destination) {
  await fs.mkdir(destination, { recursive: true });
  const quotedZip = zip.replaceAll("'", "''");
  const quotedDestination = destination.replaceAll("'", "''");
  const result = spawn('pwsh', ['-NoLogo','-NoProfile','-Command',`Expand-Archive -LiteralPath '${quotedZip}' -DestinationPath '${quotedDestination}' -Force`]);
  requireSuccess(result, '解压附件');
}

async function treeDigest(root) {
  const entries = [];
  async function walk(current) {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (current === root && entry.name === 'output') continue;
      if (entry.isDirectory()) await walk(full);
      else entries.push(path.relative(root, full).split(path.sep).join('/'));
    }
  }
  await walk(root);
  const hash = crypto.createHash('sha256');
  for (const relative of entries.toSorted()) hash.update(relative).update('\0').update(await fs.readFile(path.join(root, relative))).update('\0');
  return hash.digest('hex');
}

async function auditPlatformFiles(root) {
  const findings = [];
  async function walk(current) {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else {
        const data = await fs.readFile(full);
        const prefix = data.subarray(0, 128).toString('utf8');
        const elf = data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46;
        const shell = entry.name.toLowerCase().endsWith('.sh') || /^#!.*(?:bash|\/sh)(?:\s|$)/u.test(prefix);
        if (elf || shell) findings.push(path.relative(root, full).split(path.sep).join('/'));
      }
    }
  }
  await walk(root);
  return findings.toSorted();
}

function sqliteJson(db, sql) {
  const result = spawn(sqlite, ['-json', db, sql]);
  requireSuccess(result, 'SQLite查询');
  return result.stdout.trim() ? JSON.parse(result.stdout) : [];
}

function normalizedRows(rows, keys) {
  return rows.map((row) => Object.fromEntries(keys.map((key) => [key, row[key]]))).toSorted((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function semanticSnapshot(db) {
  const result = {
    rejected_link: normalizedRows(sqliteJson(db, 'SELECT edge_id,left_device_id,right_device_id,reason,detail FROM rejected_link;'), ['edge_id','left_device_id','right_device_id','reason','detail']),
    account_risk: normalizedRows(sqliteJson(db, 'SELECT seed_incident_id,account_id,device_id,depth,path_confidence,risk_score,evidence_path FROM account_risk;'), ['seed_incident_id','account_id','device_id','depth','path_confidence','risk_score','evidence_path']),
    action_queue: normalizedRows(sqliteJson(db, 'SELECT queue_rank,seed_incident_id,account_id,device_id,action,owner_team,case_priority,review_sla_minutes,due_at_utc,risk_score,evidence_path FROM action_queue;'), ['queue_rank','seed_incident_id','account_id','device_id','action','owner_team','case_priority','review_sla_minutes','due_at_utc','risk_score','evidence_path'])
  };
  return result;
}

async function prepareRun(label) {
  const root = path.join(os.tmpdir(), label);
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await extract(path.join(artifacts, '输入数据包.zip'), root);
  const inputRoot = path.join(root, 'input_data');
  await extract(path.join(artifacts, 'reference.zip'), path.join(root, 'reference'));
  await fs.mkdir(path.join(inputRoot, 'output', 'sql'), { recursive: true });
  await fs.copyFile(path.join(root, 'reference', 'output', 'sql', 'rebuild_device_review.sql'), path.join(inputRoot, 'output', 'sql', 'rebuild_device_review.sql'));
  await fs.rm(path.join(root, 'reference'), { recursive: true, force: true });
  return { root, inputRoot };
}

async function runClean(label) {
  const prepared = await prepareRun(label);
  const before = await treeDigest(prepared.inputRoot);
  const started = Date.now();
  const result = spawn(process.execPath, ['tools/run-task.mjs'], { cwd: prepared.inputRoot, env: { ...process.env, SQLITE3_PATH: sqlite } });
  requireSuccess(result, label);
  const outputDb = path.join(prepared.inputRoot, 'output', 'device_risk_review.db');
  const after = await treeDigest(prepared.inputRoot);
  const snapshot = semanticSnapshot(outputDb);
  return { directory_label: label, exit_code: result.status, input_digest_before: before, input_digest_after: after, semantic_digest: crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex'), elapsed_ms: Date.now() - started, snapshot, root: prepared.root, inputRoot: prepared.inputRoot };
}

for (const [file, expected] of Object.entries(expectedAttachments)) {
  const actual = await sha256(path.join(artifacts, file));
  if (actual !== expected) throw new Error(`${file}哈希不一致`);
}
const staticReview = JSON.parse(await fs.readFile(path.join(repo, 'qa', 'static-review.json'), 'utf8'));
const answerSheetNames = staticReview.answer_sheets;
const specificationSheetNames = staticReview.specification_sheets;
if (staticReview.result !== 'PASS' || staticReview.task_spec_column_count !== 2) throw new Error('静态门禁或任务规格列数不合格');
if (JSON.stringify(answerSheetNames) !== JSON.stringify(['交付物答案清单','固定字段答案','固定集合答案','固定数值答案','允许变体答案'])) throw new Error('标答工作簿页签不符合固定契约');
if (JSON.stringify(specificationSheetNames) !== JSON.stringify(['任务规格转化'])) throw new Error('任务规格工作簿页签不正确');

const sqliteVersionResult = spawn(sqlite, ['--version']);
requireSuccess(sqliteVersionResult, 'SQLite版本读取');
const sqliteVersion = sqliteVersionResult.stdout.trim().split(/\s+/)[0];
if (sqliteVersion !== '3.51.2') throw new Error(`SQLite版本不是3.51.2：${sqliteVersion}`);

const cleanA = await runClean('Q10411 first empty');
const cleanB = await runClean('Q10411 second 中文 空格目录');
if (cleanA.semantic_digest !== cleanB.semantic_digest) throw new Error('两个干净目录的语义结果不同');

const referenceRoot = path.join(os.tmpdir(), 'Q10411 reference compare');
await fs.rm(referenceRoot, { recursive: true, force: true });
await extract(path.join(artifacts, 'reference.zip'), referenceRoot);
const linuxExecutables = [...new Set([...(await auditPlatformFiles(cleanA.inputRoot)), ...(await auditPlatformFiles(referenceRoot))])].toSorted();
if (linuxExecutables.length) throw new Error(`发现Linux可执行文件：${linuxExecutables.join(',')}`);
const referenceDb = path.join(referenceRoot, 'output', 'device_risk_review.db');
const referenceSnapshot = semanticSnapshot(referenceDb);
if (JSON.stringify(cleanA.snapshot) !== JSON.stringify(referenceSnapshot)) throw new Error('标准运行与Reference语义不同');
for (const relative of deliveryFiles.slice(1)) {
  const actual = path.join(cleanA.inputRoot, relative);
  const expected = path.join(referenceRoot, relative);
  if (relative.endsWith('.csv')) {
    const actualText = (await fs.readFile(actual, 'utf8')).replace(/\r\n/g, '\n').trimEnd();
    const expectedText = (await fs.readFile(expected, 'utf8')).replace(/\r\n/g, '\n').trimEnd();
    if (actualText !== expectedText) throw new Error(`${relative}与Reference语义不同`);
  } else if (await sha256(actual) !== await sha256(expected)) throw new Error(`${relative}与Reference不同`);
}

const crlf = await prepareRun('Q10411 CRLF input');
const routeFile = path.join(crlf.inputRoot, 'rules', 'action_routes.csv');
const routeLf = (await fs.readFile(routeFile, 'utf8')).replace(/\r?\n/g, '\r\n');
await fs.writeFile(routeFile, routeLf, 'utf8');
const crlfRun = spawn(process.execPath, ['tools/run-task.mjs'], { cwd: crlf.inputRoot, env: { ...process.env, SQLITE3_PATH: sqlite } });
requireSuccess(crlfRun, 'CRLF输入');
const crlfSnapshot = semanticSnapshot(path.join(crlf.inputRoot, 'output', 'device_risk_review.db'));
if (JSON.stringify(crlfSnapshot) !== JSON.stringify(referenceSnapshot)) throw new Error('CRLF输入改变业务结果');

const mutation = await prepareRun('Q10411 rule mutation');
const policyFile = path.join(mutation.inputRoot, 'rules', 'graph_policy.json');
const policy = JSON.parse(await fs.readFile(policyFile, 'utf8'));
policy.queue_threshold = 48;
policy.queue_actions.find((item) => item.action === 'device_challenge').min_score = 48;
await fs.writeFile(policyFile, `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
const mutationRun = spawn(process.execPath, ['tools/run-task.mjs'], { cwd: mutation.inputRoot, env: { ...process.env, SQLITE3_PATH: sqlite } });
requireSuccess(mutationRun, '正向规则变化');
const mutationDb = path.join(mutation.inputRoot, 'output', 'device_risk_review.db');
const mutationQueue = sqliteJson(mutationDb, 'SELECT device_id,action,owner_team,case_priority FROM action_queue ORDER BY queue_rank;');
const added = mutationQueue.find((row) => row.device_id === 'D401');
if (!added || added.action !== 'device_challenge' || added.owner_team !== 'identity_ops' || added.case_priority !== 'P2') throw new Error('queue_threshold变化未按规则加入D401');

const invalid = await prepareRun('Q10411 invalid route');
const invalidRouteFile = path.join(invalid.inputRoot, 'rules', 'action_routes.csv');
const invalidRoutes = (await fs.readFile(invalidRouteFile, 'utf8')).split(/\r?\n/).filter((line) => !line.startsWith('step_up_review,')).join('\r\n') + '\r\n';
await fs.writeFile(invalidRouteFile, invalidRoutes, 'utf8');
const invalidRun = spawn(process.execPath, ['tools/run-task.mjs'], { cwd: invalid.inputRoot, env: { ...process.env, SQLITE3_PATH: sqlite } });
const invalidOutputDb = path.join(invalid.inputRoot, 'output', 'device_risk_review.db');
const invalidReports = path.join(invalid.inputRoot, 'output', 'reports');
let outputExists = true;
try { await fs.access(invalidOutputDb); } catch { outputExists = false; }
let reportsExist = true;
try { await fs.access(invalidReports); } catch { reportsExist = false; }
if (invalidRun.status === 0 || outputExists || reportsExist) throw new Error('缺少动作路由时未失败关闭');

const evidence = {
  schema_version: 1,
  task_asset_id: 'sqlite_device_risk_routing',
  result: 'PASS',
  generated_at_utc: new Date().toISOString(),
  git_commit_sha: process.env.GITHUB_SHA,
  workflow_run_id: process.env.GITHUB_RUN_ID,
  runner: {
    os: process.env.RUNNER_OS,
    arch: process.env.RUNNER_ARCH,
    image_os: process.env.ImageOS,
    image_version: process.env.ImageVersion,
    node: process.version,
    powershell_hosted_workflow: true
  },
  software: { main: 'SQLite', executed: true, sqlite: sqliteVersion, node: process.version },
  attachment_sha256: expectedAttachments,
  workbook_checks: {
    answer_sheet_names: answerSheetNames,
    specification_sheet_names: specificationSheetNames,
    task_spec_column_count: staticReview.task_spec_column_count
  },
  platform_audit: {
    linux_executables: linuxExecutables,
    linux_executables_executed: false,
    no_wsl_required: true,
    no_linux_container_required: true,
    no_posix_shell_required: true,
    no_unix_only_api_required: true,
    cross_platform_paths: true
  },
  clean_runs: [cleanA, cleanB].map(({ snapshot, root, inputRoot, ...item }) => item),
  reference_match: true,
  crlf_input: { file: 'rules/action_routes.csv', exit_code: crlfRun.status, semantic_digest: crypto.createHash('sha256').update(JSON.stringify(crlfSnapshot)).digest('hex'), reference_match: true },
  positive_mutation: { changed_rule: 'device_challenge档位与queue_threshold同步改为48', exit_code: mutationRun.status, added_device_id: added.device_id, action: added.action, owner_team: added.owner_team, case_priority: added.case_priority },
  invalid_input: { removed_route: 'step_up_review', exit_code: invalidRun.status, output_database_absent: !outputExists, reports_absent: !reportsExist },
  network: { installation_network_access: 'Node.js与SQLite安装阶段', formal_run_network_access: 'none, local files and local SQLite only' }
};
const evidenceRoot = path.join(repo, 'evidence');
await fs.mkdir(evidenceRoot, { recursive: true });
await fs.writeFile(path.join(evidenceRoot, 'windows-verification.json'), `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(evidence, null, 2));
