import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const sqliteCommand = process.env.SQLITE3_PATH || 'sqlite3.exe';
const taskRoot = path.resolve(process.argv[2]);
const solutionSql = path.resolve(process.argv[3]);
const inputRoot = path.join(taskRoot, 'input_data');
const outputSql = path.join(inputRoot, 'output', 'sql', 'rebuild_device_review.sql');

await fs.mkdir(path.dirname(outputSql), { recursive: true });
await fs.copyFile(solutionSql, outputSql);
const result = spawnSync(process.execPath, ['tools/run-task.mjs'], {
  cwd: inputRoot,
  encoding: 'utf8',
  timeout: 30000,
  windowsHide: true,
  env: { ...process.env, SQLITE3_PATH: sqliteCommand }
});
process.stdout.write(result.stdout || '');
process.stderr.write(result.stderr || '');
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 2);

const integrity = spawnSync(sqliteCommand, [path.join(inputRoot, 'output', 'device_risk_review.db'), 'PRAGMA integrity_check;'], {
  encoding: 'utf8',
  windowsHide: true
});
if (integrity.status !== 0 || integrity.stdout.trim() !== 'ok') {
  throw new Error(`完整性检查失败：${integrity.stdout}\n${integrity.stderr}`);
}
