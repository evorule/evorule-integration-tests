#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 EvoRule Project
//
// Cross-repo alignment gate: console-cloud TS pre-validator vs server _shared schema.
//
// The console-cloud frontend keeps a hand-maintained TS replica of the rule
// schema enums/regex for instant UX feedback (errors before the request is
// even sent). The server's core/rule_schema/schemas/_shared/v1.0.json is the
// $defs SSOT. This gate compares the replica against the authority so any
// drift turns CI red instead of silently diverging.
//
// Compared surfaces:
//   1. domain type enum         ($defs/domain object-form properties.type.enum)
//                               == VALID_DOMAIN_TYPES (ruleValidator.ts)
//   2. transform_rule type enum ($defs/transform_rule.properties.type.enum)
//                               == VALID_META_INSTRUCTIONS + "enforce"
//      (the public UI whitelist is the dispatch set minus enforce: enforce is
//       only allowed in L2 meta-rule files, business files carrying it are
//       rejected by the server load gate, so the UI pre-validator excludes it)
//   3. set operation enum       ($defs/instruction set/increment/decrement
//                               branch properties.params.properties.operation.enum)
//                               == VALID_SET_OPERATIONS
//   4. path pattern             ($defs/path.pattern) == PATH_REGEX literal source
//
// Usage: node scripts/check_ts_validator_alignment.mjs [evorule-server] [evorule-console-cloud]

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const serverDir = process.argv[2] ?? 'evorule-server';
const cloudDir = process.argv[3] ?? 'evorule-console-cloud';

const problems = [];

function fail(msg) {
  problems.push(msg);
}

function extractStringArrayConst(tsSource, constName) {
  const m = tsSource.match(new RegExp(`const ${constName} = \\[([^\\]]*)\\]`));
  if (!m) {
    fail(`constant ${constName} not found in ruleValidator.ts`);
    return null;
  }
  return m[1]
    .split(',')
    .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
    .filter((s) => s.length > 0);
}

function extractRegexLiteralSource(tsSource, constName) {
  const m = tsSource.match(new RegExp(`const ${constName} =\\s*\\n?\\s*/(.+?)/;`));
  if (!m) {
    fail(`regex literal ${constName} not found in ruleValidator.ts`);
    return null;
  }
  // The literal source text between the delimiters must equal the JSON-parsed
  // pattern string character-for-character (both carry the same escaping).
  return m[1];
}

function compareEnums(label, actual, expected) {
  if (!Array.isArray(actual) || !Array.isArray(expected)) return;
  const a = [...actual].sort();
  const e = [...expected].sort();
  const missing = e.filter((v) => !a.includes(v));
  const extra = a.filter((v) => !e.includes(v));
  if (missing.length > 0) fail(`${label}: TS side missing [${missing.join(', ')}]`);
  if (extra.length > 0) fail(`${label}: TS side has extra [${extra.join(', ')}]`);
}

const schema = JSON.parse(
  readFileSync(join(serverDir, 'core/rule_schema/schemas/_shared/v1.0.json'), 'utf8')
);
const ts = readFileSync(
  join(cloudDir, 'src/lib/kernel/validators/ruleValidator.ts'),
  'utf8'
);

// 1. domain type enum (object form inside oneOf)
const domainEnum = (schema.$defs?.domain?.oneOf ?? [])
  .map((form) => form?.properties?.type?.enum)
  .find((e) => Array.isArray(e));
compareEnums(
  'domain type enum',
  extractStringArrayConst(ts, 'VALID_DOMAIN_TYPES'),
  domainEnum
);

// 2. transform_rule type enum (public whitelist = full set minus enforce)
const transformEnum = schema.$defs?.transform_rule?.properties?.type?.enum;
if (Array.isArray(transformEnum) && !transformEnum.includes('enforce')) {
  fail('transform_rule enum no longer contains enforce — revisit whitelist derivation');
}
compareEnums(
  'meta instruction whitelist (transform enum minus enforce)',
  extractStringArrayConst(ts, 'VALID_META_INSTRUCTIONS'),
  Array.isArray(transformEnum) ? transformEnum.filter((v) => v !== 'enforce') : null
);

// 3. set operation enum (instruction layer, set/increment/decrement branch;
//    the allOf lives inside the object form of the instruction oneOf)
const instructionAllOf = [
  ...(schema.$defs?.instruction?.allOf ?? []),
  ...(schema.$defs?.instruction?.oneOf ?? []).flatMap((form) => form?.allOf ?? [])
];
const setOpEnum = instructionAllOf
  .filter(
    (branch) =>
      Array.isArray(branch?.if?.properties?.type?.enum) &&
      branch.if.properties.type.enum.includes('set')
  )
  .map((branch) => branch?.then?.properties?.params?.properties?.operation?.enum)
  .find((e) => Array.isArray(e));
if (!setOpEnum) fail('set operation enum not found in _shared/v1.0.json $defs/instruction');
compareEnums(
  'set operation enum',
  extractStringArrayConst(ts, 'VALID_SET_OPERATIONS'),
  setOpEnum
);

// 4. path pattern (JSON-parsed pattern string == regex literal source)
const pathPattern = schema.$defs?.path?.pattern;
const tsPathPattern = extractRegexLiteralSource(ts, 'PATH_REGEX');
if (pathPattern !== undefined && tsPathPattern !== null && tsPathPattern !== pathPattern) {
  fail(`path pattern mismatch:\n  _shared : ${pathPattern}\n  TS      : ${tsPathPattern}`);
}

if (problems.length > 0) {
  console.error('TS validator alignment check FAILED:');
  for (const p of problems) console.error(`  - ${p}`);
  console.error(
    'Fix: sync ruleValidator.ts constants with _shared/v1.0.json (or reverse),'
  );
  console.error(
    'then update the golden-vector tests in ruleValidator.test.ts accordingly.'
  );
  process.exit(1);
}

console.log('TS validator alignment check OK:');
console.log(`  domain types        : ${(domainEnum ?? []).join(', ')}`);
console.log(
  `  meta instructions   : ${(transformEnum ?? []).filter((v) => v !== 'enforce').join(', ')} (public) + enforce (server-only)`
);
console.log(`  set operations      : ${(setOpEnum ?? []).join(', ')}`);
console.log(`  path pattern        : match`);
