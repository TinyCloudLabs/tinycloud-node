// TC-3284: every warn/error line the node can emit from a target the shipper classifies must map to a named
// event_code (diagnostics.json exact or prefix), so a new or newly reachable warning never ships as `unclassified`.
// A small Rust lexer finds `warn!`/`error!` calls outside `#[cfg(test)]` code and reads each one's message: the
// first positional string literal, or a same-file `const NAME: &str = "…"` it names. Format messages are covered by
// a prefix entry that matches their text up to the first `{`.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

/** Source roots whose tracing targets (`tinycloud…`, `tinycloud_core…`) the shipper classifies. */
export const CLASSIFIED_ROOTS = Object.freeze(['tinycloud-core/src', 'tinycloud-node-server/src']);

const MACRO = /\b(?:tracing::)?(warn|error)!\s*\(/y;

/** Replace comments and literal contents with spaces, keeping offsets, and return the literal spans. */
function lex(source) {
  const literals = [];
  let masked = '';
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (c === '/' && next === '/') {
      const end = source.indexOf('\n', i);
      const stop = end === -1 ? source.length : end;
      masked += ' '.repeat(stop - i);
      i = stop;
    } else if (c === '/' && next === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < source.length && depth) {
        if (source[j] === '/' && source[j + 1] === '*') { depth += 1; j += 2; }
        else if (source[j] === '*' && source[j + 1] === '/') { depth -= 1; j += 2; }
        else j += 1;
      }
      masked += source.slice(i, j).replace(/[^\n]/g, ' ');
      i = j;
    } else if ((c === 'r' || (c === 'b' && next === 'r')) && /^b?r#*"/.test(source.slice(i, i + 40)) && !/[A-Za-z0-9_]/.test(source[i - 1] ?? '')) {
      const head = /^b?r(#*)"/.exec(source.slice(i, i + 40));
      const close = `"${head[1]}`;
      const start = i + head[0].length;
      const end = source.indexOf(close, start);
      literals.push({ start: i, end: end + close.length, value: source.slice(start, end) });
      masked += `"${' '.repeat(end + close.length - i - 2)}"`;
      i = end + close.length;
    } else if (c === '"' || (c === 'b' && next === '"' && !/[A-Za-z0-9_]/.test(source[i - 1] ?? ''))) {
      const open = c === '"' ? i : i + 1;
      let j = open + 1;
      let value = '';
      while (source[j] !== '"') {
        if (source[j] === '\\') {
          const esc = source[j + 1];
          if (esc === '\n') { j += 2; while (/\s/.test(source[j])) j += 1; continue; }
          value += { n: '\n', t: '\t', r: '\r', 0: '\0', '\\': '\\', '"': '"', "'": "'" }[esc] ?? `\\${esc}`;
          j += 2;
        } else { value += source[j]; j += 1; }
      }
      literals.push({ start: i, end: j + 1, value });
      masked += `"${' '.repeat(j - i - 1)}"`;
      i = j + 1;
    } else if (c === "'" && (/^'(?:\\.|[^\\'])'/.test(source.slice(i, i + 4)) || /^'\\u\{[0-9a-fA-F]+\}'/.test(source.slice(i, i + 12)) || /^'\\x[0-9a-fA-F]{2}'/.test(source.slice(i, i + 6)))) {
      const end = source.indexOf("'", i + (source[i + 1] === '\\' ? 3 : 2)) + 1;
      masked += ' '.repeat(end - i);
      i = end;
    } else {
      masked += c;
      i += 1;
    }
  }
  return { masked, literals };
}

/** Offset just past the bracket matching the opener at `open` in masked text. */
function matching(masked, open) {
  const pairs = { '(': ')', '{': '}', '[': ']' };
  const stack = [pairs[masked[open]]];
  let i = open + 1;
  while (stack.length) {
    const c = masked[i];
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === stack[stack.length - 1]) stack.pop();
    i += 1;
    if (i > masked.length) throw new Error('unbalanced brackets');
  }
  return i;
}

/** Spans of `#[cfg(test)]` items (modules, functions, impls) and the files of `#[cfg(test)] mod name;`. */
function testSpans(masked) {
  const spans = [];
  const files = [];
  const attr = /#\[cfg\(test\)\]/g;
  for (let m; (m = attr.exec(masked));) {
    let i = m.index + m[0].length;
    for (;;) {
      while (/\s/.test(masked[i])) i += 1;
      if (masked[i] === '#' && masked[i + 1] === '[') { i = matching(masked, i + 1); continue; }
      break;
    }
    const decl = /^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/.exec(masked.slice(i, i + 200));
    if (decl) { files.push(decl[1]); continue; }
    let j = i;
    while (j < masked.length && masked[j] !== '{' && masked[j] !== ';') j += 1;
    spans.push([m.index, masked[j] === '{' ? matching(masked, j) : j + 1]);
  }
  return { spans, files };
}

/** Top-level comma-separated argument spans of a macro call body. */
function args(masked, start, end) {
  const out = [];
  let depth = 0;
  let from = start;
  for (let i = start; i < end; i += 1) {
    const c = masked[i];
    if ('([{'.includes(c)) depth += 1;
    else if (')]}'.includes(c)) depth -= 1;
    else if (c === ',' && depth === 0) { out.push([from, i]); from = i + 1; }
  }
  if (masked.slice(from, end).trim()) out.push([from, end]);
  return out;
}

/** Every warn!/error! message in one Rust source, with `{ level, message, line }`; `message` is null if unresolved. */
export function scanSource(source) {
  const { masked, literals } = lex(source);
  const { spans, files } = testSpans(masked);
  const consts = new Map();
  for (const m of masked.matchAll(/\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*"/g)) {
    const lit = literals.find(l => l.start === m.index + m[0].length - 1);
    if (lit) consts.set(m[1], lit.value);
  }
  const calls = [];
  const literalAt = (a, b) => {
    const at = a + masked.slice(a, b).indexOf('"');
    return literals.find(l => l.start === at || l.start === at - 1)?.value ?? null;
  };
  const value = (a, b, text) => (text.startsWith('"') ? literalAt(a, b) : consts.get(text) ?? null);
  for (let i = 0; i < masked.length; i += 1) {
    if (masked[i] !== 'w' && masked[i] !== 'e' && masked[i] !== 't') continue;
    if (/[A-Za-z0-9_:]/.test(masked[i - 1] ?? '') && !masked.slice(0, i).endsWith('tracing::')) continue;
    MACRO.lastIndex = i;
    const m = MACRO.exec(masked);
    if (!m) continue;
    const open = i + m[0].length - 1;
    const close = matching(masked, open) - 1;
    i = close;
    if (spans.some(([a, b]) => open >= a && open < b)) continue;
    // `message`: the resolved text, or null when the call has none or it is built at run time (`dynamic`).
    const call = { level: m[1], message: null, dynamic: false, event: null, target: null, line: source.slice(0, open).split('\n').length };
    for (const [a, b] of args(masked, open + 1, close)) {
      const text = masked.slice(a, b).trim();
      const field = /^([A-Za-z_][\w.]*)\s*=(?!=)\s*/.exec(text);
      if (/^target\s*:/.test(text)) {
        const rest = text.replace(/^target\s*:\s*/, '');
        call.target = value(a + masked.slice(a, b).indexOf(rest), b, rest);
      } else if (field) {
        if (field[1] === 'event') call.event = value(a + masked.slice(a, b).indexOf(field[0]) + field[0].length, b, text.slice(field[0].length));
        if (field[1] === 'message') call.dynamic = true;
      } else if (/^[%?]\s*message$/.test(text)) {
        call.dynamic = true;
      } else if (/^[%?]/.test(text) || (/^[A-Za-z_]\w*$/.test(text) && !consts.has(text))) {
        continue;
      } else {
        const message = value(a, b, text);
        const inline = /^\{([A-Z_][A-Z0-9_]*)\}$/.exec(message ?? '');
        call.dynamic = message === null || (!(inline && consts.has(inline[1])) && formatPrefix(message) !== null);
        call.message = inline && consts.has(inline[1]) ? consts.get(inline[1]) : message;
        break;
      }
    }
    calls.push(call);
  }
  return { calls, testModules: files };
}

function rustFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return rustFiles(path);
    return entry.name.endsWith('.rs') ? [path] : [];
  });
}

/** All production warn!/error! calls under the classified roots, as `{ file, line, level, message }`. */
export function scanRepo(root) {
  const found = [];
  const skipped = new Set();
  const all = CLASSIFIED_ROOTS.flatMap(dir => rustFiles(join(root, dir)));
  const parsed = new Map(all.map(file => [file, scanSource(readFileSync(file, 'utf8'))]));
  for (const [file, { testModules }] of parsed) {
    const base = file.endsWith('/mod.rs') || file.endsWith('/lib.rs') || file.endsWith('/main.rs') ? dirname(file) : file.slice(0, -3);
    for (const name of testModules) {
      skipped.add(join(base, `${name}.rs`));
      skipped.add(join(base, name, 'mod.rs'));
    }
  }
  for (const [file, { calls }] of parsed) {
    if (skipped.has(file)) continue;
    for (const call of calls) found.push({ file: relative(root, file), ...call });
  }
  return found;
}

/** The event_code a message ships as under the shipper's rules: exact first, then the longest matching prefix. */
export function codeFor(diagnostics, message) {
  if (Object.hasOwn(diagnostics.exact, message)) return diagnostics.exact[message];
  const prefixes = Object.keys(diagnostics.prefix).filter(prefix => message.startsWith(prefix)).sort((a, b) => b.length - a.length);
  return prefixes.length ? diagnostics.prefix[prefixes[0]] : diagnostics.fallback;
}

/** The text a format message is matched by: everything before its first placeholder. */
export function formatPrefix(message) {
  const at = message.search(/\{(?!\{)/);
  return at === -1 ? null : message.slice(0, at).replaceAll('{{', '{');
}
