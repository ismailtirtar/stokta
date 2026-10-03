import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

// A fresh, time-bounded process prevents stale require caches and turns an
// accidentally unbounded caller-supplied AST into a failed release check.
function runtimeProbes(packageRoot, consumers) {
  const assert = require("node:assert/strict");
  const { join } = require("node:path");
  const braces = require(packageRoot);
  const results = [];
  const record = (name, check) => {
    try { check(); results.push({ name, passed: true }); }
    catch (error) { results.push({ name, passed: false, detail: `${error.name}: ${error.message}` }); }
  };
  const nested = (kind, depth) => {
    const open = Array.from({ length: depth }, (_, i) => kind === "brace" ? "{" : kind === "paren" ? "(" : i % 2 ? "(" : "{").join("");
    return open + "a" + [...open].reverse().map((ch) => ch === "{" ? "}" : ")").join("");
  };
  const apis = {
    "public default": (input, options) => braces(input, options),
    "public create": (input, options) => braces.create(input, options),
    "public parse": (input, options) => braces.parse(input, options),
    "public compile": (input, options) => braces.compile(input, options),
    "public expand": (input, options) => braces.expand(input, options),
    "public stringify": (input, options) => braces.stringify(input, options),
    "public default expand": (input, options) => braces(input, { ...options, expand: true }),
  };
  for (const kind of ["brace", "paren", "mixed"]) {
    for (const [name, api] of Object.entries(apis)) {
      for (const depth of [101, 4400]) record(`${name}: ${kind} string depth ${depth}`, () => {
        assert.throws(() => api(nested(kind, depth)), { name: "SyntaxError", message: "Input depth (101), exceeds max depth (100)" });
      });
      record(`${name}: ${kind} allowed boundary 100`, () => {
        const input = nested(kind, 100);
        const result = api(input);
        if (name === "public parse") assert.equal(result.input, input);
        else assert.deepEqual(result, ["public default", "public expand", "public default expand"].includes(name) ? [input] : input);
      });
      record(`${name}: ${kind} stricter depth`, () => {
        assert.throws(() => api(nested(kind, 2), { maxDepth: 1 }), { name: "SyntaxError", message: "Input depth (2), exceeds max depth (1)" });
      });
    }
  }
  for (const value of [1000000, Infinity, NaN, "1000000", null, false]) {
    for (const [name, api] of Object.entries(apis)) record(`${name}: maxDepth cannot lift ceiling (${String(value)})`, () => {
      assert.throws(() => api(nested("mixed", 101), { maxDepth: value }), { name: "SyntaxError", message: "Input depth (101), exceeds max depth (100)" });
    });
  }
  const ast = (depth, root = true) => {
    let node = { type: "text", value: "a" };
    for (let i = 0; i < depth; i++) {
      const parent = { type: "paren", nodes: [node] };
      node.parent = parent;
      node = parent;
    }
    if (!root) return node;
    const parent = { type: "root", nodes: [node] };
    node.parent = parent;
    return parent;
  };
  const walkers = {};
  for (const name of ["compile", "expand", "stringify"]) {
    walkers[`public ${name}`] = braces[name];
    walkers[`direct lib/${name}`] = require(join(packageRoot, `lib/${name}.js`));
  }
  for (const [name, api] of Object.entries(walkers)) {
    for (const root of [true, false]) {
      record(`${name}: raw AST depth 101 (${root ? "root" : "subtree"})`, () => {
        assert.throws(() => api(ast(101, root)), { name: "RangeError", message: "AST depth (101), exceeds max depth (100)" });
      });
      record(`${name}: raw AST boundary 100 (${root ? "root" : "subtree"})`, () => {
        assert.deepEqual(api(ast(100, root)), name.endsWith("expand") ? ["a"] : "a");
      });
    }
    record(`${name}: cyclic child nodes`, () => {
      const cyclic = { type: "root", nodes: [] };
      cyclic.nodes.push(cyclic);
      assert.throws(() => api(cyclic), { name: "RangeError", message: "AST depth (101), exceeds max depth (100)" });
    });
    record(`${name}: raw AST options cannot lift ceiling`, () => {
      assert.throws(() => api(ast(101), { maxDepth: 1000000 }), { name: "RangeError", message: "AST depth (101), exceeds max depth (100)" });
    });
  }
  const parse = require(join(packageRoot, "lib/parse.js"));
  for (const kind of ["brace", "paren", "mixed"]) record(`direct lib/parse: ${kind} string depth 101`, () => {
    assert.throws(() => parse(nested(kind, 101)), { name: "SyntaxError", message: "Input depth (101), exceeds max depth (100)" });
  });
  for (const mutual of [false, true]) record(`expand: ${mutual ? "mutual" : "self"} parent cycle`, () => {
    const node = { type: "paren", nodes: [] };
    const parent = mutual ? { type: "paren", parent: node } : node;
    node.parent = parent;
    assert.throws(() => braces.expand(node), { name: "RangeError", message: "AST parent depth exceeds max depth (100)" });
  });
  const valid = [
    ["src/{app,lib}/**/*.{js,ts}", "src/(app|lib)/**/*.(js|ts)", ["src/app/**/*.js", "src/app/**/*.ts", "src/lib/**/*.js", "src/lib/**/*.ts"]],
    ["a/{b,{c,d}}/e", "a/(b|(c|d))/e", ["a/b/e", "a/c/e", "a/d/e"]],
    ["file-{1..3}.js", "file-([1-3]).js", ["file-1.js", "file-2.js", "file-3.js"]],
    ["{a..c}", "([a-c])", ["a", "b", "c"]],
    ["{01..03}", "(0[1-3])", ["01", "02", "03"]],
    ["\\{a,b\\}", "{a,b}", ["{a,b}"]],
    ["'[{{literal}}]'", "[{{literal}}]", ["[{{literal}}]"]],
    ["[{{literal}}]", "[{{literal}}]", ["[{{literal}}]"]],
  ];
  for (const [input, compiled, expanded] of valid) {
    record(`valid compile: ${input}`, () => assert.equal(braces.compile(input), compiled));
    record(`valid expand: ${input}`, () => assert.deepEqual(braces.expand(input), expanded));
    record(`valid default: ${input}`, () => assert.deepEqual(braces(input), [compiled]));
  }
  record("array input preserves compile", () => assert.deepEqual(braces(["{a,b}", "{c,d}"]), ["(a|b)", "(c|d)"]));
  record("array input preserves expand", () => assert.deepEqual(braces(["{a,b}", "{a,c}"], { expand: true, nodupes: true }), ["a", "b", "c"]));
  record("character cap still rejects", () => assert.throws(() => braces.parse("a".repeat(10001)), { name: "SyntaxError" }));
  for (const consumer of consumers) {
    const micromatch = require(consumer);
    for (const kind of ["brace", "paren", "mixed"]) {
      for (const name of ["parse", "braces", "braceExpand"]) record(`micromatch.${name}: ${kind} depth 101`, () => {
        // micromatch.braces bypasses inputs without a literal brace pair.
        const input = kind === "paren" ? `{${nested(kind, 100)}}` : nested(kind, 101);
        assert.throws(() => micromatch[name](input), { name: "SyntaxError", message: "Input depth (101), exceeds max depth (100)" });
      });
    }
    record("micromatch.braces standard Metro pattern", () => assert.deepEqual(micromatch.braces("**/*.{js,ts}"), ["**/*.(js|ts)"]));
    record("micromatch.braceExpand standard Metro pattern", () => assert.deepEqual(micromatch.braceExpand("**/*.{js,ts}"), ["**/*.js", "**/*.ts"]));
    record("micromatch.parse standard Metro pattern", () => assert.equal(micromatch.parse("**/*.{js,ts}").length, 1));
  }
  return results;
}

export function depthProbeResults(packageRoot, { consumers = [] } = {}) {
  const source = `const run = ${runtimeProbes.toString()}; process.stdout.write(JSON.stringify(run(process.argv[1], JSON.parse(process.argv[2]))));`;
  const result = spawnSync(process.execPath, ["--input-type=commonjs", "-e", source, packageRoot, JSON.stringify(consumers)], {
    encoding: "utf8", timeout: 8000, maxBuffer: 1024 * 1024,
  });
  assert(!result.error && result.status === 0, `braces runtime probes did not complete: ${result.error?.message ?? result.stderr}`);
  return JSON.parse(result.stdout);
}
