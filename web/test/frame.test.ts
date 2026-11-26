import assert from "node:assert/strict";
import { test } from "node:test";
import { frameDocument } from "../src/frame.ts";

const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src cid: data:; style-src 'unsafe-inline'">`;

test("the policy meta is exact", () => {
  assert.ok(frameDocument("hi").includes(csp));
});

test("the email comes after the policy", () => {
  const email = `<meta http-equiv="Content-Security-Policy" content="default-src *"><p>hi</p>`;
  const doc = frameDocument(email);
  assert.ok(doc.indexOf(csp) < doc.indexOf(email));
});

test("the html passes through unchanged", () => {
  const email = `<p class="a">5 &lt; 6 & "q" '</p><script>x</script>`;
  assert.ok(frameDocument(email).includes(email));
});
