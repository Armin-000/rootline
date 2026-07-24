import test from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp, normalizeDomain, validateDomain } from "../lib/scan-service.mjs";

test("normalizes URLs into root hostnames", () => {
  assert.equal(normalizeDomain("https://www.AlphaWave.hr/path?q=1"), "alphawave.hr");
  assert.equal(normalizeDomain("example.com."), "example.com");
});

test("accepts public domains and rejects local names", () => {
  assert.equal(validateDomain("alphawave.hr").ok, true);
  assert.equal(validateDomain("localhost").ok, false);
  assert.equal(validateDomain("printer.local").ok, false);
});

test("blocks private and reserved addresses from HTTPS probing", () => {
  assert.equal(isPrivateIp("10.0.0.1"), true);
  assert.equal(isPrivateIp("192.168.1.25"), true);
  assert.equal(isPrivateIp("203.0.113.10"), true);
  assert.equal(isPrivateIp("::1"), true);
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("1.1.1.1"), false);
});
