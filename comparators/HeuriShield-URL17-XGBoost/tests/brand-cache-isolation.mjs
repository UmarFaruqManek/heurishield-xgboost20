import assert from "node:assert/strict";
import { createBrandLookupCache } from "../src/analyzer/brand/brand-lookup-cache.js";

const cache = {};
const options = {
  getCache: async () => cache,
  updateCache: async update => update(cache),
  ttlMs: 86400000
};
const tokenLookup = createBrandLookupCache({ ...options,
  lookup: async () => ({lookup_success:true,candidates:[{name:"Liquipedia",domain:"liquipedia.net"}]})
});
let calls = 0;
let forceRefresh = false;
const domainLookup = createBrandLookupCache({ ...options,
  namespace:"brand:domain-search:v2",
  lookup: async (query, request) => {
    calls++;
    forceRefresh = request.forceRefresh;
    return {lookup_success:true,found:true,queried_domain:query,
      candidates:[{name:"Liquipedia",domain:query}]};
  }
});
await tokenLookup("liquipedia.net");
assert.equal((await domainLookup("liquipedia.net")).found,true);
assert.equal(calls,1);
await domainLookup("liquipedia.net");
assert.equal(calls,1);
await domainLookup("liquipedia.net",{forceRefresh:true});
assert.equal(calls,2);
assert.equal(forceRefresh,true);
assert.equal((await tokenLookup("liquipedia.net")).found,undefined);
console.log("Brand token/domain caches remain separate; explicit refresh reaches lookup.");
