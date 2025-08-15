// functions/cf-static-site-router-worker/index.ts
import path from "node:path";
var cf_static_site_router_worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/^\//, "");
    const filePath = pathname === "" ? env.INDEX_PAGE : pathname;
    let cachedResponse = await lookupCache();
    if (cachedResponse)
      return cachedResponse;
    {
      const object = await env.ASSETS.getWithMetadata(filePath);
      if (object.value)
        return await respond(200, filePath, object);
    }
    {
      const guess = path.join(filePath, "index.html");
      const object = await env.ASSETS.getWithMetadata(guess);
      if (object.value)
        return await respond(200, guess, object);
    }
    {
      const guess = filePath + ".html";
      const object = await env.ASSETS.getWithMetadata(guess);
      if (object.value)
        return await respond(200, guess, object);
    }
    if (env.ERROR_PAGE) {
      const object = await env.ASSETS.getWithMetadata(env.ERROR_PAGE);
      if (object.value)
        return await respond(404, env.ERROR_PAGE, object);
    } else {
      const object = await env.ASSETS.getWithMetadata(env.INDEX_PAGE);
      if (object.value)
        return await respond(200, env.INDEX_PAGE, object);
    }
    return new Response("Page Not Found", { status: 404 });
    async function lookupCache() {
      const cache = caches.default;
      const r = await cache.match(request);
      if (!r)
        return;
      if (r.headers.get("etag") !== SST_ASSET_MANIFEST[filePath])
        return;
      return r;
    }
    async function saveCache(response) {
      const cache = caches.default;
      await cache.put(request, response.clone());
    }
    async function respond(status, filePath2, object) {
      const headers = new Headers;
      if (SST_ASSET_MANIFEST[filePath2]) {
        headers.set("etag", SST_ASSET_MANIFEST[filePath2]);
        headers.set("content-type", object.metadata.contentType);
        headers.set("cache-control", object.metadata.cacheControl);
      }
      const response = new Response(base64ToArrayBuffer(object.value), {
        status,
        headers
      });
      if (request.method === "GET") {
        await saveCache(response);
      }
      return response;
    }
  }
};
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0;i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
export {
  cf_static_site_router_worker_default as default
};
