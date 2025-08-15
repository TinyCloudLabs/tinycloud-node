// functions/cf-ssr-site-router-worker/index.ts
var cf_ssr_site_router_worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/^\//, "");
    let cachedResponse = await lookupCache();
    if (cachedResponse)
      return cachedResponse;
    const route = SST_ROUTES.find((r) => new RegExp(r.regex).test(pathname));
    if (route?.origin === "server") {
      return await env.SERVER.fetch(request);
    } else if (route?.origin === "assets") {
      const object = await env.ASSETS.getWithMetadata(pathname);
      if (object.value)
        return await respond(200, object);
    }
    return new Response("Page Not Found", { status: 404 });
    async function lookupCache() {
      const cache = caches.default;
      const r = await cache.match(request);
      if (!r)
        return;
      if (r.headers.get("etag") !== SST_ASSET_MANIFEST[pathname])
        return;
      return r;
    }
    async function saveCache(response) {
      const cache = caches.default;
      await cache.put(request, response.clone());
    }
    async function respond(status, object) {
      const headers = new Headers;
      if (SST_ASSET_MANIFEST[pathname]) {
        headers.set("etag", SST_ASSET_MANIFEST[pathname]);
        headers.set("content-type", object.metadata.contentType);
        headers.set("cache-control", object.metadata.cacheControl);
      }
      const response = new Response(object.value, {
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
export {
  cf_ssr_site_router_worker_default as default
};
