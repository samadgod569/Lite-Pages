
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname === "/" ? "/index.html" : url.pathname;

    if (pathname.includes("..")) {
      return new Response("Bad Request", { status: 400 });
    }

    const assetRequest = new Request(
      new URL(pathname, url.origin),
      request
    );

    let response = await env.ASSETS.fetch(assetRequest);

    if (response.status === 404 && !pathname.includes(".")) {
      response = await env.ASSETS.fetch(
        new Request(new URL("/index.html", url.origin), request)
      );
    }

    return response;
  },
};
