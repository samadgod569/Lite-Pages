export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Gen2 API proxy
    if (url.pathname.startsWith("/api/")) {
      const GEN2_URL = "https://gen2-litepages.wisp.uno";

      const target = new URL(
        url.pathname + url.search,
        GEN2_URL
      );

      const headers = new Headers(request.headers);

      headers.delete("host");
      headers.delete("cf-connecting-ip");
      headers.delete("cf-ray");
      headers.delete("cf-visitor");

      try {
        const response = await fetch(target, {
          method: request.method,
          headers,
          body: ["GET", "HEAD"].includes(request.method)
            ? undefined
            : request.body,
          redirect: "manual",
        });

        const responseHeaders = new Headers(response.headers);
        responseHeaders.delete("content-length");
        responseHeaders.delete("content-encoding");

        return new Response(response.body, {
          status: response.status,
          headers: responseHeaders,
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Gen2 proxy request failed",
            details: error.message,
          },
          { status: 502 }
        );
      }
    }

    // Existing ASSETS handling
    const pathname =
      url.pathname === "/" ? "/index.html" : url.pathname;

    if (pathname.includes("..")) {
      return new Response("Bad Request.", { status: 400 });
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
