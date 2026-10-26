export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Proxy health endpoint to Gen2
    if (url.pathname === "/health") {
      const target = "https://YOUR-GEN2-DOMAIN.com/health";

      try {
        return await fetch(target, {
          method: request.method,
          headers: request.headers,
          redirect: "manual",
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Gen2 health proxy failed",
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
