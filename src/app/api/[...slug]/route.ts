import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8080";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  return proxyRequest(request, slug, "GET");
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  return proxyRequest(request, slug, "POST");
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  return proxyRequest(request, slug, "PUT");
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  return proxyRequest(request, slug, "DELETE");
}

async function proxyRequest(
  request: NextRequest,
  slug: string[],
  method: string
) {
  const path = slug.join("/");
  const url = `${BACKEND_URL}/api/${path}`;

  // Get query parameters
  const searchParams = request.nextUrl.searchParams;
  const queryString = searchParams.toString();
  const fullUrl = queryString ? `${url}?${queryString}` : url;

  // Get request headers
  const headers = new Headers();
  request.headers.forEach((value, key) => {
    // Forward relevant headers
    if (
      key.toLowerCase() === "authorization" ||
      key.toLowerCase() === "content-type" ||
      key.toLowerCase() === "accept"
    ) {
      headers.set(key, value);
    }
  });

  // Get request body if present
  let body: string | undefined;
  if (method !== "GET" && method !== "DELETE") {
    const contentType = request.headers.get("content-type");
    if (contentType?.includes("multipart/form-data")) {
      // For multipart/form-data, forward the raw body stream
      return fetch(fullUrl, {
        method,
        headers: {
          "Content-Type": contentType,
          Authorization: request.headers.get("authorization") || "",
        },
        body: request.body,
        // @ts-expect-error - duplex is required for streaming bodies in standard fetch
        duplex: "half",
      });
    } else {
      body = await request.text();
    }
  }

  try {
    const response = await fetch(fullUrl, {
      method,
      headers,
      body: body || undefined,
    });

    const responseHeaders = new Headers();
    response.headers.forEach((value, key) => {
      responseHeaders.set(key, value);
    });

    // Add CORS headers
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "Content-Type, Authorization");

    const responseBody = await response.text();

    return new NextResponse(responseBody, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (error: any) {
    console.error("Proxy error:", error);
    return NextResponse.json(
      { error: "Backend service unavailable. Please ensure the Rust backend is running on port 8080." },
      { status: 503 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}
