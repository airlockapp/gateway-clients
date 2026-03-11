import type { RequestInit, Response } from "node:http";

/** Create a mock fetch function that returns pre-configured responses. */
export function createMockFetch() {
    const requests: Array<{
        method: string;
        url: string;
        body?: string;
        headers: Record<string, string>;
    }> = [];

    const responses: Array<{
        status: number;
        body: string;
        headers?: Record<string, string>;
    }> = [];

    function enqueue(status: number, body: unknown = ""): void {
        responses.push({
            status,
            body: typeof body === "string" ? body : JSON.stringify(body),
        });
    }

    async function mockFetch(url: string | URL, init?: RequestInit): Promise<Response> {
        const method = (init?.method ?? "GET").toUpperCase();
        const bodyStr = init?.body ? String(init.body) : undefined;
        const headers: Record<string, string> = {};

        if (init?.headers) {
            const h = init.headers as Record<string, string>;
            for (const [k, v] of Object.entries(h)) {
                headers[k] = v;
            }
        }

        requests.push({ method, url: String(url), body: bodyStr, headers });

        if (responses.length === 0) {
            throw new Error(`MockFetch: No response enqueued for ${method} ${url}`);
        }

        const mock = responses.shift()!;
        return {
            ok: mock.status >= 200 && mock.status < 300,
            status: mock.status,
            statusText: `${mock.status}`,
            text: async () => mock.body,
            json: async () => JSON.parse(mock.body),
            headers: new Headers(mock.headers ?? {}),
        } as unknown as Response;
    }

    return { fetch: mockFetch as unknown as typeof globalThis.fetch, requests, enqueue };
}
