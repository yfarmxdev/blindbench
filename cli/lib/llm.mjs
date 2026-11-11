// OpenAI-compatible chat call that keeps the exact bytes sent and received,
// because NEAR AI Cloud signs sha256(request body) and sha256(response body).
import { sha256 } from './util.mjs';
import { fetch as ufetch, Agent, EnvHttpProxyAgent } from 'undici';

// Node's built-in fetch gives up when response headers take more than 300 s, which
// every long unstreamed answer does (the model enclave sends nothing until it has
// finished). Our own timers below bound the request instead.
const NO_LIMIT = { headersTimeout: 0, bodyTimeout: 0 };
const dispatcher = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy
  ? new EnvHttpProxyAgent(NO_LIMIT) : new Agent(NO_LIMIT);

// temperature 0 makes reasoning models loop until they hit max_tokens with no
// answer, so the default is 0.6 (the usual setting for reasoning models).
// stream: NEAR-run enclaves sign non-streamed responses with their own key, but
// streamed ones only with the gateway key, so model-enclave runs use
// stream:false. Streaming keeps bytes flowing on long runs (no idle cut-off).
// Either way the signature covers sha256 of the exact bytes, which we keep.
// params: extra request fields for this model (recorded in the evidence).
export async function chat({ endpoint, apiKey, model, messages, maxTokens = 1024, temperature = 0.6, stream = true, params = {}, timeoutMs = 1800000, idleMs = 300000, failFast = false }) {
  const body = JSON.stringify({ model, messages, max_tokens: maxTokens, temperature, stream, ...(stream ? { stream_options: { include_usage: true } } : {}), ...params });
  if (!stream) idleMs = timeoutMs;
  for (let attempt = 0; ; attempt++) {
    try {
      return await chatOnce({ endpoint, apiKey, model, body, timeoutMs, idleMs });
    } catch (e) {
      // Rate limits get a longer, growing back-off and more tries: an upstream
      // provider can stay saturated for many minutes, and giving up there wastes
      // the whole run (and the tokens already spent on it). The wait is capped so
      // the back-off does not outgrow the run's own timeout.
      const limit = e.rateLimited ? 9 : 4;
      // failFast: the caller has another way to ask (streamed), so a dropped
      // connection or a timeout is not retried here. Busy signals still are.
      if (e.fatal || attempt >= limit || (failFast && !e.rateLimited)) throw new Error(`chat ${model}: ${e.name === 'TimeoutError' ? 'timed out' : e.message}`);
      const wait = e.rateLimited ? Math.min(20000 * 2 ** attempt, 300000) : 5000 * (attempt + 1);
      await new Promise((ok) => setTimeout(ok, wait));
    }
  }
}

async function chatOnce({ endpoint, apiKey, model, body, timeoutMs, idleMs }) {
  const ctl = new AbortController();
  const overall = setTimeout(() => ctl.abort(new Error('timed out')), timeoutMs);
  let idle;
  const touch = () => { clearTimeout(idle); idle = setTimeout(() => ctl.abort(new Error(`no bytes for ${idleMs / 1000}s`)), idleMs); };
  try {
    touch();
    const r = await ufetch(endpoint.replace(/\/$/, '') + '/chat/completions', {
      dispatcher,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept-Encoding': 'identity',
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
      body,
      signal: ctl.signal,
    });
    const chunks = [];
    for await (const c of r.body) { chunks.push(Buffer.from(c)); touch(); }
    const bytes = Buffer.concat(chunks);
    const raw = bytes.toString('utf8');
    if (!r.ok) {
      const err = new Error(`HTTP ${r.status} ${raw.slice(0, 300)}`);
      // 429, and the gateway's 502/503/504 "model currently unavailable", both
      // clear within minutes: same long, growing back-off for either.
      err.rateLimited = r.status === 429 || [502, 503, 504].includes(r.status);
      err.fatal = r.status < 500 && !err.rateLimited;
      throw err;
    }
    const out = { id: null, text: '', finishReason: null, usage: null, reasoningChars: 0 };
    if ((r.headers.get('content-type') ?? '').includes('event-stream')) {
      for (const line of raw.split('\n')) {
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (!data || data === '[DONE]') continue;
        let j; try { j = JSON.parse(data); } catch { continue; }
        out.id ??= j.id;
        const ch = j.choices?.[0];
        out.text += ch?.delta?.content ?? '';
        out.reasoningChars += (ch?.delta?.reasoning_content ?? ch?.delta?.reasoning ?? '').length;
        if (ch?.finish_reason) out.finishReason = ch.finish_reason;
        if (j.usage) out.usage = j.usage;
      }
    } else {
      // Non-streaming servers (the offline mock) answer with one JSON body.
      const j = JSON.parse(raw);
      Object.assign(out, { id: j.id, text: j.choices?.[0]?.message?.content ?? '', finishReason: j.choices?.[0]?.finish_reason ?? null, usage: j.usage ?? null });
    }
    if (!out.id) throw new Error('no completion id in response');
    // The exact bodies are handed back too: sealed grading (lib/sealed.mjs) needs the
    // bytes the enclave signed, not just their hashes.
    return { ...out, requestSha256: sha256(body), responseSha256: sha256(bytes), rawRequest: body, rawResponse: raw };
  } catch (e) {
    if (ctl.signal.aborted && ctl.signal.reason) e = ctl.signal.reason;
    throw e;
  } finally {
    clearTimeout(overall); clearTimeout(idle);
  }
}
