const CSP = "default-src 'none'; img-src cid: data:; style-src 'unsafe-inline'";

// The policy goes first so a meta tag inside the email cannot come before it.
export function frameDocument(html: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${CSP}"></head><body>${html}</body></html>`;
}

export function showEmail(host: HTMLElement, html: string): HTMLIFrameElement {
  const frame = document.createElement("iframe");
  frame.setAttribute("sandbox", "");
  frame.srcdoc = frameDocument(html);
  host.appendChild(frame);
  return frame;
}
