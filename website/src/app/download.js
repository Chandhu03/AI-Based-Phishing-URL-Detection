// Save generated text as a file. The Blob never leaves the browser.
export function download(filename, text, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function readFile(file, maxBytes) {
  if (file.size > maxBytes) return Promise.reject(new Error(`The file is larger than ${Math.round(maxBytes / 1048576)} MB.`));
  return file.text();
}

export const stamp = (d = new Date()) => d.toISOString().slice(0, 16).replace(/[:T]/g, "-");
