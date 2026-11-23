const form = document.getElementById('login-form');
const input = document.getElementById('password');
const button = document.getElementById('enter');
const error = document.getElementById('error');

function workerMessage(worker, payload) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('worker_timeout')), 15000);
    channel.port1.onmessage = event => { clearTimeout(timer); resolve(event.data); };
    worker.postMessage(payload, [channel.port2]);
  });
}

function destination() {
  const next = new URL(location.href).searchParams.get('next') || 'content/index.html';
  if (!next.startsWith('content/') || next.includes('..') || next.includes('\\')) return './content/index.html';
  return `./${next}`;
}

let workerReady;
try {
  workerReady = navigator.serviceWorker.register('./sw.js', { scope: './' }).then(() => navigator.serviceWorker.ready);
  workerReady.then(async registration => {
    const state = await workerMessage(registration.active, { type: 'status' });
    if (state?.authorized) location.replace(destination());
  }).catch(() => {});
} catch {
  error.textContent = '이 브라우저에서 보안 저장 기능을 사용할 수 없습니다.';
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  error.textContent = '';
  button.disabled = true;
  button.textContent = '확인 중…';
  try {
    const [registration, configResponse, manifestResponse] = await Promise.all([
      workerReady, fetch('./config.json'), fetch('./manifest.bin')
    ]);
    if (!configResponse.ok || !manifestResponse.ok) throw new Error('network');
    const config = await configResponse.json();
    const salt = Uint8Array.from(atob(config.salt), char => char.charCodeAt(0));
    const passwordBytes = new TextEncoder().encode(input.value);
    const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: config.iterations, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const sealed = await manifestResponse.arrayBuffer();
    const data = new Uint8Array(sealed);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
    const manifest = JSON.parse(new TextDecoder().decode(plaintext));
    if (manifest.version !== 1 || !manifest.files?.['index.html']) throw new Error('manifest');
    const result = await workerMessage(registration.active, { type: 'unlock', key, manifest });
    if (!result?.ok) throw new Error('worker');
    input.value = '';
    location.replace(destination());
  } catch (cause) {
    error.textContent = cause?.name === 'OperationError'
      ? '비밀번호가 일치하지 않습니다.'
      : '자료를 불러오지 못했습니다. 새로고침 후 다시 시도해 주세요.';
    input.select();
  } finally {
    button.disabled = false;
    button.textContent = '가이드 보기';
  }
});
