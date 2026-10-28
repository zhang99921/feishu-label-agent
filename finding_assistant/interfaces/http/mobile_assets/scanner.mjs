// 设备适配边界：仅接受明确注册的采集器，不猜测宿主API或解析任意URL。
// 飞书原生扫码接入并完成手机验收后，由宿主安装扫描适配器。
let adapter = null;
export function installScanner(scanner) {
  if (typeof scanner !== 'function') throw Error('无效扫码适配器');
  adapter = scanner;
}
export function scannerReady() { return adapter !== null; }
export async function scanBox() {
  if (!adapter) throw Error('当前设备扫码尚未接入，请使用扫码枪或输入箱号');
  const code = await adapter();
  if (typeof code !== 'string' || !code.trim() || code.length > 200 || /\s/.test(code.trim())) {
    throw Error('未读取到有效箱号');
  }
  return code.trim();
}
