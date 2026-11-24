export function NeedLogin({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="boot">
      <div className="login-card" role="main">
        <div className="brand-mark brand-mark-lg" aria-hidden>
          A
        </div>
        <h1>需要登录</h1>
        <p>控制台只在你的开发机上运行，用一次性登录链接验证身份。</p>
        <ol className="steps-list">
          <li>
            在开发机终端运行 <code>pa console</code>
          </li>
          <li>
            打开它打印的登录链接（形如 <code>http://&lt;局域网IP&gt;:7878/login?token=…</code>）。若配置为仅监听本机，通过 SSH / VS Code 端口转发访问时把主机和端口换成转发后的地址
          </li>
          <li>登录状态会保存在这个浏览器里 30 天</li>
        </ol>
        <p className="muted small">链接里的令牌等同于密码，请不要分享。如果怀疑泄露，可以重新生成令牌让旧链接失效。</p>
        <button className="btn btn-primary" onClick={onRetry}>
          我已登录，重试
        </button>
      </div>
    </div>
  );
}
