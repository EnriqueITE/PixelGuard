# PixelGuard 隐私声明

本声明适用于 PixelGuard 0.2.0，包括其可选的 VirusTotal 集成功能。

## 本地跟踪分析

PixelGuard 会读取当前显示邮件的 HTML 和基本发件人元数据（例如 From 邮件头中的域名），以识别可能的跟踪像素、跟踪链接和外部图片。跟踪分析在本地进行。PixelGuard 不会修改已保存的邮件，也不会覆盖 Thunderbird 对远程内容的控制设置。

为了提供可选的查询面板，PixelGuard 还会读取当前显示邮件的 HTML 或纯文本，以列出 HTTP(S) 链接，并获取附件名称和大小。它不会访问这些链接，也不会跟随链接的重定向。选择附件进行查询时，会通过 Thunderbird 读取附件字节，并在本地计算 SHA-256 哈希值。作为正常运行的一部分，Thunderbird 可能需要从用户的邮件服务获取邮件或附件数据。PixelGuard 不会执行或解压附件。附件大小的初始上限为 50 MiB。

## 可选的 VirusTotal 请求

此集成功能默认关闭。启用时，需要输入你自己的 VirusTotal API 密钥、确认已了解数据共享说明，并授予可选权限。打开邮件、打开弹出面板或保存密钥都不会发起 VirusTotal 查询。

只有在你主动请求查询后，PixelGuard 才会通过 HTTPS 将以下数据直接发送给 VirusTotal：

- 所选域名，或在预览中显示并经你明确确认的确切完整网址。
- 查询附件时，发送其 SHA-256 哈希值，而非附件内容或文件名。
- 通过身份验证请求头发送你的 VirusTotal API 密钥。

VirusTotal 还会收到常规连接信息，例如你的 IP 地址。哈希值不会泄露文件的字节内容，但可以识别 VirusTotal 已知的文件。网址可能包含个人信息、访问令牌或其他私密标识符。如果不想披露完整地址，请优先选择域名查询。

PixelGuard 使用 VT Augment 小组件 API 查询已有的背景信息。它不会上传邮件正文或附件字节，不会提交网址以发起新的扫描，也不会请求重新分析。它不使用由开发者运营的代理服务器或遥测服务。VirusTotal 的结果提供可选的参考信息，不会改变 PixelGuard 的跟踪分类、警报或计数。

打开官方报告时，会在独立的 Thunderbird 标签页或默认浏览器中加载 VirusTotal 网页。该网页由 VirusTotal 提供，适用其自身的 Cookie、请求、数据保留和账户政策；你在该网页上执行的操作不属于 PixelGuard 的查询流程。请查阅 [VirusTotal 隐私信息](https://docs.virustotal.com/docs/privacy-policy)、[适用条款](https://docs.virustotal.com/docs/terms-of-service)以及 [API 使用条件](https://docs.virustotal.com/reference/public-vs-premium-api)。

## 数据存储与保留

- 偏好设置和检测计数保存在 Thunderbird 的扩展本地存储中。PixelGuard 不会同步这些数据，也不会将其传给开发者。
- 请求时间戳保存在本地，用于执行每分钟最多四次 API 请求、任意连续 24 小时内最多 500 次的限制，重启后仍然有效。这些时间戳不包含域名、网址、哈希值或文件名。在为下一次请求预留名额时，会丢弃超过 24 小时的记录。
- 如果提供了 VirusTotal API 密钥，该密钥会与通用设置分开保存在 `browser.storage.local` 中。此存储并非加密的凭据保险库。能够访问你的 Thunderbird 配置文件、其备份或你的设备的人，可能接触到本地存储的数据。PixelGuard 不会将密钥包含在设置导出、返回给邮件脚本的 API 响应、日志或扩展安装包中。
- VirusTotal 查询对象清单、查询结果和临时报告网址仅在当前邮件会话期间保存在内存中，不会保存为查询历史。在切换该邮件、关闭其标签页、关闭集成功能或更换密钥时，这些数据会被清除。尚未完成的操作无法将结果恢复到已失效的会话中。
- 之前打开的 VirusTotal 标签页会独立保持打开状态。清除 PixelGuard 的内存不会撤销临时报告网址，也不会删除浏览器历史、控制台输出或 VirusTotal 已经收到的数据。
- 调试模式默认关闭。启用后，现有的跟踪扫描器可能会将检测结果（包括邮件中的完整网址）记录到 Thunderbird 的本地控制台。VirusTotal 密钥和临时报告令牌不会写入日志。控制台数据的保留和导出由 Thunderbird 和用户控制。

## 你的控制选项

你可以在 PixelGuard 设置中关闭 VirusTotal、替换密钥或删除密钥。关闭功能会阻止新的查询并取消待处理的请求；删除密钥还会移除已保存的密钥。撤销可选权限会阻止后续查询。关闭集成功能无法撤回已经发送的数据。你可以通过 Thunderbird 的附加组件管理器停用或移除 PixelGuard。

## 权限用途

- `messagesRead`：访问当前显示的邮件及其元数据，列出附件，并读取所选附件以在本地计算哈希值。
- `messagesModify`：注册 PixelGuard 的邮件显示脚本并显示邮件内的提示横幅。PixelGuard 不会编辑邮件，也不会保存对邮件的更改。
- `storage`：保存本地偏好设置、计数以及可选的 API 密钥。
- 可选权限 `sensitiveDataUpload`：说明并授权将所选指标发送给第三方查询服务。
- 可选权限 `https://www.virustotal.com/*`：向固定的 VirusTotal 端点发送经过身份验证的 HTTPS 请求。

## 联系方式

电子邮箱：hello@enriqueite.com
