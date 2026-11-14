# AnythingLLM + Authelia OIDC 部署说明

每个 Authelia 用户首次登录时，会在 AnythingLLM 中自动创建同名账号。之后每次登录时，桥会按 Authelia 组同步该账号的角色和工作区权限。

## 文件

```
.
├── docker-compose.yml
├── .env.example          # 复制为 .env
├── Caddyfile             # 内部路由
├── authelia-client.yml   # 合并进 Authelia 配置
├── bridge/server.mjs     # OIDC 登录桥（零依赖）
└── data/                 # 运行时数据（bind mount）
```

## 第一阶段：初始化 AnythingLLM

1. 准备目录和配置：
   ```bash
   mkdir -p data/storage && touch data/anythingllm.env
   sudo chown -R 1000:1000 data
   cp .env.example .env      # 先填 PUBLIC_URL、JWT_SECRET、SIG_KEY、SIG_SALT、BRIDGE_SECRET
   docker compose up -d
   ```
2. 把你的 HTTPS 反代指向本机 `3001` 端口，然后打开 `PUBLIC_URL`，完成 AnythingLLM 的初始化向导。
3. 在 **设置 → 安全** 中开启多用户模式。创建管理员时，**用户名要和你在 Authelia 里的用户名一致**（转成小写）。这样 SSO 登录后会直接对应到这个管理员账号。
4. 在 **设置 → 开发者 API** 中创建一个 API Key，填到 `.env` 的 `ANYTHINGLLM_API_KEY`。
5. 如需按组授权工作区，现在就把工作区建好。工作区 slug 就是 URL 中 `/workspace/` 后面的那一段。

## 第二阶段：开启 SSO

1. 生成 client secret，把 `authelia-client.yml` 合并进 Authelia 配置，然后重启 Authelia：
   ```bash
   docker run --rm authelia/authelia:latest authelia crypto hash generate pbkdf2 \
     --variant sha512 --random --random.length 72 --random.charset rfc3986
   ```
   - 输出中的 `Random Password` 填到 `.env` 的 `OIDC_CLIENT_SECRET`。
   - 输出中的 `Digest` 填到 Authelia 配置的 `client_secret`。
   - `redirect_uris` 改成 `${PUBLIC_URL}/sso/oidc/callback`。
2. 在 `.env` 中填写 `OIDC_ISSUER_URL`、`ALLOWED_GROUPS`、`ADMIN_GROUPS` 等。
3. 取消 `docker-compose.yml` 中 `SIMPLE_SSO_*` 三行的注释，然后执行：
   ```bash
   docker compose up -d
   ```
4. 打开 `PUBLIC_URL`。页面会自动跳转到 Authelia，登录后回到 AnythingLLM。

## 权限映射

| 变量 | 作用 |
|---|---|
| `ALLOWED_GROUPS` | 只有这些组的成员能登录；留空则不限制 |
| `ADMIN_GROUPS` / `MANAGER_GROUPS` | 属于这些组的用户分别映射为 admin / manager，其余用户为 default |
| `SYNC_ROLE` | `true` 时每次登录都按组覆盖角色。只在配置了上面任一组时生效，避免把现有管理员降级 |
| `DEFAULT_WORKSPACES` | 新用户首次登录时加入的工作区 |
| `GROUP_WORKSPACES` | `组:ws1\|ws2,组2:ws3`。每次登录追加授权，**不会**自动移除 |

admin 和 manager 本来就能看到所有工作区，所以工作区映射只对 default 用户有意义。

## 注意事项

- **账号以用户名关联。** Authelia 用户名会转成小写，非法字符替换为 `-`，以数字开头的会加前缀 `u`。如果在 Authelia 中改了用户名，AnythingLLM 中会出现一个新账号。
- **停用用户。** 在 AnythingLLM 中停用账号，或把用户移出 `ALLOWED_GROUPS`，都能阻止其登录。但已登录用户的会话会持续到过期为止，默认 30 天，可用 `JWT_EXPIRY` 缩短。
- **退出登录。** 只退出 AnythingLLM 时，Authelia 会话仍有效，用户会被自动登回。要彻底退出，需要同时退出 Authelia。
- **应急入口。** 开启 `SIMPLE_SSO_NO_LOGIN` 后，账号密码登录会被禁用，管理员也不例外。如果 Authelia 出了问题，把三行 `SIMPLE_SSO_*` 重新注释掉并重启，即可恢复密码登录。
- **API Key 权限。** `ANYTHINGLLM_API_KEY` 相当于管理员权限，只放在 `.env` 中，不要外泄。
- **网络连通。** 登录桥需要能从容器内访问 `OIDC_ISSUER_URL`，必要时配置 DNS 或 `extra_hosts`。如果 Authelia 用的是自签证书，按 compose 中的注释挂载 CA。
- **排查问题。** 查看登录桥日志：`docker logs anythingllm-oidc-bridge`。
