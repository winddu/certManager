# CertManager

自动申请 Let's Encrypt 泛域名证书的工具，包含服务端和客户端。

服务端通过阿里云 DNS API 完成 DNS-01 验证，集中管理所有域名的证书申请与续期；客户端从服务端下载证书并 reload Nginx。

## 项目结构

```
src/
├── CertManager.Shared/       # 共享模型（配置、API DTO）
├── CertManager.Server/       # 服务端
│   ├── Services/
│   │   ├── AcmeService.cs        # Let's Encrypt 证书申请
│   │   ├── DnsProviderService.cs # 阿里云 DNS 操作
│   │   ├── CertRenewWorker.cs    # 每 48h 后台续期检查
│   │   └── AuthService.cs        # HMAC 客户端认证
│   ├── Api/CertApi.cs            # HTTP API 端点
│   └── Logging/DailyFileLogger.cs # 按年月日日志
│
└── CertManager.Client/       # 客户端
    └── Services/
        ├── CertDownloadService.cs # 从服务端下载证书
        └── NginxService.cs        # Nginx reload + 自动检测路径
```

## 服务端

### 功能

- 监听 HTTP 端口，提供 REST API 供客户端下载证书
- 后台每 48 小时检查本地证书有效期，距过期不足 10 天则自动续期
- 通过 Certes 库与 Let's Encrypt 交互，DNS-01 挑战
- 通过阿里云 SDK 自动创建/删除 DNS TXT 记录
- 支持多阿里云账号，每个账号下管理不同域名列表
- 客户端权限控制，每个客户端只能下载授权域名的证书

### 配置文件 `conf.json`

```json
{
  "ver": "1",
  "port": 15555,
  "letsEncryptEmail": "your-email@example.com",
  "certDir": "./certs",
  "certCheckIntervalHours": 48,
  "certRenewDays": 10,
  "clients": [
    {
      "name": "client1",
      "key": "your-client-key",
      "salt": "your-client-salt",
      "privilege": ["example.com"]
    }
  ],
  "certs": [
    {
      "dnsName": "阿里云账号",
      "dnsProvider": "阿里云",
      "keyId": "your-aliyun-access-key-id",
      "keySecret": "your-aliyun-access-key-secret",
      "domains": ["example.com"]
    }
  ]
}
```

参数说明：

| 字段 | 说明 |
|------|------|
| `port` | 监听端口，客户端通过此端口连接 |
| `letsEncryptEmail` | Let's Encrypt 注册邮箱，用于过期提醒 |
| `certDir` | 证书本地保存目录 |
| `certCheckIntervalHours` | 证书检查间隔（小时） |
| `certRenewDays` | 证书剩余多少天时续期 |
| `clients` | 客户端列表，每个客户端有 key、salt 和可访问的域名列表 |
| `clients[].privilege` | 该客户端允许下载哪些域名的证书 |
| `certs` | 阿里云 DNS 账号列表，每个账号包含 keyId、keySecret 及其管理的域名 |
| `certs[].domains` | 该阿里云账号管理的域名（DNS Zone），支持泛域名 `*.domain.com` |

### 证书保存格式

证书保存在 `certs/{domain}/` 目录下：
- `fullchain.pem` — 证书链（`ssl_certificate`）
- `privkey.pem` — 私钥（`ssl_certificate_key`）

### 使用

```bash
# 安装为 Windows 服务（管理员权限）
CertManager.Server.exe --install

# 卸载 Windows 服务（管理员权限）
CertManager.Server.exe --uninstall

# 前台调试运行
CertManager.Server.exe --run
```

首次运行若无配置文件或文件非法，会自动生成示例 `conf.json` 并提示修改。

#### API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/ping` | 健康检查 |
| POST | `/cert/download` | 下载证书（需 HMAC 认证） |

##### 认证方式

每个请求通过 HTTP Body 传递以下字段：

```json
{
  "key": "客户端 key",
  "timestamp": "Unix 毫秒时间戳",
  "sign": "HMAC-SHA256(salt, timestamp + body)",
  "domains": ["example.com"]
}
```

- `sign` 算法: `HMAC-SHA256(salt, timestamp + 完整请求体 JSON)`
- 时间戳超过 5 分钟视为无效
- 服务端验证签名并检查域名权限

## 客户端

### 功能

- 检查本地证书有效期，距过期不足 5 天或证书不存在则向服务端下载
- 自动检测运行中的 Nginx 路径并 reload
- 首次运行自动创建 Windows 计划任务（随机 1~4 点之间，每天运行）
- 支持手动配置 Nginx 路径（不配置则自动检测）

### 配置文件 `conf.json`

```json
{
  "serverUrl": "http://127.0.0.1:15555",
  "key": "your-client-key",
  "salt": "your-client-salt",
  "nginxPath": "",
  "nginxReloadCmd": "nginx -s reload",
  "domains": [
    {
      "name": "example.com",
      "fullchainPath": "C:/nginx/ssl/example.com/fullchain.pem",
      "privkeyPath": "C:/nginx/ssl/example.com/privkey.pem"
    }
  ]
}
```

参数说明：

| 字段 | 说明 |
|------|------|
| `serverUrl` | 服务端地址 |
| `key` / `salt` | 与服务端配置一致的客户端凭据 |
| `nginxPath` | Nginx 安装目录，留空则自动从运行中的 nginx 进程检测 |
| `nginxReloadCmd` | Nginx reload 命令 |
| `domains` | 需要管理的域名列表及证书保存路径 |

### 使用

```bash
# 运行（首次自动创建计划任务，需管理员权限一次）
CertManager.Client.exe
```

客户端会自动检测并运行已安装的计划任务，后续无需手动干预。

## 发布

### 环境要求

- [.NET 8 SDK](https://dotnet.microsoft.com/zh-cn/download/dotnet/8.0)
- Windows x64

### AOT 编译发布

```bash
# 发布服务端（~27 MB）
dotnet publish src\CertManager.Server\CertManager.Server.csproj ^
  -c Release -r win-x64 --self-contained true ^
  -p:PublishAot=true -o publish\server

# 发布客户端（~6 MB）
dotnet publish src\CertManager.Client\CertManager.Client.csproj ^
  -c Release -r win-x64 --self-contained true ^
  -p:PublishAot=true -o publish\client
```

发布产物为单 exe 文件，可直接拷贝到目标机器运行，无需安装 .NET 运行时。

## 部署流程

1. **服务端**
   - 修改 `conf.json`，填入阿里云 AccessKey、Let's Encrypt 邮箱、客户端配置
   - 管理员运行 `CertManager.Server.exe --install` 安装为 Windows 服务
   - 服务会自动启动并每 48 小时检查续期

2. **客户端**
   - 修改 `conf.json`，填入服务端地址、凭据、域名及证书保存路径
   - 管理员运行一次 `CertManager.Client.exe` 创建计划任务
   - 计划任务每天随机在 1~4 点执行，检查并更新证书

## 技术栈

- .NET 8、C#
- [Certes](https://github.com/fszlin/certes) — ACME 客户端
- Alibaba Cloud DNS SDK
- ASP.NET Core Minimal API
- Windows Service / Task Scheduler
