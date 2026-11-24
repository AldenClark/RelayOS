# WireGuard / IPsec 控制与 UI 审计

日期：2026-11-25（北京时间）。审计基线：`c21935a35eb12b9bc1bb4ba365b1c2bb8dca7aee`。

本次覆盖 LuCI 编辑器、管理网络与隧道的保存关系、UCI/RPC 权限、Agent 所有权、
WireGuard 防火墙补全，以及 IPsec 配置发布、运行状态核实和回滚。
按“各模块审查与复现 → 原生 LuCI/UCI 行为核对 → 整合后独立复审”进行了三轮检查。
修复没有改变锁定的 OpenWrt/LuCI 版本、内核、SOE/EIP-93 驱动或手动固件构建策略。

## 已确认问题与修复

| 范围 | 问题及影响 | 修复 |
| --- | --- | --- |
| WireGuard 创建 | 在原生表单解析前填入新接口默认值，尚未渲染的监听端口被解析过程删除，创建后变成 Automatic，无法按预期生成固定端口放行规则 | 在当前表单校验完成后的保存回调中创建接口及默认值 |
| WireGuard 创建 | 新接口创建后仍保留 `NamedSection.addremove`，重绘时出现没有专门所有权保护的原生删除入口 | 创建完成后关闭该删除入口，保持现有隧道不提供整接口删除的契约 |
| WireGuard 对端编辑 | 新增和删除对端先改 UCI 再校验当前表单；校验失败仍遗留界面未显示的新增/删除 | 新增在校验通过后执行；删除时跳过目标自身的必填校验，其他字段通过后才删除；结构性编辑统一进入共享操作门禁 |
| WireGuard 密钥 UI | `onchange` 参数数量与原生 LuCI 不符，实际私钥未传给派生公钥 RPC | 使用原生 `(event, section_id, value)` 签名；清空/无效输入清除公钥，忽略过期异步返回 |
| WireGuard 输入校验 | `/00` 和全零点分掩码等合法输入形式可绕过原先的默认路由正则；密钥尾部换行也可绕过 `$` 结尾匹配 | 数值解析 CIDR/连续掩码，密钥强制精确长度；拒绝会覆盖特殊地址范围的本地前缀 |
| WireGuard 路由与端口 | 缺少跨隧道、管理网络、IPsec 保护网段的冲突检查，同一隧道重复公钥和多个启用隧道同端口也会造成错误配置 | 在应用前结合配置草稿、当前 netifd 状态和最新 IPsec 配置进行校验 |
| WireGuard 防火墙 | 已有隧道分区时不再补全缺失的出口转发和 NAT；多个分区归属时会选取任意匹配项 | 对已有归属补全必要的出口能力；在修改前拒绝不唯一的相关分区配置 |
| 共存 | WireGuard 可占用 UDP 500/4500，与启动后的 charon 监听冲突 | 两个方向均校验；IPsec 全局启用即保留两个端口，即使暂时没有启用的对端 |
| 共享保存 | 管理网络和 WG 使用全局 UCI 待应用区，单独点 LAN 保存可能带上尚未完整校验的 WG 草稿 | 两个按钮走联合解析、校验和保存路径，继续使用原生确认应用/自动回滚 |
| 并发 UI | IPsec 应用期间仍可能执行 WG 结构性保存；原生 `ui.changes.apply()` 返回空值，不能把函数返回当成确认完成 | 共享门禁覆盖 WG 创建/增删、LAN/WG 保存和 IPsec 应用；原生 modal 持续期间也拒绝其他变更 |
| 权限与所有权 | 页面级写权限可来自其他设置项，不能证明具有 network/firewall 写权限；不完整 Agent 状态也曾被当成可手动配置 | 分别核实 UCI 权限；缺失关键 Agent 状态时不授予手动控制；Agent 接管后不允许 LAN 保存夹带旧 WG 暂存修改 |
| IPsec 高级参数 | 收起高级参数后，DPD/MTU 小数触发浏览器 number 原生校验，阻止 submit，页面自己的错误提示没有执行 | 自定义表单使用 `novalidate`，统一由现有严格校验器显示可见错误，RPC 前仍拒绝无效值 |
| IPsec 并发发布 | 较慢的路由保护/对端静默操作与最终文件发布之间，其他 UCI 写入可被旧快照覆盖 | 每次发布前核对四个文件的预期内容，成功前再核对；保留其他写入，无法安全恢复时报告回滚失败并保留保护路由 |
| IPsec 状态快照 | 先读对端、后取 revision，可能把旧对端数据和新 revision 一并返回 | 在组装响应前后读取并核对 revision，不一致时拒绝该快照 |
| IPsec 运行核实 | 原先只检查期望对象存在，删除失败、旧地址/路由残留及 MTU 未生效可能仍返回成功 | 同时核实已删除对象和旧状态消失，并比较实际 MTU；应用和回滚均使用该检查 |

## 保存行为

管理网络和 WireGuard 属于同一原生 UCI 应用事务。页面明确说明其修改会一并校验、
一并应用；任意一侧校验失败时都不执行原生 apply。IPsec 保留独立的事务与草稿，
不会提交 LAN/WireGuard 的待应用配置。

IPsec 操作会改变生成的 network 配置，因此 WG 保存使用最新 IPsec 对端地址和保护
网段，替代页面加载时缓存的生成段。关闭的 IPsec 对端仍保留保护网段；删除完成后，
旧网段不会仅因浏览器缓存而继续被错误占用。

如果 Agent 已接管或者 WG 编辑器只读，LAN 页面无法验证旧的 WG 暂存操作，因而拒绝
夹带已有 network/firewall 暂存修改。没有这类旧暂存修改时，仍允许正常修改管理网络。

## 验证证据与复现方式

自动化验证使用一次性配置目录和合成密钥，不操作真实路由器。

最终回归结果：8 组控制台测试通过；原生模型 134 项断言通过；原生运行测试
105 项结果检查通过；两套 LuCI DOM 集成测试及 shell 桥接测试通过。运行测试还覆盖
64 个对端、256 个前缀的配置上限。JavaScript/shell 语法、差异空白检查和
179 条在用 UI 文本的中文翻译覆盖/目录编译检查通过。

- `tests/test-console-*.cjs`：控制台回归，包括新增的共享 Settings 保存及 Agent 状态测试。
- `tests/test-ipsec-model.uc`：原生 ucode 模型检查，包括双向端口冲突的后端策略。
- `tests/test-ipsec-runtime.cjs`：真实锁定版本的 ucode/UCI，设备命令使用隔离适配器；
  覆盖两对端与 WG 隔离、并发写入、删除/地址/路由/MTU 后置条件、服务故障和回滚。
- `tests/test-ipsec-dom.cjs`：真实锁定 LuCI DOM/RPC 实现与 jsdom，覆盖无效高级参数、
  草稿保留、两对端编辑、密钥脱敏、ACL 变化和保存门禁。
- `tests/test-wireguard-dom.cjs`：真实锁定 LuCI form/UI/validation 实现与 jsdom，
  覆盖创建默认值、密钥 onchange、必填校验、对端增删、共享门禁及只读控件。
- `tests/test-ipsec-control.sh`：固定 shell/RPC 桥接和权限相关静态回归。

```sh
# 使用已准备的锁定 OpenWrt 源码，含 feeds/luci。
export OPENWRT_DIR=/absolute/path/to/pinned/openwrt
for test_file in tests/test-console-*.cjs; do node "$test_file" || exit; done
bash tests/test-ipsec-control.sh

# 真实原生 UCI/ucode；必要时设置对应 LD_LIBRARY_PATH。
UCODE=/absolute/path/to/pinned/ucode UCI=/absolute/path/to/pinned/uci \
  bash scripts/test-ipsec-native.sh

JSDOM_MODULE=/absolute/path/to/node_modules/jsdom \
LUCI_DIR=/absolute/path/to/pinned/luci node tests/test-ipsec-dom.cjs
JSDOM_MODULE=/absolute/path/to/node_modules/jsdom \
LUCI_DIR=/absolute/path/to/pinned/luci node tests/test-wireguard-dom.cjs
```

本轮核对的原生依赖为 ucode `dfc64d41fd720163ac21d9feb9cb224d1a80fd75`、
UCI `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8`、
LuCI `a7614a633e88274373e61c28262a2736f1446a7b`；LuCI 上游测试源保持未修改。
新增英文提示均补齐简体中文翻译；`relay-ipsec` 包 release 提升为 3。

## 仍需设备验收的边界

本轮没有构建或刷写固件，没有连接真实的 XG-040G-MD/MF。
jsdom 验证不能代替浏览器布局或真实设备交互验证；本环境 Chromium 启动受到限制，
因此不把桌面/移动端截图检查计为通过。

下一次固件验收应重点执行：

1. 同时保持两个 IPsec 对端和一个 WG 隧道有业务流量；修改、停用或删除 A 时，
   验证 B 和 WG 不被全局重启。
2. 对照 `ip -d link`、地址和路由检查 MTU/网段变化及删除结果；停用对端后确认
   保护路由仍存在，删除后仅释放该对端的前缀。
3. 通过实际浏览器验证创建 WG、私钥派生公钥、增删对端、无效输入提示及联合保存，
   并验证管理 IP 改动的确认/回滚。
4. 检查重启与保留配置升级后的恢复，并分别核实 MD/MF 上实际 netifd 完成时间。

任意 SSH/UCI 外部写入没有加入本管理器锁时，四个配置文件仍不是全局原子事务。
新增检查用于缩小覆盖风险并拒绝不一致状态；不能据此承诺任意并发写入均可无损自动恢复。
本次验证也不证明真实 SA 的互通性、硬件加密卸载或吞吐率。
