# WireGuard / IPsec 控制与 UI 追加审计

日期：2026-11-25（北京时间）。本次基线：
`1d3f0b9fb6e0fbf0c9fcde7dd0298e6a56d8afe7`。
这是上一批修复后的追加检查；上一轮结果保留在
[首轮报告](control-ui-audit-2026-11-25.md)，不重复计算为本次发现。

本次分三轮推进：先核对锁定版本的 netifd、WireGuard、fw4 和 LuCI 接口语义，
再用真实 LuCI/UCI 与原生 ucode/UCI 注入失败、验证复现，最后交叉复审修复并进行
整合回归。设备命令仍使用一次性测试适配器，没有连接或更改真实路由器。

## 新确认的问题

| 范围 | 复现与影响 | 修复 |
| --- | --- | --- |
| WG 地址序列化 | LuCI 接受点分掩码和带前导零的 IPv4；这些值原样进入 WG 配置时，与原生脚本/工具的解析不一致。例如 `10.77.0.2/255.255.255.0` 会产生错误前缀 | 在原生表单写入阶段规范化地址和数字 CIDR，拒绝非连续掩码；端点 IPv4 也规范化，保留 DNS 主机名 |
| WG 端口 | `port` 校验允许端点端口 `0`，原生 WG 却忽略该 Endpoint；监听端口 `0` 表示自动选择，原逻辑会生成 UDP 0 的无效放行规则 | 端点端口限定 1–65535；自动监听端口不生成固定端口放行规则 |
| WG 停用状态 | 已停用的对端仍显示为普通对端，并满足“至少一个对端”检查，实际 netifd 不加载该对端 | 显示对端启用开关；启用的隧道要求至少一个启用对端；区分接口与对端各自的原生停用语义 |
| 隧道网段预检 | 静态地址/路由采用点分、八进制或十六进制掩码时，IPsec 预检会忽略合法但非规范 CIDR 的范围；WG 对部分原生静态格式也存在同类遗漏。接口尚未启动时，内核查询无法补上这个范围 | 两侧在环境读取层按原生语义规范化静态配置和标量多地址，保留各自的用户输入规则；已有 WG 前缀单独按其脚本语义处理 |
| 防火墙预检 | fw4 对停用分区、重复分区名及不适用的地址族可能跳过而不让检查命令失败，原控制器仍会宣布配置成功；WG 也曾把停用的现有转发视为已配置 | 在修改前核实相关分区启用、名称唯一、支持 IPv4；WG 额外核实已有必要转发启用，保留用户停用策略并报错 |
| WG 结构性操作 | 创建接口、增删对端使用 `map.save()`，会立即发送所有已加载配置的 UCI 写入。部分 RPC 失败后，远端与页面可能不同步，重试可产生重复对端 | 这些操作只修改浏览器内草稿；显式 Save & Apply 统一解析、验证和发送 |
| 共享保存部分失败 | 原生 `uci.save()` 并行执行多个写入；一个匿名新增成功、另一个写入失败后，客户端仍保留该新增，直接重试会再新增一次 | 保留当前页面输入并阻止继续写入，明确提示重新加载、检查待应用更改，提供重载入口；不自动撤销其他待应用更改 |
| 保存中的编辑 | 校验完成后等待远端状态时，LAN/WG 输入仍可修改；后续重绘会静默丢掉这段输入 | 网络操作期间冻结两个表单及自定义控件，结束后恢复原有只读/禁用状态 |
| 错误展示 | 联合保存绕过原生 `map.save()` 的错误提示；按钮处理器仅恢复按钮，预检或 RPC 拒绝缺少可见说明 | 在用户操作入口显示错误通知，保留草稿，并处理按钮事件的 Promise 拒绝 |
| 管理网络地址 | 普通 `ip4addr` 接受前导零 IPv4 和 `/CIDR`；netifd 的网关和 DNS 要求裸地址，地址解析也拒绝前导零。管理口保存看似通过，原生配置却失败或忽略该值 | 网关、DNS 和独立掩码字段使用无前缀校验，写入时规范化 IPv4；管理地址保留地址/前缀语义并转换为原生可消费格式 |
| 动态列表输入 | LuCI 动态列表会把无效的待添加文本排除在聚合值之外，已有合法项可能使整个字段再次通过校验，保存或增删重绘后丢掉错误输入 | 对 WG 地址、AllowedIPs 和 DNS 同时校验待添加输入；错误时停止操作并保留该输入供修改 |

## 保存和恢复行为

创建 WG 隧道、添加或删除对端，现在只修改当前页草稿。这些操作不会触发 UCI RPC，
也不会顺带保存管理网络的修改。LAN/WG 的两个 Save & Apply 按钮继续执行联合验证，
使用原生确认应用和自动回滚流程。IPsec 保留自己的保存事务。

所有预检和输入错误都允许修改后重试。只有真正进入 UCI 保存后发生失败，才要求
重新加载：此时不能从单个失败响应推断哪些并行写入已完成。当前页保留可核对的输入，
但共享写操作被阻止；重新加载后应检查实际待应用配置，再继续编辑或应用。
这不会自动恢复或清空 rpcd 中可能已成功保存的部分修改。

防火墙预检不会擅自启用用户明确停用的分区或转发。它会拒绝把这些配置当作有效出口，
在发生设备配置变更前给出错误。IPsec 的旧快照保护、路由保护及回滚机制继续保留。

## 上游核对依据

本轮针对仓库固定版本，不依据其他 OpenWrt 版本猜测行为：

- [OpenWrt WireGuard 脚本](https://github.com/openwrt/openwrt/blob/64c777f3af8ad1503c257afe686e44200de832c7/package/network/utils/wireguard-tools/files/wireguard.uc)：地址前缀、Endpoint 端口、对端停用和配置生成。
- [LuCI UCI 客户端](https://github.com/openwrt/luci/blob/a7614a633e88274373e61c28262a2736f1446a7b/modules/luci-base/htdocs/luci-static/resources/uci.js)：并行保存、失败后的 creates 状态。
- [LuCI 表单](https://github.com/openwrt/luci/blob/a7614a633e88274373e61c28262a2736f1446a7b/modules/luci-base/htdocs/luci-static/resources/form.js)、[UI 控件](https://github.com/openwrt/luci/blob/a7614a633e88274373e61c28262a2736f1446a7b/modules/luci-base/htdocs/luci-static/resources/ui.js)和[校验器](https://github.com/openwrt/luci/blob/a7614a633e88274373e61c28262a2736f1446a7b/modules/luci-base/htdocs/luci-static/resources/validation.js)：错误通知、动态列表和 IPv4 输入语法。
- [netifd 掩码解析](https://github.com/openwrt/netifd/blob/a1e39a458f9601100ee6bf91b0d6800688cf6a5b/utils.c)、[接口配置](https://github.com/openwrt/netifd/blob/a1e39a458f9601100ee6bf91b0d6800688cf6a5b/config.c)、[静态地址/网关](https://github.com/openwrt/netifd/blob/a1e39a458f9601100ee6bf91b0d6800688cf6a5b/proto.c)及[DNS](https://github.com/openwrt/netifd/blob/a1e39a458f9601100ee6bf91b0d6800688cf6a5b/interface-ip.c)：另直接编译并运行了该版本的原始掩码解析函数核对输入结果。
- [fw4 分区和转发解析](https://github.com/openwrt/firewall4/blob/3722eadc088c3ab81389596ca9796112b436583a/root/usr/share/ucode/fw4.uc)：停用、重复名称和地址族处理。

## 回归验证

最终整合结果：

| 检查 | 结果 |
| --- | --- |
| 控制台回归 | 8 组 `test-console-*.cjs` 全部通过 |
| IPsec 原生纯模型 | 134 项断言通过 |
| IPsec 原生运行回归 | 167 项结果检查通过；真实锁定 ucode/UCI，设备命令模拟 |
| 原生 LuCI DOM | IPsec、WireGuard、Settings 三套全部通过 |
| shell / RPC 桥接 | 固定动作、输入/输出、锁、权限及默认关闭启动回归通过 |
| 源码与翻译 | JavaScript/shell 语法、差异空白检查通过；189 条在用 UI 文本中文覆盖、目录检查与 MO 编译通过 |

运行回归包括 64 个对端、256 个前缀的配置上限、批量密钥更新和关闭/删除；本次
主机 fixture 的上限应用为 3062 ms，该数字不代表设备性能或加密吞吐率。
新增的真实 Settings DOM/UCI 回归为 `tests/test-settings-dom.cjs`，WG DOM 回归
也改为使用锁定 LuCI 的真实 UCI 客户端，避免简单替身隐藏部分 RPC 失败和本地
草稿语义。

部分保存测试包含负对照：一个新增成功、另一项写入失败后，产品门禁阻止重试，
对端数量保持为 2；只在一次性测试中绕过门禁再次调用原生 `uci.save()`，数量确实
变为 3，从而验证重复创建风险和防护作用。异步编辑测试也先用基线重现了 `.99`
草稿被先前解析的 `.21` 覆盖，再验证修改后操作期间的控件锁定和恢复。

```sh
export OPENWRT_DIR=/absolute/path/to/pinned/openwrt
for test_file in tests/test-console-*.cjs; do node "$test_file" || exit; done
bash tests/test-ipsec-control.sh

UCODE=/absolute/path/to/pinned/ucode UCI=/absolute/path/to/pinned/uci \
  bash scripts/test-ipsec-native.sh

export JSDOM_MODULE=/absolute/path/to/node_modules/jsdom
export LUCI_DIR=/absolute/path/to/pinned/luci
node tests/test-ipsec-dom.cjs
node tests/test-wireguard-dom.cjs
node tests/test-settings-dom.cjs
```

## 验证边界

原生 UCI/ucode 和 LuCI DOM 测试能证明上述控制逻辑、输入处理和失败路径，
不能证明真实 SA 互通、流量转发、固件启动时序、浏览器布局或硬件卸载性能。
本轮没有构建/刷写固件，也未连接 MD/MF 实机。后续实机验收应重点覆盖掩码输入、
启停对端、部分 RPC 失败后的待应用区、管理地址变更确认/回滚，以及两个 IPsec 对端
与活跃 WG 的隔离性。

本次不修改 OpenWrt/LuCI 锁定版本、内核或 SOE/EIP-93 驱动；`relay-ipsec`
包 release 提升为 4。
