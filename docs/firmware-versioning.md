# RelayOS 固件版本号

## 版本与构建标识

固件版本采用 `YYYYMMDD-<12 位 Git SHA>`，例如
`20261125-eeb4588834ab`。日期取 **RelayOS 源码提交的 committer date**，统一转换成 UTC。
CI 从实际检出的提交计算版本，同一次提交的 MD、MF、sysupgrade、recovery 和重复构建共用版本。
日期用于识别发布时期。同一天的提交通过 Git SHA 区分，先后次序以 Git 提交关系或发布记录为准。

构建另有标识 `<GitHub run ID>.<attempt>`，例如 `123456789.1`。构建标识、构建时间和 SHA-256
用于区分同源重跑的产物。脏工作区只允许本地构建，显示 `-dirty`，发布任务拒绝这种产物。
日期和短 SHA 均从完整提交推导，发布元数据同时保留完整 SHA。

## 显示、文件和发布

| 位置 | 示例 |
| --- | --- |
| 设备页面与 OpenWrt 版本字段 | `RelayOS 20261125-eeb4588834ab` |
| Sysupgrade 文件 | `relayos-20261125-eeb4588834ab-mf-squashfs-sysupgrade.itb` |
| Recovery 文件 | `relayos-20261125-eeb4588834ab-mf-initramfs-recovery.itb` |
| GitHub 开发发布标签 | `relayos-20261125-eeb4588834ab-mf-dev.123456789.1` |

现有 CI 按板型分开执行，因此标签带 `md` 或 `mf`，两个板型仍共用同一个源码版本。开发发布
继续标记为 prerelease。
标签指向完整源码提交，已发布的镜像、标签和校验和保持不可变。同一次开发构建的不同尝试使用各自的标签。

## 单一来源与兼容性

CI 在配置 OpenWrt 前生成版本与构建信息，用同一份数据写入固件、导出构建信息、产物名和
发布标签。记录 RelayOS 完整提交、OpenWrt 与 feeds 锁定提交、设备板型、镜像类型、构建 ID、
构建时间和 SHA-256。导出时核对镜像元数据与期望板型，校验两种镜像和清单属于同一版本。

板型与 UBI 布局仍由原有镜像校验约束。OpenWrt 软件包版本、内核 ABI 和配置迁移各自遵循原有规则。
回滚按板型、完整提交和校验和选择已验证镜像。LuCI 缓存继续使用资源内容生成的标识，发布版本用于显示和追溯。
