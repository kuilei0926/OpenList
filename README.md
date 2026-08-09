<div align="center">
  <img src="https://raw.githubusercontent.com/OpenListTeam/Logo/main/logo.svg" width="128" height="128" alt="logo" />

  <p><em>OpenList FotCrypt Fork — 在 OpenList 上集成飞牛 fnOS 加密备份（.fot）解密/加密驱动的个人分支。</em></p>

  <a href="https://github.com/kuilei0926/OpenList"><img src="https://img.shields.io/github/license/kuilei0926/OpenList" alt="License" /></a>
  <a href="https://github.com/kuilei0926/OpenList/releases"><img src="https://img.shields.io/github/release/kuilei0926/OpenList" alt="latest version" /></a>
</div>

---

# 本仓库说明

**这是一个 OpenList 的个人 fork**，在保持与上游 [OpenListTeam/OpenList](https://github.com/OpenListTeam/OpenList) 同步的基础上，新增了一个 **FotCrypt** 存储驱动。

> 上游 OpenList 的完整中文文档见 [README_cn.md](./README/README_cn.md)。本文件仅补充 fork 特有的内容。

## 为什么有这个仓库

飞牛私有云（fnOS）的「加密备份」功能会把文件加密成 `.fot` 格式。官方没有提供在线浏览/直接访问这些加密文件的方式，也没有离线解密工具。

本 fork 新增的 **FotCrypt** 驱动可以让 OpenList **透明地解密这些 `.fot` 文件**，实现：
- 📂 直接浏览加密备份目录，显示**解密后的真实文件名和大小**
- ▶️ 在线预览、播放（视频/音频/图片/文档），支持拖动进度条（随机访问）
- ⬇️ 直接下载解密后的文件
- ⬆️ 上传文件时**自动加密成 .fot 格式**，兼容飞牛备份格式

由于驱动实现依赖对 fnOS 私有加密格式的逆向分析、且首次列出大目录的性能受网盘 API 限速影响较大，**该驱动不推送给上游**，仅在此个人仓库发布，供有需要的人使用。

---

## FotCrypt 驱动

> **解密思路来源**：本驱动的 .fot 格式分析基于飞牛官方论坛用户 [陪玩](https://club.fnnas.com/forum.php?mod=viewthread&tid=69019) 分享的《飞牛加密备份 FOT 文件离线脱机解密记录》帖文（https://club.fnnas.com/forum.php?mod=viewthread&tid=69019 ），在此致谢。

### 快速开始

1. 先在 OpenList 添加一个**底层存储**（本地目录、WebDAV、阿里云盘等），里面存放 `.fot` 加密文件
2. 再添加一个 **FotCrypt** 存储，填写：
   - **Password**：加密口令（必须与创建 fnOS 备份时设置的一致）
   - **Remote Path**：底层存储的挂载路径，如 `/local` 或 `/webdav`

配置完成后，打开 FotCrypt 挂载的目录即可看到解密后的文件。

### 工作原理

- **解密（读）**：`.fot` 文件显示为原始文件名和明文大小；下载/预览时通过 AES-256-CTR 实时解密，支持随机访问（HTTP Range / 视频拖动）
- **加密（写）**：上传的文件自动加密为 `.fot`（PBKDF2 + AES-256-CTR + HMAC），与飞牛备份格式兼容

### 已知限制

- **首次打开大目录较慢**：每个 `.fot` 文件都需要读取头部才能得到真实文件名/大小，相当于每个文件一次底层存储请求。在云盘上受限于厂商 API 限速（如阿里云盘 `getDownloadUrl` 约 1 次/秒），几百个文件的目录首次打开可能需要一分钟左右。**再次打开走缓存，秒开**。
- 读写内容无损，但 `.fot` 文件名编码了原名/大小/mtime，如需恢复到飞牛系统请保留原始 mtime。

---

## 构建与发布

本 fork 通过 GitHub Actions 在 Release 发布时自动构建全平台二进制，与上游流程一致。

## 上游 OpenList

OpenList 是一个有韧性、长期治理、社区驱动的 AList 分支，功能完整、生态成熟。上游项目信息见：

- [OpenListTeam/OpenList](https://github.com/OpenListTeam/OpenList)
- [官方文档](https://doc.oplist.org)

## 许可证

基于 [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.txt) 许可证开源。详情见 [LICENSE](./LICENSE)。
