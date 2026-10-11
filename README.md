# WebTunnel UID

[WebTunnel](https://github.com/Desmond-Dong/webtunnel) 的精简单集成：**仅支持 UID 登录**。

## 功能

- 添加集成时填入 WebTunnel 平台分配的 uid 即可
- 云端心跳监控、隧道自动连接
- 本机绑定的通道自动发现为通道子条目（实体：通道状态、公网地址、流量等）
- 基础信息设备：状态、通道数量、心跳、月流量、连接状态、重连按钮
- 无账号密码、无验证码、无云端通道管理（创建通道/删除请用主集成或官方客户端）

## 安装（手动）

把 `custom_components/webtunnel_uid/` 复制到 HA 的 `config/custom_components/` 下，重启 HA。

## 一键安装

[![通过 HACS 安装](https://img.shields.io/badge/HACS-一键安装-41bdf5)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Desmond-Dong&repository=webtunnel-uid&category=integration)
[![添加集成](https://img.shields.io/badge/集成-一键添加-41bdf5)](https://my.home-assistant.io/redirect/config_flow_start/?domain=webtunnel_uid)
