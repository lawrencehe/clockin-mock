# 方案B:OS 层数据注入(设备可信度完全继承)

> 思路:不碰协议、不碰 App,在数据源头(OS 框架 API / SDK 边界)注入打卡点
> 的 GPS 与 WiFi。App 内部逻辑、签名、device_register、ttreq、risk_info
> 全部由真 App 自己生成 —— 服务端看到的是一个完全正常的客户端。
>
> 依据:`~/lark31/lark-clockin-study` 逆向结论(引用处见各节)。

## 1. 为什么选这条路(对比直调接口)

| | 方案A 直调接口 | 方案B OS层注入 |
|---|---|---|
| 签名/凭证(第1层) | 需抓包抠 + ttreq 定期过期重抓 | ✅ App 自己维护,永不过期 |
| 设备信誉 | 借用真机,行为模式仍异常 | ✅ 就是真机行为 |
| 环境数据(第2层) | wifi.json/GPS 手工构造 | ✅ 注入同样数据,但由 App 正常采集链路消费 |
| 风险_info | 手工构造,画像易突变 | ✅ 如实上报(root 用 DenyList 隐藏后为 false) |
| 维护成本 | 抓包/协议变动敏感 | App 升级后 hook 点可能漂移(中等) |
| 前提 | 无 | 一台 root/Magisk 设备 |

策略:**方案A 的 --probe 探测先行,成本已付;方案B 作为主力/兜底。** 两者
共用同一份 wifi.json 快照与锚点坐标。

## 2. 注入点选择(逆向证据决定,勿改)

### 2.1 WiFi —— OS 框架层,直接 hook ✅

`SpeedClockInWifiManager`(03-sources/clockin-core/state/)读的是标准 API:

```
WifiManager.getConnectionInfo()      → 当前连接 BSSID/SSID
WifiManager.getScanResults()         → scan_wifi_list
WifiManager.startScan()              → 触发扫描(返回注入列表即可)
```

外层 `cw0.c` 只是安全调用包装,最终仍走 WifiManager —— hook 框架层,
App 侧零感知。

### 2.2 GPS —— ⚠️ 不能只 mock OS 定位提供者

调用链(实测):`SpeedClockInLocationManager` → `u83.b.b().getLocationV2()`
→ **高德 AMap 融合定位**。两个坑:

1. Lark 调用了 `AMapLocationClient.setMockEnable(false)`(map/service/f.java
   L314/L353)→ 开发者选项"模拟位置应用"+Fake GPS 的经典方案会被
   AMap 引擎**忽略**。
2. AMap 网络定位走它自己的 HTTP 接口,用设备**真实**基站/WiFi 算位置。
   设备在家 → 网络定位返回家的位置,且室内精度常优于 GPS,融合结果
   可能选中它,假 GPS 白mock。

**正确钩子点:AMap SDK 输出边界**

```
首选:com.amap.api.location.AMapLocation       ← 覆盖单次/连续定位全部出口
等价:me5.a(AMapLocation→LarkLocation 转换器)  ← Lark 侧唯一必经之路
```

在该点注入:GCJ02 坐标(锚点 + 缓慢飘移)、真实感 accuracy、
locationType 保持原值。两个子路径(GPS/网络定位)一并覆盖。

### 2.3 顺带:坐标系语义

`SpeedClockInLocationManager.b()` 按 `str`(wgs84/gcj02)映射
`gps_map_type`。AMap 返回本就是 GCJ02,注入时直接给 GCJ02 坐标即可,
链路自动报 `gps_map_type=2`,与真机一致。

## 3. 技术栈与对抗项

| 项 | 选择 | 理由(逆向证据) |
|---|---|---|
| root 方案 | Magisk + Zygisk | DenyList 可对 App 隐藏 su(14路径扫描+`which su` 全部落空 → is_cracked 如实为 false) |
| hook 框架 | LSPosed | Java 层框架 hook;相比 Frida 不留 ptrace 痕迹,DenyList 从目标进程视图摘除注入(Zygisk fork 前注入)。metasec 的 `/proc/self/maps` 扫描与 `http_sign_callstack_check` 面向 TTNet 栈,打卡请求走 liblark.so,不经 metasec |
| 触发 | 保持 App 长连接在线 + 让服务端推送,或定时前台化 | 后台熔断 `isAppRealForeground`:`openplatform.speedclockin.allow_bg_location` 未开则后台直接放弃(Manager.b())。推送路径 `PUSH_ATTENDANCE_TOP_SPEED_CLOCK_IN` 是服务端主动行为,最自然 |
| is_debug | 打卡时段关闭 USB 调试 | `Settings.Secure adb_enabled>0` 会如实上报 true |
| 作弊App | 无需处理 | app_list 只探测 cheat_app_list 名单内包名,正常手机为空 |

## 4. LSPosed 模块规格(实现清单)

一个自定义模块,配置文件(如 `/data/local/tmp/clockin_env.json`):

```json
{
  "enabled": true,
  "gps": {
    "lat_gcj02": 31.3418, "lng_gcj02": 121.5040,   // 现场校准的 GCJ02 锚点
    "jitter_radius_m": 80,
    "accuracy_base": [8, 25]
  },
  "wifi": {                        // 与 wifi.json 同源的现场实扫快照
    "connected": {"ssid": "...", "bssid": "aa:bb:...", "security": 3},
    "scan_list": [ ... ]
  }
}
```

Hook 点(共 2 处,尽力少):

1. `android.net.wifi.WifiManager`
   - `getConnectionInfo()` → 返回注入的 WifiInfo(BSSID/SSID)
   - `getScanResults()` → 返回注入列表
   - `startScan()` → 返回 true(扫描已"完成")
2. `com.amap.api.location.AMapLocation`(构造后/字段填充后)
   - setLatitude/setLongitude → 注入锚点+飘移(每次调用独立随机,
     连续定位时用缓慢漂移模型,禁止瞬移)
   - setAccuracy → 与飘移距离协调(同方案A的 hypot 公式)
   - setMock(false)/setLocationType(保留原值)

## 5. 验证顺序

1. 模块装好后,先看 Lark 内部日志(SpeedClockInLocationManager/WifiManager
   有 Log.i)确认注入生效;
2. 平日非打卡时段观察 App 的推送触发是否自然发生;
3. 第一次真实打卡盯 `clock_in_fail_code_name`(若走方案A)或考勤后台结果;
4. 失败码持久化,反馈迭代注入数据。

## 6. 残留风险(诚实清单)

- App 升级可能改变 hook 类名(混淆);AMap SDK 版本随 App 更新 —— 模块
  需按版本适配,建议 hook 点写成多候选类名;
- 服务端若对比"该设备历史 WiFi 序列"(一直家宽 → 突然公司 WiFi),
  属正常通勤叙事,风险低;但打卡时段外的其余时间 App 若也在采集
  (端点安全通道),家坐标与打卡坐标并存 —— 建议方案B设备为专用机,
  或接受混合画像;
- `EndpointSecurityFactorCollector` 另上报 timezone/VPN 给 Rust 通道,
  注入不影响,但设备时区保持 Asia/Shanghai、不挂代理。
