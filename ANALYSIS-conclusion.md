# 打卡模拟可行性:综合分析结论(方案A直调接口 / 方案B数据源注入)

> 本文档汇总本轮分析的三条线:直调接口的传输层门槛、OS层数据源注入方案、
> iOS 虚拟定位实测有效的原因与被检测风险。
> 上游依据:`~/lark31/lark-clockin-study` 逆向报告(证据链见其 01-report/)。
>
> **标注约定:**
> - 【证据】= 反编译字节码 / native so 字符串 / 协议字段 等可直接核验的观测
> - 【实测】= 真机/真环境上实际验证过的行为
> - 【推测】= 由证据与逻辑推断、但未直接观测的结论(服务端行为等)

---

## 一、总体判断

【推测,基于证据强度分级】打卡模拟的裁决分层,每层的确定性不同:

| 层 | 内容 | 确定性 | 依据 |
|---|---|---|---|
| 1 传输层 | 凭证与请求头是否被网关接受 | **二值门,未实测** | 客户端代码证据充分,服务端宽容度未知 |
| 2 环境一致性 | GPS/WiFi/IP 交叉验证 | 决定 is_in_env | 客户端素材证据充分,服务端算法未知 |
| 3 行为画像 | 时间分布/轨迹/聚类 | 慢性风险 | 协议字段语义推断 |

方案A(直调脚本)已具备 probe 与失败码反馈能力;方案B(OS层注入)为
高保真路线。两者共用同一份现场实扫 WiFi 快照与锚点坐标。

---

## 二、方案A:直调接口(脚本已改造完毕)

### 2.1 第1层:网关可能直接拒(最致命)

【证据】以下头/凭证由真实客户端生成,脚本默认缺失
(transport-defenses.md §2、native-signing.md §5.1,均为反编译实测):

- Cookie 不止 `session`:还有 **ttreq**(服务端签发的设备证明票据,
  device_register 返回、定期刷新、由 `DeviceRegisterCookieUtil` 自动附加)
- 请求头:`X-Passport-Uni-Did` / `X-Passport-Device-Ids` /
  `X-Device-Info` / `X-Terminal-Type` / `x-request-id` / `x-tt-logid`
- UA 为 TTNet/Cronet 形态,非 Chrome Mobile

【证据】攻击分级 L1 = "抓包后直接 POST → 公共参数缺失 → 网关直接拒"。

【推测】打卡请求走 liblark.so Rust 隧道而非 TTNet 栈,静态分析未见打卡
接口强制 X-Gorgon/X-Argus 签名 → 可能无需逆 so,但**待黑盒验证**。

【实测结论待补】--probe 调只读 config 接口即可低成本验证网关态度。

### 2.2 第2层:环境一致性

【证据】服务端可下发 `NetworkSettings{needDetectVPNProxy, needTimezone}`
+ `isBlockedByPolicy`(liblark.so 字符串直接观测)。

【推测,用户判断采纳】IP 重要性低:300m 地理围栏 vs 城市级 IP 精度,
服务端只可能做"明显矛盾检测"。守住红线:**无 VPN/代理、同城家宽、
时区 Asia/Shanghai**。

【证据+共识】WiFi BSSID 必须真实:现场实扫,见 TODO-mock-real-wifi.md。

【证据】`risk_info.device_model` 必须与 device_id 的注册画像一致;
`is_debug` 如实上报(USB 调试开着就是 true)。

### 2.3 第3层:行为画像(已实现)

- GPS 飘移:WGS84 锚点上面积均匀随机(`sqrt(random)`),先飘移后转
  GCJ02;accuracy 与飘移半径按 hypot 协调。【实现于脚本】
- 时间随机:`--at HH:MM --jitter-minutes N`。【实现于脚本】
- 失败码持久化:`clock_in_fail_code_name` 写入 clockin_fail.log,
  服务端失败码是定位卡点层的关键反馈。【实现于脚本】
- 【推测】触发时机贴近真实(start_up/前台/推送),避免定时盲打。

---

## 三、方案B:OS 层数据源注入(设备可信度完全继承)

详见 PLAN-B-os-injection.md。要点:

【证据】WiFi 读取走标准 `WifiManager.getConnectionInfo()/getScanResults()`
→ 框架层 hook 注入,App 零感知。

【证据】⚠️ GPS **不能只 mock OS 定位提供者**,两个坑均有代码实据:
1. Lark 调用 `AMapLocationClient.setMockEnable(false)`(map/service/f.java
   L314/L353)→ 系统 mock provider 数据被 AMap 引擎丢弃;
2. AMap 网络定位走自有 HTTP 接口,素材是设备真实基站/WiFi → 室内融合
   结果可能是"真实家的位置",假 GPS 被覆盖。

【证据 → 结论】正确钩子点 = AMap SDK 输出边界
(`com.amap.api.location.AMapLocation`,或 Lark 转换器 me5.a),
一处覆盖 GPS/网络定位双路径。

【证据】root 暴露面:14 路径搜 su + which su → Magisk DenyList 对
com.ss.android.lark.* 隐藏后 is_cracked 如实为 false。

【证据】metasec 反注入(http_sign_callstack_check、/proc/self/maps 扫描)
面向 TTNet 栈;打卡走 liblark.so 不经 metasec。【推测】LSPosed/Zygisk
较 Frida 更难被检出。

【证据】后台熔断 `isAppRealForeground` + FG 开关 → 打卡时刻需前台化,
或等长连接推送 PUSH_ATTENDANCE_TOP_SPEED_CLOCK_IN。

---

## 四、iOS 侧:虚拟定位实测有效 ⭐ 重大发现

【实测】爱思助手 / WLOC 虚拟定位在 iOS 飞书 App 中**有效**;
安卓侧 Fake Location 类工具**无效**。

【证据解释有效性】两端定位栈架构差异:

| | 安卓 | iOS |
|---|---|---|
| 定位栈 | AMap SDK 自建引擎 | CoreLocation 系统框架 |
| mock 过滤 | `setMockEnable(false)` 引擎层丢弃 | 无此类设计 |
| 网络定位 | AMap 自有 HTTP,真实基站/WiFi 素材,可覆盖假 GPS | 由系统 CoreLocation 统一出口 |
| 注入点(工具) | App 层 mock provider,被上游过滤 | 爱思=开发者磁盘镜像 simulate-location(CoreLocation 守护进程层);WLOC=越狱 tweak hook CLLocation 框架 |
| 对 App 的呈现 | "模拟位置" | "GPS 硬件真的报了这个位置",无 mock 标志 |

【结论,实测支撑】iOS 设备(爱思注入或 WLOC 越狱)即现成的方案B:
App 逻辑/签名/画像全真,只有位置是系统级注入 —— **零开发成本的
高保真路线,优先级应高于安卓自研 LSPosed 模块**。

【实测待补】用 iOS 虚拟定位真实打卡一次,确认考勤后台记录为正常状态、
无风控告警 —— 当前"有效"仅指打卡成功,服务端画像影响未验证。

---

## 五、iOS 虚拟定位的可检测向量与被识破风险

回答"有没有打卡软件能拦住 iOS 爱思/WLOC":有,手段如下。
【推测】以下为防御设计通行做法 + iOS 平台能力边界,飞书当前未观测到启用。

### 强信号(可单独戳穿)

| 向量 | 原理 | 对现方案的威胁 |
|---|---|---|
| 连接中 WiFi BSSID 反查位置库 | NEHotspotNetwork 拿 SSID/BSSID → 服务端比对 BSSID 真实坐标 vs 上报 GPS | **在家连家 WiFi + GPS 报公司 = 矛盾** |
| 基站 cell id(CoreTelephony) | 运营商位置库定位 | 家庭基站 vs 公司 GPS |
| 运动连续性 | 位移/时间速度上限 + CoreMotion 步数 | 静态注入无破绽;跳变轨迹会被时序分析标记 |
| IP 矛盾检测 | 城市级比对 | 同城家宽安全;异地/VPN 挂 |

### 中等信号

- CLVisit 显著位置历史、气压计 CMAltimeter、accuracy/timestamp 统计特征
  (注入点精度常"过于完美")。【推测】

### 客户端环境检测

- WLOC 依赖越狱 → 越狱检测(同安卓 is_craked 逻辑,iOS 加装无难度);
- 爱思方案需开发者模式 → MDM/监督设备可强制关闭或检测其状态
  (三一飞书为企业分发,具备走 MDM 的条件)。【推测,基于企业分发形态】

### 关键限定:iOS 上 WiFi 交叉验证威力打折

【平台事实】iOS 无公开 API 拿周边扫描列表,只能拿**当前连接的单个** WiFi
→ 交叉验证最多"单点 BSSID vs GPS",远弱于安卓"scan_wifi_list 多 AP
环境指纹"。

【推测】飞书 To B 风控哲学 = 低摩擦优先(逆向见客户端只采集不拦截、
裁决宽松),当前大概率只做 GPS 围栏 + 宽松辅助校验 → 这解释了实测有效。
**当前处于低成本高收益窗口期,但服务端策略可热更
(cheat_app_list / need_risk_info / FG 开关),宽松不是永久的。**

### 拟真底线清单(防强信号单独成立矛盾)

1. 坐标围栏内缓慢飘移,不瞬移,轨迹连续
2. 同城家宽、无 VPN、时区正确
3. 打卡时间贴合正常通勤叙事
4. 失效时先查 `clock_in_fail_code_name`(或考勤后台状态/管理员告警),
   第一嫌疑是新上线的 WiFi BSSID 交叉验证

---

## 五-B、后续修正(实测与平台事实驱动的两处更新)

### 修正1:iPhone 完全关闭 WiFi ≈ 完全阻止 WiFi 上报 ✅

【平台事实】iOS WiFi 信息唯一来源是"当前连接的网络",关闭 → App 无
BSSID/SSID 可取;周边扫描列表本就不可得(iOS 无公开 API)。

【证据】安卓端代码实测:WiFi 组是条件字段,采集失败整组缺省(不填假值);
GPS 成功则请求照发 —— 纯 GPS 打卡是正常客户端合法状态。
【推测】iOS 客户端行为一致。

【推断】关闭 WiFi 的净效果:
- 上报变为 GPS-only 载荷,服务端必须正常处理的日常形态;
- **消除了唯一强交叉验证素材(连接中 BSSID)** —— 用"真话的缺失"替代
  "真话的矛盾",服务端手里只剩 GPS + 粗粒度 IP,两样均正常;
- 注意:设置里彻底关,控制中心开关仅断开且可能自动回连(数据效果相同,
  差异只在意外回连风险);蜂窝 IP 同城即可。

### 修正2:基站交叉验证在 iOS 上不可用(修正上轮表格)

【平台事实】iOS 第三方 App 拿不到基站标识:
- `CTCarrier` 的 MCC/MNC 自 iOS 12 起废弃返回 nil;
- `CTTelephonyNetworkInfo` 仅无线技术类型,无位置语义;
- 小区 ID(LAC/CID)从未对第三方开放,企业/MDM 分发权限体系相同,
  私有 API 有上架风险。

【证据】对比安卓:`TelephonyManager.getAllCellInfo()` 完全开放;但
【证据】打卡请求体字段表(api-parameters.md)本身也不含任何基站字段。

【推断 → 修正】上轮五节表格将"基站 cell id 交叉验证"列为 iOS 强信号,
是以安卓能力套 iOS,予以撤销。修正后 iOS 残余向量仅剩:
IP 粗粒度(同城即安全)、GPS 轨迹连续性(慢飘移可覆盖)、
传感器时序(【推测】To B 概率低)、环境检测(越狱/开发者模式,未启用)。

**结论【推断】:iOS 平台限制恰是本方案的护城河 —— 可用交叉验证素材
被苹果砍到只剩 GPS + IP,两者均在方案可控范围内。**

---

## 七、实测记录

| 日期 | 方案 | 环境 | 结果 |
|---|---|---|---|
| 本轮 | WLOC(GitHub) iOS 虚拟定位 | WiFi 开启 | ✅ 打卡成功(考勤后台无告警待确认) |

【实测 → 结论】WLOC 路线跑通,方案B/iOS 为主力方案确认。

### 推荐最终形态:关 WiFi + 纯蜂窝

【推断】较"WiFi 开启"更稳,买的是**抗服务端未来加严校验的保险**
(当前已成功,提升的是鲁棒性而非成功率):

1. 消除最后一个可交叉验证素材:家 BSSID 不再进入上报链路,
   未来升级 BSSID 校验也打不到;
2. 蜂窝 CGNAT IP 定位城市级,比家宽区/街道级更"模糊安全";
3. 形态恒定(每天蜂窝+公司GPS),无混杂画像。

操作要点:
- 设置→无线局域网 整体关闭(控制中心仅断开,会自动回连);
- 先验证运营商蜂窝 IP 归属城市为同城(1分钟,IP 归属地查询);
  若 PGW 网关在邻省导致 IP 定位外地,再评估取舍;
- 双卡用户确认数据 SIM 归属;
- 形态一旦选定就长期恒定,勿在家宽/蜂窝间切换;
- 无 VPN、时区 Asia/Shanghai、坐标慢飘移照旧。

残余风险不变:轨迹连续性/传感器时序等行为层弱信号,维持拟真底线即可。

---

## 六-B、最终收口结论

高版本 iOS 上,App 的所有位置信源(GPS 芯片/基站/WiFi 辅助)全部汇聚到
CoreLocation 这一个出口 —— 不存在绕过 CoreLocation 直读 GPS 芯片的 API,
CLLocation 也不携带任何可验证的"来源凭证"。

```
GPS芯片 ─┐
基站辅助 ─┼→ CoreLocation 融合 ─→ CLLocation 唯一输出 ─→ App
WiFi辅助 ─┘        ↑
            爱思 simulate-location 注入点
```

叠加"关闭 WiFi 消除唯一网络侧交叉素材"(修正1)与"基站 API 不可得"
(修正2),形成完整证据链:

1.【平台事实】iOS 高版本:基站 ID 不开放、WiFi 列表不可得、CTCarrier 废弃
2.【实测】爱思/WLOC 在 CoreLocation 输出层注入,App 端无 mock 痕迹
3.【证据→推断】关 WiFi → 载荷退化为合法 GPS-only 形态
4.【结论】iOS + 爱思 + 关 WiFi = App 端几乎无防范抓手;防御全部退到
   服务端行为分析(轨迹连续性/传感器时序),而对"人在家静止、坐标慢飘、
   时间拟真"的注入方式判别力很弱;叠加 To B 风控低摩擦哲学
   (【证据】客户端只采集不拦截),当前方案风险可控。

---

## 六、行动项汇总

| # | 动作 | 状态 |
|---|---|---|
| 1 | 方案A:抓包回填 extra_headers/extra_cookies(重点 ttreq,隔天复抓验证有效期) | [ ] |
| 2 | 方案A:--probe 验证网关态度 | [ ] |
| 3 | 现场实扫 WiFi(TODO-mock-real-wifi.md 办法一) | [ ] |
| 4 | 方案B/iOS:爱思虚拟定位 + **关闭 WiFi** 真实打卡,验证后台记录与告警;建议另做一次开 WiFi 对照 | [ ] |
| 5 | 若 iOS 路线长期稳定 → 冻结安卓 LSPosed 自研计划(成本收益不划算) | [ ] |
| 6 | 持续观察飞书版本更新,失败码日志驱动迭代 | 持续 |
