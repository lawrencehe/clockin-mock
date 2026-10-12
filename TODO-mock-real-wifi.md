# TODO:Mock 真实 WiFi 数据获取

> 背景:服务端用 `scan_wifi_list` 的 BSSID 反查 Wi-Fi 位置库,与 GPS 坐标
> 做地理交叉验证(详见 `~/lark31/lark-clockin-study/01-report/location-anti-spoof.md`)。
> BSSID 是物理布设的,凭空构造是最大风控破绽 —— 数据必须真实。

目标位置:上海市杨浦区国权北路1688弄53号 湾谷科技园 B7栋
参考坐标(WGS84):121.499241, 31.343448(园区中心,B7 楼栋级待高德图钉校准)

- [ ] 办法一:现场实扫(推荐,数据 100% 真实)
- [ ] 办法二:WiGLE 账号查询(免到场,但数据是历史快照)

---

## 办法一:现场实扫(推荐)

人到 B7 楼下(园区内即可),用手机扫描并导出周边 AP。

步骤:
1. 手机装 WiFi 扫描 App(任选其一):
   - Android:「WiFi 分析仪」(WiFi Analyzer)/ WiFiInfoView
   - iOS:「AirPort 工具」类 App 或捷径
2. 站在 B7 附近静止 1~2 分钟,等扫描列表稳定(至少 10+ 个 AP)
3. 记录两类数据:
   - **当前连接的 AP**:SSID + BSSID + 加密类型 → 填 `wifi.json` 的 `connected`
   - **周边扫描列表**:全部可见 AP → 填 `scan_list`
4. 导出格式(与脚本约定一致):
   ```json
   {
     "connected":  {"name": "Office-5G", "mac_address": "aa:bb:cc:dd:ee:01", "network_security_type": 3},
     "scan_list": [
       {"name": "Office-5G", "mac_address": "aa:bb:cc:dd:ee:01", "network_security_type": 3},
       {"name": "Office",    "mac_address": "aa:bb:cc:dd:ee:02", "network_security_type": 3}
     ]
   }
   ```
   `network_security_type` 枚举:0=开放 1=WEP 2=WPA 3=WPA2 4=WPA3
   (以真机抓包一次真实打卡请求里的取值为准,和它对齐)

优点:数据即时、真实、与当前 AP 布设一致
缺点:需要人到现场一次

## 办法二:WiGLE 账号查询(免到场)

WiGLE(www.wigle.net)是全球最大志愿 WiFi 位置库,支持坐标反查周边 BSSID。

步骤:
1. 注册 wigle.net 免费账号
2. 在 Account 页面生成 API Token(格式 `AID:TOKEN`)
3. 查询湾谷科技园范围内的历史记录:
   ```bash
   curl -u "AID:TOKEN" \
     "https://api.wigle.net/api/v2/network/search?onlymine=false\
&latrange1=31.3410&latrange2=31.3460\
&longrange1=121.4970&longrange2=121.5025\
&resultsPerPage=50"
   ```
4. 从返回结果筛:lat/lon 落在 B7 半径 ~100m 内、lasttime(采集时间)尽量新
5. 整理成 `wifi.json` 格式(同上)

⚠️ 注意:
- WiGLE 数据是**志愿者过去采集的快照**,写字楼常换 AP,老 BSSID 可能已被
  服务端位置库标记过期/失效 —— 首选还是办法一,办法二做兜底
- 中国区志愿者覆盖密度一般,查不到几个 AP 属正常
- Token 不要提交到任何公开仓库

辅助验证(可选):拿到候选 BSSID 后,用免费正向接口反查它是否还活着:
`https://api.mylnikov.org/geolocation/wifi?v=1.1&bssid=xx:xx:...`
(返回 200 且坐标接近园区 → 该 BSSID 仍有效;中国区覆盖稀疏,查不到不代表无效)
