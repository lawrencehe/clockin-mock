#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
飞书极速打卡(top_speed_clock_in)直接调用脚本
依据:~/31/lark-clockin-study 逆向分析(SpeedClockInModel / NetworkUtils / entity)

链路:
  1) POST /attendance/v2/clock_in/get_top_speed_clock_in_config   -- 读取服务端决策
  2) POST /attendance/v2/clock_in/top_speed_clock_in              -- 提交 GPS + WiFi 环境
  3) 失败时按响应 top_speed_retry_time_duration(秒)重试

风控对策(务必阅读):
  - scan_wifi_list 是服务端地理交叉验证的核心素材,必须来自目标地点的真实扫描
    (在考勤点用任意 WiFi 扫描 App 导出 SSID/BSSID/加密类型),不要凭空构造
  - 中国境内坐标自动 WGS84->GCJ02 并上报 gps_map_type=2
  - risk_info 如实上报(真机 -> 全 false),app_list 按服务端 cheat_app_list 回填
  - device_id / session 必须取自同一台真机的飞书登录态

用法:
  1. 抓包获取 session(飞书请求头 cookie: session=xxx)与 device_id
  2. 准备 wifi.json(格式见 WIFI_JSON_EXAMPLE)
  3. python3 lark_speed_clockin.py --config config.json
"""

import argparse
import json
import math
import random
import sys
import time
import uuid

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

# ---------------------------------------------------------------- 配置模板 ---

CONFIG_EXAMPLE = {
    "domain": "ems_oa 域名,如 xxx.larksuite.com / 内网 ems_oa 下发域名(抓包可见)",
    "session": "你的登录态 session(cookie: session=xxx)",
    "device_id": "真机飞书的 device_id",
    "device_model": "Pixel 7, Android 14",       # rom版本, 系统版本 —— 按真机填,必须与 device_id 注册画像一致
    "longitude": 116.39747,                       # WGS84 经度(打卡围栏锚点,飘移在此坐标上做)
    "latitude": 39.908692,                        # WGS84 纬度
    "wifi_file": "wifi.json",                     # 现场真实扫描的周边 WiFi
    "dry_run": True,                              # True=只打印请求体不发送
    "extra_headers": {                            # 第1层:真机抓包抠出的设备身份头,原样回放
        "X-Passport-Uni-Did": "<抓包可见>",
        "X-Device-Info": "<抓包可见>",
        "X-Terminal-Type": "<抓包可见>"
    },
    "extra_cookies": {                            # ttreq 等设备票据,会过期,需定期重抓
        "ttreq": "<抓包可见>"
    },
    "user_agent": "",                            # 留空用默认;建议抓包抄真机 TTNet UA
    "gps_jitter_radius_m": 80,                    # 第3层:GPS 飘移半径(米),须 << 围栏半径(300m)
    "fail_log": "clockin_fail.log"                # 失败原因码持久化,用于反馈环
}

# 真实扫描导出格式(示例)。connected 指当前手机连接的那个 AP。
WIFI_JSON_EXAMPLE = {
    "connected": {
        "name": "Office-5G",
        "mac_address": "aa:bb:cc:dd:ee:01",       # BSSID
        "network_security_type": 3                # 0=开放,1=WEP,2=WPA,3=WPA2,4=WPA3(按客户端枚举)
    },
    "scan_list": [
        {"name": "Office-5G", "mac_address": "aa:bb:cc:dd:ee:01", "network_security_type": 3},
        {"name": "Office",    "mac_address": "aa:bb:cc:dd:ee:02", "network_security_type": 3},
        {"name": "Neighbor",  "mac_address": "aa:bb:cc:dd:ee:03", "network_security_type": 2}
    ]
}

UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/114.0.0.0 Mobile Safari/537.36 Lark/7.72.10")  # 默认值,建议抓包真机 UA 覆盖

M_PER_DEG_LAT = 111320.0   # WGS84 中纬度 1 度纬线米数(米->度换算)


def jitter_wgs84(lng, lat, radius_m):
    """在 WGS84 锚点上半径 radius_m 圆内面积均匀随机取一点(先飘移后转 GCJ02)"""
    if radius_m <= 0:
        return lng, lat
    r = radius_m * math.sqrt(random.random())   # 面积均匀,避免向心聚集
    theta = random.uniform(0, 2 * math.pi)
    dx = r * math.cos(theta)
    dy = r * math.sin(theta)
    m_per_deg_lng = M_PER_DEG_LAT * math.cos(lat / 180.0 * math.pi)
    return lng + dx / m_per_deg_lng, lat + dy / M_PER_DEG_LAT


def append_fail_log(path, code_name, data):
    """失败原因码持久化:服务端的 clock_in_fail_code_name 是定位卡点的关键反馈"""
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " fail_code=" + str(code_name)
                    + " resp=" + json.dumps(data, ensure_ascii=False) + "\n")
    except Exception:
        pass

URL_CONFIG = "/attendance/v2/clock_in/get_top_speed_clock_in_config"
URL_CLOCKIN = "/attendance/v2/clock_in/top_speed_clock_in"

ENV_GPS, ENV_WIFI = 1, 2   # 1=GPS 2=WIFI 3=IP 4=考勤机 5=蓝牙


# ------------------------------------------------------- WGS84 -> GCJ02 -----
# 与客户端 location/LocationCoordinateUtil.java 同算法(中国边界框 72.004~137.8347, 0.8293~55.8271)

def out_of_china(lng, lat):
    return not (72.004 <= lng <= 137.8347 and 0.8293 <= lat <= 55.8271)


def _transform_lat(x, y):
    ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * math.sqrt(abs(x))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(y * math.pi) + 40.0 * math.sin(y / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (160.0 * math.sin(y / 12.0 * math.pi) + 320.0 * math.sin(y * math.pi / 30.0)) * 2.0 / 3.0
    return ret


def _transform_lng(x, y):
    ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * math.sqrt(abs(x))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(x * math.pi) + 40.0 * math.sin(x / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (150.0 * math.sin(x / 12.0 * math.pi) + 300.0 * math.sin(x / 30.0 * math.pi)) * 2.0 / 3.0
    return ret


def wgs84_to_gcj02(lng, lat):
    """返回 (gcj_lng, gcj_lat);中国境外原样返回(此时应报 gps_map_type=1)"""
    if out_of_china(lng, lat):
        return lng, lat
    a, ee = 6378245.0, 0.00669342162296594323
    dlat = _transform_lat(lng - 105.0, lat - 35.0)
    dlng = _transform_lng(lng - 105.0, lat - 35.0)
    radlat = lat / 180.0 * math.pi
    magic = math.sin(radlat)
    magic = 1 - ee * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((a * (1 - ee)) / (magic * sqrtmagic) * math.pi)
    dlng = (dlng * 180.0) / (a / sqrtmagic * math.cos(radlat) * math.pi)
    return lng + dlng, lat + dlat


# ------------------------------------------------------------------- 请求 ---

class ClockInClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = "https://" + cfg["domain"].rstrip("/")
        self.trace_id = uuid.uuid4().hex
        self.http = requests.Session()
        headers = {
            "User-Agent": cfg.get("user_agent") or UA,
            "Content-Type": "application/json",
        }
        # 第1层:真机抓包抠出的额外头,原样回放(X-Passport-Uni-Did / X-Device-Info / ...)
        for k, v in (cfg.get("extra_headers") or {}).items():
            if v and not str(v).startswith("<"):
                headers[k] = str(v)
        self.http.headers.update(headers)
        # cookie: session + ttreq 等设备票据(真实客户端由 DeviceRegisterCookieUtil 自动附加)
        cookie_parts = ["session=" + cfg["session"]]
        for k, v in (cfg.get("extra_cookies") or {}).items():
            if v and not str(v).startswith("<"):
                cookie_parts.append(k + "=" + str(v))
        self.http.headers["cookie"] = "; ".join(cookie_parts)

    def _post(self, path, body):
        url = self.base + path
        r = self.http.post(url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- 1. 配置接口 -------------------------------------------------------
    def get_config(self):
        body = {"device_trace_id": self.trace_id}
        print(f"[config] POST {URL_CONFIG}")
        resp = self._post(URL_CONFIG, body)
        # BaseResp{code,msg,data}
        if resp.get("code") != 0:
            print(f"[config] 失败 code={resp.get('code')} msg={resp.get('msg')}")
            return None
        data = resp.get("data") or {}
        print("[config] " + json.dumps(data, ensure_ascii=False, indent=2))
        return data

    # -- 2. 风控信息(如实构造,见 TopSpeedClockInRisk) --------------------
    def build_risk_info(self, cheat_app_list):
        return {
            "is_cracked": False,          # 真机如实上报;客户端逻辑:14 路径 su 探测
            "is_emulator": False,         # anti-cheat a.i() 的 Build 指纹族检测
            "is_debug": False,            # Settings.Secure adb_enabled;开着 USB 调试则为 True
            "app_list": list(cheat_app_list or []),  # 服务端下发名单,客户端探测已安装后回填
            "device_id": self.cfg["device_id"],
            "device_os": 2,               # 恒 2(Android)
            "device_model": self.cfg.get("device_model", "unknown"),
            "is_new_version": True,
        }

    # -- 3. 打卡请求体(与 SpeedClockInModel.d() 字段序一致) --------------
    def build_body(self, cfg_data):
        env_list = cfg_data.get("environment_type_list") or []
        body = {"device_trace_id": self.trace_id}

        using_gps = ENV_GPS in env_list
        using_wifi = ENV_WIFI in env_list
        has_env = False

        # GPS 组:客户端定位成功才上报,失败整组缺省
        if using_gps:
            # 先在 WGS84 锚点上飘移,再转 GCJ02(不能在 GCJ02 坐标上飘)
            radius = float(self.cfg.get("gps_jitter_radius_m", 0) or 0)
            lng_wgs, lat_wgs = jitter_wgs84(float(self.cfg["longitude"]),
                                            float(self.cfg["latitude"]), radius)
            if out_of_china(lng_wgs, lat_wgs):
                lng, lat, map_type = lng_wgs, lat_wgs, 1        # wgs84
            else:
                lng, lat = wgs84_to_gcj02(lng_wgs, lat_wgs)
                map_type = 2                                     # gcj02(中国境内客户端统一转 GCJ02)
            # accuracy 与飘移半径协调:飘得越远精度应越差,避免"飘 80m 却报 5m 精度"的不自然组合
            base_acc = random.uniform(8.0, 25.0)
            accuracy = round(math.hypot(base_acc, radius * 0.6), 1)
            body["gps"] = {
                "longitude": round(lng, 6),
                "latitude": round(lat, 6),
                "accuracy": accuracy,
                "gps_map_type": map_type,
            }
            has_env = True
            print(f"[gps] 锚点({self.cfg['longitude']},{self.cfg['latitude']})"
                  f" 飘移≤{radius:.0f}m -> WGS84({lng_wgs:.6f},{lat_wgs:.6f})"
                  f" -> 上报({lng:.6f},{lat:.6f}) acc={accuracy} map_type={map_type}")

        # WiFi 组:必须来自真实扫描(服务端拿 BSSID 反查位置库与 GPS 交叉验证)
        if using_wifi:
            wifi = self._load_wifi()
            if wifi:
                if wifi.get("connected"):
                    c = wifi["connected"]
                    body["wifi_mac_address"] = c["mac_address"]
                    body["network_security_type"] = int(c.get("network_security_type", 0))
                if wifi.get("scan_list"):
                    body["scan_wifi_list"] = [
                        {"name": s["name"],
                         "mac_address": s["mac_address"],
                         "network_security_type": int(s.get("network_security_type", 0))}
                        for s in wifi["scan_list"]
                    ]
                has_env = True
            else:
                print("[wifi] wifi.json 缺失或为空 —— 若配置含 WiFi 环境而无法上报,服务端可能按无环境处理")

        if not has_env:
            print("[warn] environment_type_list 要求 GPS/WiFi 但两者均未成功采集,客户端此分支不会发请求")
            return None

        # 风控组:仅当 need_risk_info=true
        if cfg_data.get("need_risk_info"):
            body["risk_info"] = self.build_risk_info(cfg_data.get("cheat_app_list"))

        body["device_id"] = self.cfg["device_id"]
        return body

    def _load_wifi(self):
        path = self.cfg.get("wifi_file")
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[wifi] 读取 {path} 失败: {e}")
            return None

    # -- 4. 主流程 ---------------------------------------------------------
    def probe(self):
        """Step0 零风险探测:只调 config 只读接口,验证网关是否接受当前头/凭证集合"""
        resp = self.get_config()
        if resp is None:
            print("[probe] ✘ 网关拒绝或接口报错 —— 需要补齐 extra_headers/extra_cookies(抓包)")
            return 1
        print("[probe] ✔ 网关接受当前头/凭证集合,传输层门槛比预想低,可进入实卡流程")
        return 0

    def run(self, dry_run=False):
        cfg_data = self.get_config()
        if cfg_data is None:
            return 1
        if not (cfg_data.get("is_opened") and cfg_data.get("is_need_speed_clock_in")):
            print("[stop] 服务端决策:当前无需打卡(is_opened/is_need_speed_clock_in=false)")
            return 0
        if not cfg_data.get("is_new_version"):
            print("[stop] is_new_version=false,客户端会回退旧版链路,本脚本不覆盖该分支")
            return 0

        body = self.build_body(cfg_data)
        if body is None:
            return 1
        print("[clockin] 请求体:\n" + json.dumps(body, ensure_ascii=False, indent=2))

        if dry_run:
            print("[dry_run] 未发送。确认无误后把 config.json 中 dry_run 改为 false")
            return 0

        # 提交 + 按服务端节奏重试
        attempt, max_retry = 1, 3
        while attempt <= max_retry:
            print(f"[clockin] POST {URL_CLOCKIN} (第 {attempt} 次)")
            try:
                resp = self._post(URL_CLOCKIN, body)
            except Exception as e:
                print(f"[clockin] 网络异常: {e}")
                time.sleep(5)
                attempt += 1
                continue

            if resp.get("code") != 0:
                print(f"[clockin] 接口失败 code={resp.get('code')} msg={resp.get('msg')}")
                return 1

            data = resp.get("data") or {}
            print("[clockin] 响应: " + json.dumps(data, ensure_ascii=False, indent=2))
            if data.get("is_clock_in_succeed"):
                print("[clockin] ✔ 打卡成功 is_in_env=%s" % data.get("is_in_env"))
                return 0

            wait = int(data.get("top_speed_retry_time_duration") or 0)
            reason = data.get("clock_in_fail_code_name")
            append_fail_log(self.cfg.get("fail_log"), reason, data)
            if wait > 0 and attempt < max_retry:
                print(f"[clockin] 打卡失败({reason}),服务端要求 {wait}s 后重试")
                time.sleep(wait)
                attempt += 1
                continue
            print(f"[clockin] ✘ 打卡失败: {reason} (is_in_env={data.get('is_in_env')})")
            return 1
        return 1


# --------------------------------------------------------------------- main --

def wait_until_random(at_hhmm, jitter_minutes):
    """等到 HH:MM ± jitter_minutes 内的随机时刻(第3层:打卡时间拟真)"""
    h, m = map(int, at_hhmm.split(":"))
    target = now = time.localtime()
    target_ts = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, h, m, 0, 0, 0, -1))
    jitter_s = random.uniform(-jitter_minutes * 60, jitter_minutes * 60)
    target_ts += jitter_s
    wait = target_ts - time.time()
    if wait < -300:
        print(f"[at] 目标时刻 {at_hhmm}±{jitter_minutes}min 已过,立即执行")
        return
    print(f"[at] 目标 {at_hhmm}±{jitter_minutes}min -> 随机定在 "
          f"{time.strftime('%H:%M:%S', time.localtime(target_ts))},等待 {wait/60:.1f} 分钟")
    time.sleep(max(wait, 0))


def main():
    ap = argparse.ArgumentParser(description="飞书极速打卡接口调用(基于逆向分析)")
    ap.add_argument("--config", default="config.json", help="配置文件路径")
    ap.add_argument("--init", action="store_true", help="生成 config.json / wifi.json 模板后退出")
    ap.add_argument("--capture-hint", action="store_true", help="打印 mitmproxy 抓包核对要点后退出")
    ap.add_argument("--probe", action="store_true", help="Step0:只调只读 config 接口,验证网关态度,不发打卡")
    ap.add_argument("--at", metavar="HH:MM", help="调度:在指定时刻±随机抖动后执行打卡(如 --at 08:55)")
    ap.add_argument("--jitter-minutes", type=float, default=5.0, help="--at 的随机抖动分钟数,默认5")
    args = ap.parse_args()

    if args.capture_hint:
        print("""抓包核对要点(mitmproxy / Charles + root 设备 SSL unpinning):
  1. 过滤 host 含 ems_oa 下发域名的 POST /attendance/v2/clock_in/*
  2. 【第1层核心】完整抄录请求头,回填 config.json:
     - User-Agent(真机 TTNet UA 原文,覆盖脚本默认值)
     - X-Passport-Uni-Did / X-Passport-Device-Ids / X-Device-Info / X-Terminal-Type
     - x-request-id / x-tt-logid / X-Api-Version 等一切出现的自定义头
  3. 【第1层核心】完整抄录 Cookie:除 session 外重点抓 ttreq(设备证明票据,
     会过期 —— 隔天再抓一次对比,确定有效期,过期需重复抓包刷新)
  4. 记录真机的 device_id 与请求体字段;核对 scan_wifi_list 的
     network_security_type 取值与真机一致""")
        return

    if args.init:
        for name, tpl in (("config.json", CONFIG_EXAMPLE), ("wifi.json", WIFI_JSON_EXAMPLE)):
            with open(name, "w", encoding="utf-8") as f:
                json.dump(tpl, f, ensure_ascii=False, indent=2)
            print(f"已生成 {name}")
        print("\n下一步:填好 config.json(session/device_id/坐标),在考勤点真实扫描 WiFi 填 wifi.json")
        return

    try:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        sys.exit(f"读取 {args.config} 失败: {e}(先运行 --init 生成模板)")

    for k in ("domain", "session", "device_id", "longitude", "latitude"):
        if not cfg.get(k):
            sys.exit(f"config.json 缺少必填字段: {k}")

    if args.at:
        wait_until_random(args.at, args.jitter_minutes)

    client = ClockInClient(cfg)
    if args.probe:
        sys.exit(client.probe())
    sys.exit(client.run(dry_run=bool(cfg.get("dry_run"))))


if __name__ == "__main__":
    main()
