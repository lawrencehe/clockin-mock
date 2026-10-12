# clockin-mock — 极速打卡协议 PoC(本地模拟)

配套 `lark31` 逆向分析的**本地模拟/验证**工程:用 Python 复刻飞书「极速打卡」
客户端的请求构造流程(GPS + WiFi 扫描 + 协议字段),可在自建测试环境中验证对
协议的理解。

## 文件说明

| 文件 | 说明 |
|---|---|
| `lark_speed_clockin.py` | 主程序:构造并发送极速打卡请求;支持 `--probe` 探测与 dry-run |
| `config.json` | 配置模板(域名 / session / device_id / 坐标等,**均为占位符**) |
| `wifi.json` | WiFi 扫描结果样例(MAC 均为示例值) |
| `ANALYSIS-conclusion.md` | 分析结论汇总(协议、cookie、反作弊分层等) |
| `PLAN-B-os-injection.md` | 方案 B(系统层注入)设计草案 |
| `TODO-mock-real-wifi.md` | 真机 WiFi 复刻待办与注意事项 |

## 使用

```bash
pip install requests
python lark_speed_clockin.py --help
```

`config.json` 中的 `dry_run` 默认为 `true`。

## 边界

本工程仅用于对**自有测试账号 / 自建测试租户**的协议验证与学习。
请勿用于对真实生产考勤系统的伪造打卡;相关约束参见 `lark31/lark-clockin-study/POLICY.md`。

## 不要提交的东西

`config.json` 一旦填入真实 `session` / `device_id` 即视为凭据,
请勿提交到任何公开仓库(仓库已 `.gitignore` 忽略 `__pycache__`、`*.pyc`、`*.log`)。
