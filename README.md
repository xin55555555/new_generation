# generation_system

策略调优系统的联调接口工程。控制中心运行在 `8000`，本服务运行在 `8001`。

本目录已经包含接口、任务编排、攻击分类、攻击类型映射、增量模板、日志和控制中心回调代码，可以作为独立 Git 项目上传。

## 调用链

1. 控制中心收到 Syslog 告警并从 SeCoManager 下载 PCAP。
2. 控制中心调用 `POST http://127.0.0.1:8001/api/traffic/pcap/info`。
3. 本服务校验 PCAP 后立即返回任务信息，避免控制中心的 10 秒请求超时。
4. 后台调用核心分类脚本，选择对应的增量策略模板。
5. 本服务将 selected JSON 原样回调到 `POST http://127.0.0.1:8000/api/defenseConfig/update`。
6. 控制中心将策略下发至 SeCoManager/AntiDDoS 设备。

## 启动

```bash
cd /path/to/generation_system
/opt/conda/bin/pip install -r requirements.txt
/opt/conda/bin/python run.py
```

默认配置可通过环境变量覆盖：

```bash
export DDOS_PROJECT_ROOT=/path/to/generation_system
export CONTROL_CENTER_URL=http://127.0.0.1:8000
export GENERATION_API_PORT=8001
export CONTROL_CENTER_CALLBACK_REQUIRED=true
```

## 接口

控制中心对接入口函数是 `src/api/index.py` 中的 `receive_pcap_info()`，HTTP 地址是 `POST /api/traffic/pcap/info`。后台编排入口是 `src/services/job_service.py` 中的 `submit_pcap_job()`。

提交 PCAP：

```bash
curl -X POST http://127.0.0.1:8001/api/traffic/pcap/info \
  -H 'Content-Type: application/json' \
  -d '{"pcapDir":"/path/to/generation_system/data/xinertai","pcapName":"tt0603_20260603_151744_CLEAN_ABNORMAL_SYNFlood_Index_64.pcap"}'
```

查询任务：

```bash
curl http://127.0.0.1:8001/api/traffic/jobs/JOB_ID
```

日志位于 `logs/generation_system.log`，任务状态位于 `workdir/jobs/`，核心流水线结果位于 `workdir/pipeline_runs/`。


## 联调自检

以下命令使用现有 SYN Flood PCAP 和一个本地假控制中心，检查接口受理、模板选择以及 selected JSON 回传：

```bash
cd /path/to/generation_system
SMOKE_PCAP=/absolute/path/to/sample.pcap /opt/conda/bin/python tests/integration_smoke.py
```

## 项目目录

- `src/`：FastAPI 接口、后台任务、日志和控制中心回调。
- `pipeline/`：攻击分类结果映射和增量模板选择流水线。
- `核心脚本/攻击分类/`：DDoS PCAP 分类器及配置。
- `华为antiddos1908/模板/switch_templates_incremental/`：当前生效的增量策略模板。
- `config/policy_t.json`：默认策略基线备份。
