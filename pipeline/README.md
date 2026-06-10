# Pipeline Usage

This directory connects traffic input, attack classification, and Huawei AntiDDoS1908 incremental policy-template selection.

## Current Workflow

1. The control center downloads or stores a PCAP file, then calls `POST /api/traffic/pcap/info` with `pcapDir` and `pcapName`.
2. The strategy tuning API checks required parameters, absolute directory path, PCAP suffix, and whether the file exists.
3. If the API returns `code=200`, the resolved PCAP path is used as the input for the core classifier.
4. The v5.5 classifier writes classified attack PCAPs under `classified/`.
5. `policy_mapper.py` normalizes classifier output into one `attack_type` per job.
6. `run_incremental_template_pipeline.py` maps each `attack_type` to the matching incremental Huawei template.
7. The selected incremental JSON is written for downstream dispatch or manual import verification.

## PCAP Info API

Interface implemented by `strategy_tuning/api_server.py`:

```text
POST /api/traffic/pcap/info
```

Request body:

```json
{
  "pcapDir": "/path/to/generation_system/data/xinertai/",
  "pcapName": "udp.pcap"
}
```

Response contract:

```json
{
  "code": 200,
  "message": "获取PCAP文件信息成功",
  "data": {
    "resultJsonPath": "/path/to/generation_system/workdir/api_runs/.../result.json",
    "manifestPath": "/path/to/generation_system/workdir/api_runs/.../incremental_templates/selected_template_manifest.json",
    "incrementalJsonPaths": [
      "/path/to/generation_system/workdir/api_runs/.../incremental_templates/selected_templates/...incremental.json"
    ]
  }
}
```

On success, the API stores the full run result in `resultJsonPath`. The actual incremental policy JSON files for downstream dispatch are listed in `data.incrementalJsonPaths`.

Module layout:

- `strategy_tuning/api_server.py`: HTTP endpoint, response format, and `handle_pcap_info_request`.
- `strategy_tuning/pipeline_settings.py`: default paths and `PipelineConfig`.
- `strategy_tuning/pcap_policy_pipeline.py`: PCAP path validation, classifier execution, template selection, and `result.json` generation.
- `strategy_tuning/downstream_dispatcher.py`: selected JSON conversion plus control-center callback; legacy `json_to_api` remains optional.

Failure responses follow the provided interface requirement:

```json
{"code": 400, "message": "pcapDir、pcapName参数不能为空"}
{"code": 400, "message": "对应PCAP文件不存在，请检查目录和文件名"}
{"code": 500, "message": "查询PCAP文件信息失败，服务器内部异常"}
```

Start the API service:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/strategy_tuning/api_server.py --host 0.0.0.0 --port 18080
```

Preferred dispatch mode is a callback to the control center. The dispatcher loads every JSON path in `incrementalJsonPaths`, converts the selected policy into `policy_in`, and posts it to `/api/defenseConfig/update`. It never sends the aggregate `result.json` as a device policy.

The control center normally supplies its callback URL in the PCAP request as `controlCenterUrl`. It can also be configured when starting the tuning API:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/strategy_tuning/api_server.py \
  --host 0.0.0.0 \
  --port 18080 \
  --control-center-url http://127.0.0.1:8000 \
  --control-center-timeout 300
```

The older `--downstream-api-module` / `json_to_api` mode remains available for direct-device testing. It now also receives each selected incremental JSON separately. Control-center callback mode takes precedence when both modes are configured. Dispatch results are stored under `data.downstreamDispatch`.

Example request:

```bash
curl -X POST http://127.0.0.1:18080/api/traffic/pcap/info \
  -H 'Content-Type: application/json' \
  -d '{"pcapDir":"/path/to/generation_system/data/xinertai/","pcapName":"udp.pcap"}'
```


## One-Command PCAP Run

For local experiments, run a single PCAP through classification and incremental template selection:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/strategy_tuning/run_pcap_to_incremental_template.py \
  /path/to/generation_system/data/xinertai/tt0603_20260603_151744_CLEAN_ABNORMAL_SYNFlood_Index_64.pcap \
  --workdir /path/to/generation_system/workdir/xinertai_synflood_pipeline
```

The script prints a compact JSON summary. The selected incremental templates are listed in `incrementalJsonPaths`, and the full run record is stored in `resultJsonPath`.

Compatibility wrappers remain available at `pipeline/api_server.py` and `pipeline/run_pcap_to_incremental_template.py` for old commands.

## Rebase Incremental Templates

When the default AntiDDoS policy JSON changes, rebase the incremental templates against the new baseline:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/strategy_tuning/rebase_incremental_templates.py \
  --baseline /path/to/generation_system/policy_t.json \
  --template-dir /path/to/generation_system/华为antiddos1908/模板/switch_templates_incremental
```

The script backs up the previous templates, removes entries already identical to the baseline, drops devices not present in the baseline, and writes `policy_t_rebase_report.json`.

## Apply ATIC Strict Profile

After rebasing to the latest default policy, apply the `严格-Strict` column from the ATIC workbook:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/strategy_tuning/apply_atic_strict_profile.py \
  --baseline /path/to/generation_system/policy_t.json \
  --xlsx /path/to/generation_system/ATIC策略配置基线20260602.xlsx \
  --template-dir /path/to/generation_system/华为antiddos1908/模板/switch_templates_incremental
```

The script backs up the previous templates, rewrites each normalized attack template with strict-profile policy entries, and writes `atic_strict_profile_report.json`. The strict profile only changes switches/modes; every `threshold` value is inherited from `/path/to/generation_system/policy_t.json`.

## Classification

Run the third-party classifier directly:

```bash
/opt/conda/bin/python /path/to/generation_system/核心脚本/攻击分类/ddos_classifier_v5_5.py \
  "/path/to/pcaps/*.pcap" \
  --output /path/to/generation_system/workdir/classified \
  --config /path/to/generation_system/pipeline/ddos_classifier.yaml \
  --whitelist /path/to/generation_system/核心脚本/攻击分类/whitelist.json \
  -j 4
```

## Incremental Template Selection

After classification, select only the incremental policy changes needed for each detected attack type:

```bash
/opt/conda/bin/python /path/to/generation_system/pipeline/run_incremental_template_pipeline.py \
  /path/to/generation_system/workdir/classified \
  --template-dir /path/to/generation_system/华为antiddos1908/模板/switch_templates_incremental \
  --output-dir /path/to/generation_system/workdir/incremental_templates
```

Main outputs:

- `policy_jobs.jsonl` records normalized attack jobs.
- `selected_template_manifest.json` records classifier-to-template mapping results.
- `selected_templates/*.incremental.json` is the selected incremental policy-template payload.

## Existing Auxiliary Flow

`run_huawei_pipeline.py`, `huawei_dispatcher.py`, and the previous ConfScrub bridge are still available as review-oriented fallback tools. The current main path for AntiDDoS1908 is classifier output directly mapped to incremental JSON templates.
