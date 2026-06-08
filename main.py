from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from openai import OpenAI
from datetime import datetime
from threading import Lock
import json
import httpx
import re
import hashlib
import traceback
import uuid

# 初始化 Client：設定指向本機運行的 Ollama 服務
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

app = FastAPI(title="SQL 注入防禦系統 API (IDS 非阻塞模式)")

# 配置 n8n Webhook 端點
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/sql-alert"

# 全域變數：精確比對快取池，儲存安全 SQL 的雜湊指紋
exact_match_cache = set()

# 全域變數：儲存最近的 AI 背景分析結果
analysis_results = []

# 全域變數：本次伺服器啟動後的分析請求流水號
analysis_sequence_counter = 1

# 最多保留最近 100 筆紀錄，避免記憶體無限增加
MAX_ANALYSIS_RESULTS = 100

# Lock：避免多個請求同時進來時，結果紀錄或 sequence_no 發生競爭問題
analysis_lock = Lock()


class SQLPayload(BaseModel):
    # 放寬字元限制至 1,000,000 字元，確保能接住 WordPress / Magento 等 CMS 的極端 SQL
    sql_query: str = Field(..., max_length=1000000, description="原始 SQL 查詢語句")


SYSTEM_PROMPT = """
你是一位資料庫安全專家。任務是分析 SQL 查詢是否具有 SQL Injection 風險。

請特別注意：
1. 傳統 SQL 注入，例如 1=1、UNION SELECT、堆疊查詢、DROP TABLE。
2. 時間型注入，例如 SLEEP()、BENCHMARK()。
3. Boolean-based injection，例如 OR 1=1、AND 1=1。
4. Error-based injection，例如 extractvalue()、updatexml()。
5. 可疑的註解符號，例如 --、#、/* */。
6. 可疑的資料庫探測語句，例如 information_schema、show databases、show tables。

【重要】你必須「只」回傳標準的 JSON 字串，不要包含任何 Markdown 標記，例如 ```json。

格式如下：
{
  "is_safe": false,
  "confidence_score": 0.95,
  "reason": "判斷理由說明"
}
"""


def now_iso() -> str:
    """
    回傳目前時間，方便追蹤每筆分析紀錄
    """
    return datetime.now().isoformat(timespec="seconds")


def generate_analysis_id() -> str:
    """
    產生 UUID 格式的分析紀錄 ID。
    使用 UUID 可避免伺服器重開後 ID 從 1 重新開始造成混淆。
    """
    return str(uuid.uuid4())


def generate_sequence_no() -> int:
    """
    產生本次伺服器啟動後的分析請求流水號。
    注意：此數字重開伺服器後會從 1 重新開始。
    """
    global analysis_sequence_counter

    with analysis_lock:
        current_no = analysis_sequence_counter
        analysis_sequence_counter += 1

    return current_no


def save_analysis_result(record: dict):
    """
    新增一筆 AI 分析結果，只保留最近 MAX_ANALYSIS_RESULTS 筆
    """
    with analysis_lock:
        analysis_results.append(record)

        if len(analysis_results) > MAX_ANALYSIS_RESULTS:
            analysis_results.pop(0)


def update_analysis_result(analysis_id: str, updated_fields: dict):
    """
    根據 analysis_id 更新既有分析紀錄
    """
    with analysis_lock:
        for record in analysis_results:
            if record.get("id") == analysis_id:
                record.update(updated_fields)
                record["updated_at"] = now_iso()
                return True

    return False


def generate_cache_key(sql: str) -> str:
    """
    將 SQL 語句轉成唯一 SHA-256 雜湊指紋
    """
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def compress_sql_for_llm(raw_sql: str) -> str:
    """
    智慧型壓縮：
    只縮短 SQL 內的超長字串資料，保留完整 SQL 指令結構。
    防止超長正常資料造成 LLM 推理延遲過高。
    """
    pattern = r"'([^'\\]*(?:\\.[^'\\]*)*)'"

    def replacer(match):
        content = match.group(1)

        # 如果引號內資料長度超過 100 字元，則進行遮蔽
        if len(content) > 100:
            return f"'[LONG_DATA_OMITTED_LEN_{len(content)}]'"

        return match.group(0)

    compressed_sql = re.sub(pattern, replacer, raw_sql)
    return compressed_sql


def trigger_n8n_webhook(payload: dict, ai_report: dict):
    """
    將資安警報內容打包發送給 n8n。
    目前只在 AI 判定不安全時觸發。
    """
    alert_data = {
        "event": "SQL_INJECTION_DETECTED",
        "analysis_id": payload.get("analysis_id"),
        "sequence_no": payload.get("sequence_no"),
        "sql_query": payload.get("sql_query"),
        "ai_reason": ai_report.get("reason"),
        "confidence_score": ai_report.get("confidence_score")
    }

    try:
        response = httpx.post(N8N_WEBHOOK_URL, json=alert_data, timeout=5.0)

        if response.status_code in [200, 201]:
            print("[n8n 連動成功] 資安警報已成功推送到 n8n 工作流程")
        else:
            print(f"[n8n 連動警告] n8n 伺服器回傳異常狀態碼: {response.status_code}")

    except Exception as e:
        print(f"[n8n 連動失敗] 無法連線到 n8n: {e}")


def analyze_sql_with_llm(analysis_id: str, sequence_no: int, payload: dict):
    """
    非同步稽核核心：
    在背景執行 AI 分析，不阻擋 MySQL Proxy 主流程
    """
    raw_sql = payload.get("sql_query", "")

    # 讓 n8n 告警也知道這筆分析 ID 與流水號
    payload["analysis_id"] = analysis_id
    payload["sequence_no"] = sequence_no

    # 1. 第一道防線：精確比對 Cache 池
    cache_key = generate_cache_key(raw_sql)

    if cache_key in exact_match_cache:
        print(
            f"[快取池命中] sequence_no={sequence_no}, "
            f"analysis_id={analysis_id}，發現完全相同的安全查詢，直接略過 LLM"
        )

        update_analysis_result(
            analysis_id,
            {
                "status": "cached",
                "is_safe": True,
                "confidence_score": 1.0,
                "reason": "命中安全查詢快取，未重新呼叫 LLM 分析",
                "completed_at": now_iso()
            }
        )

        return

    # 2. 執行結構保留壓縮
    safe_length_sql = compress_sql_for_llm(raw_sql)

    # 3. 終極物理截斷：送給 LLM 的 SQL 絕對不能超過 2000 字
    if len(safe_length_sql) > 2000:
        safe_length_sql = safe_length_sql[:2000] + "...[SQL_TRUNCATED]"

    print(f"\n[背景 AI 分析啟動] sequence_no={sequence_no}, analysis_id={analysis_id}")
    print(f"[背景 AI 分析啟動] 原始 SQL 長度: {len(raw_sql)} 字元")
    print(f"[背景 AI 分析啟動] 送入 AI 的 SQL 長度: {len(safe_length_sql)} 字元")

    # 先更新狀態成 analyzing
    update_analysis_result(
        analysis_id,
        {
            "status": "analyzing",
            "raw_sql_length": len(raw_sql),
            "llm_sql_length": len(safe_length_sql),
            "started_at": now_iso()
        }
    )

    # 4. 呼叫 LLM 進行分析
    try:
        response = client.chat.completions.create(
            model="llama3",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"SQL Query: {safe_length_sql}"}
            ],
            temperature=0.0
        )

        result_json = json.loads(response.choices[0].message.content)

        print(f"[AI 稽核報告產出] sequence_no={sequence_no}, analysis_id={analysis_id}:")
        print(json.dumps(result_json, indent=2, ensure_ascii=False))

        is_safe = result_json.get("is_safe")

        # 5. 更新分析結果紀錄
        update_analysis_result(
            analysis_id,
            {
                "status": "completed",
                "is_safe": is_safe,
                "confidence_score": result_json.get("confidence_score"),
                "reason": result_json.get("reason"),
                "completed_at": now_iso()
            }
        )

        # 6. 如果 AI 判定是不安全的，立刻觸發 n8n 告警流程
        if not is_safe:
            print(
                f"[偵測到高風險查詢] sequence_no={sequence_no}, "
                f"analysis_id={analysis_id}，開始調度 n8n 進行自動化事件回應"
            )
            trigger_n8n_webhook(payload, result_json)
        else:
            # 如果 AI 判定安全，將這個指紋存進快取池
            print(f"[寫入快取池] sequence_no={sequence_no}, analysis_id={analysis_id}，學習到全新的安全查詢")
            exact_match_cache.add(cache_key)

    except Exception as e:
        print(f"[模型分析發生錯誤] sequence_no={sequence_no}, analysis_id={analysis_id}: {e}")
        traceback.print_exc()

        update_analysis_result(
            analysis_id,
            {
                "status": "error",
                "is_safe": None,
                "confidence_score": 0.0,
                "reason": f"模型分析發生錯誤：{str(e)}",
                "completed_at": now_iso()
            }
        )


@app.post("/api/v1/analyze")
async def analyze_sql(payload: SQLPayload, background_tasks: BackgroundTasks):
    """
    接收組員 MySQL Proxy 傳送請求的進入點。

    IDS 非阻塞模式：
    1. API 收到 SQL 後，立即產生 UUID analysis_id。
    2. 產生 sequence_no，表示這是本次伺服器啟動後第幾筆分析請求。
    3. 立即回傳 queued 與 is_safe=True 給 Proxy。
    4. AI 在背景分析，不阻擋網站正常運作。
    5. 分析完成後，可由 /api/v1/results/{analysis_id} 查詢結果。
    """
    print("\n====== 成功接收 API 請求，進入 IDS 非阻塞模式 ======")

    analysis_id = generate_analysis_id()
    sequence_no = generate_sequence_no()
    payload_dict = payload.model_dump()

    # 收到請求後，先建立一筆 queued 紀錄
    save_analysis_result({
        "id": analysis_id,
        "sequence_no": sequence_no,
        "status": "queued",
        "is_safe": None,
        "confidence_score": None,
        "reason": f"SQL 查詢已接收，這是本次伺服器啟動後第 {sequence_no} 筆背景分析任務，等待 AI 分析",
        "sql_query": payload_dict.get("sql_query"),
        "created_at": now_iso(),
        "updated_at": now_iso()
    })

    # 將耗時的 AI 分析任務加入 FastAPI 背景佇列中
    background_tasks.add_task(analyze_sql_with_llm, analysis_id, sequence_no, payload_dict)

    print(
        f"====== 已排入背景分析，sequence_no={sequence_no}, "
        f"analysis_id={analysis_id}，立即回傳放行訊號給 Proxy ======\n"
    )

    # IDS 模式：立即回傳放行，避免網站被 LLM 推理延遲卡住
    return JSONResponse(content={
        "status": "queued",
        "analysis_id": analysis_id,
        "sequence_no": sequence_no,
        "is_safe": True,
        "message": f"SQL 查詢已接收，這是本次伺服器啟動後第 {sequence_no} 筆背景分析任務，正在背景進行安全稽核"
    })


@app.get("/api/v1/results")
async def get_analysis_results():
    """
    查看最近的 AI 背景分析結果
    """
    with analysis_lock:
        results_copy = list(analysis_results)

    return JSONResponse(content={
        "count": len(results_copy),
        "results": results_copy
    })


@app.get("/api/v1/results/{analysis_id}")
async def get_analysis_result_by_id(analysis_id: str):
    """
    根據 UUID analysis_id 查詢單筆 AI 背景分析結果
    """
    with analysis_lock:
        for record in analysis_results:
            if record.get("id") == analysis_id:
                return JSONResponse(content=record)

    return JSONResponse(
        status_code=404,
        content={
            "status": "not_found",
            "analysis_id": analysis_id,
            "message": f"找不到 analysis_id={analysis_id} 的分析結果，可能尚未分析完成、API 已重啟，或紀錄已被清除"
        }
    )


@app.get("/")
async def root():
    """
    API 健康檢查
    """
    return JSONResponse(content={
        "service": "SQL 注入防禦系統 API",
        "mode": "IDS non-blocking",
        "status": "running",
        "endpoints": {
            "analyze": "POST /api/v1/analyze",
            "all_results": "GET /api/v1/results",
            "single_result": "GET /api/v1/results/{analysis_id}"
        },
        "status_meaning": {
            "queued": "SQL 已接收，已排入背景 AI 分析佇列",
            "analyzing": "背景 AI 分析任務正在執行",
            "completed": "AI 已完成分析，可查看 is_safe、confidence_score 與 reason",
            "cached": "命中安全查詢快取，未重新呼叫 LLM",
            "error": "模型分析或後端處理發生錯誤",
            "not_found": "查詢的 analysis_id 不存在於目前記憶體結果池"
        }
    })