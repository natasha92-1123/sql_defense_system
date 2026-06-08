from fastapi import FastAPI, BackgroundTasks, Query
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
import sqlite3

# 初始化 Client：設定指向本機運行的 Ollama 服務
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

app = FastAPI(title="SQL 注入防禦系統 API (IDS 非阻塞模式)")

# 配置 n8n Webhook 端點
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/sql-alert"

# 對外服務網址
PUBLIC_BASE_URL = "https://sql-judge.ntut.me"

# SQLite 資料庫檔案
DB_PATH = "sql_analysis_results.db"

# 查詢結果預設回傳最近幾筆
# 注意：這只是 API 每次查詢預設回傳筆數，不代表資料庫最多只能存 100 筆
DEFAULT_RESULT_LIMIT = 100
MAX_RESULT_LIMIT = 500

# Lock：避免多個背景任務同時寫入資料庫時發生競爭問題
analysis_lock = Lock()


class SQLPayload(BaseModel):
    # 放寬字元限制至 1,000,000 字元，確保能接住 WordPress / Magento 等 CMS 的極端 SQL
    sql_query: str = Field(..., max_length=1000000, description="原始 SQL 查詢語句")


SYSTEM_PROMPT = """
你是一位資料庫安全專家。任務是分析 SQL 查詢是否具有 SQL Injection 風險。

你的判斷重點是：SQL 是否出現「明確攻擊意圖」或「高度可疑的注入特徵」。
請不要只因為 SQL 語句較長、條件較多、使用 IN、LIKE、CONCAT、OR，就直接判定為不安全。

請特別注意下列高風險 SQL Injection 特徵：
1. 傳統 SQL 注入，例如 OR 1=1、OR '1'='1'、AND 1=1、UNION SELECT、堆疊查詢、DROP TABLE。
2. 時間型注入，例如 SLEEP()、BENCHMARK()。
3. 錯誤型注入，例如 extractvalue()、updatexml()，特別是搭配 user()、database()、version()、concat() 取得資料庫資訊時。
4. 可疑的註解繞過，例如 --、#、/* */，且用於截斷原本 WHERE 條件。
5. 可疑的資料庫探測語句，例如 information_schema、show databases、show tables。
6. 多語句或破壞性操作，例如 ; DROP、; DELETE、; UPDATE、; INSERT，尤其出現在原本應為查詢的語句中。

請避免下列誤判：
1. 單純的 IN (...) 清單不一定是 SQL Injection。若清單內容是固定字串、系統元件名稱、component 名稱、數字 ID 清單，不應只因為 IN 清單很長就判定為不安全。
2. OR 條件不一定是攻擊。只有在出現 OR 1=1、OR '1'='1'、OR true、或搭配註解繞過、UNION、SLEEP、updatexml 等攻擊特徵時，才應提高風險。
3. CONCAT() 不一定是攻擊。若 CONCAT() 使用的是資料表欄位，例如 CONCAT(',', user_rank, ',')，通常只是字串處理，不代表使用者輸入。
4. LIKE 不一定是攻擊。像 LIKE '%,0,%'、LIKE '%keyword%' 若只是固定字串比對，不應直接判定為 SQL Injection。
5. 欄位名稱不等於使用者輸入。出現在 SELECT、WHERE、CONCAT、ORDER BY 中的欄位名稱，例如 user_rank、start_time、end_time，不應被當成未清洗的外部輸入。
6. 部分系統可能會產生較長且複雜的正常 SQL。若沒有明確注入特徵，應傾向判定為安全。

判斷原則：
1. 若 SQL 有明確攻擊特徵，請判定 is_safe=false。
2. 若 SQL 只是正常查詢、系統查詢、固定條件查詢，且沒有明確攻擊特徵，請判定 is_safe=true。
3. 若只有「可能被操控」但 SQL 本身沒有出現實際攻擊特徵，請不要直接判定為不安全；應判定為安全或低風險。
4. reason 必須指出具體特徵，不要只寫「可能被操控」這種籠統理由。
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


def get_db_connection():
    """
    建立 SQLite 連線。
    每次操作都開新連線，避免跨執行緒共用同一連線造成問題。
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # 啟用 WAL，可改善讀寫並行表現
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    return conn


def init_db():
    """
    初始化 SQLite 資料表與索引。

    analysis_results：
    - sequence_no 使用 INTEGER PRIMARY KEY AUTOINCREMENT，自動遞增
    - id 使用 UUID，並設定 UNIQUE，資料庫會建立索引
    - 查詢單筆 analysis_id 時可走索引，避免 O(N) 掃描

    safe_query_cache：
    - cache_key 使用 PRIMARY KEY，查詢時可走索引
    """
    with analysis_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                sequence_no INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                is_safe INTEGER,
                confidence_score REAL,
                reason TEXT,
                sql_query TEXT,
                raw_sql_length INTEGER,
                llm_sql_length INTEGER,
                created_at TEXT,
                updated_at TEXT,
                started_at TEXT,
                completed_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS safe_query_cache (
                cache_key TEXT PRIMARY KEY,
                sql_query TEXT,
                created_at TEXT
            )
        """)

        # id 雖然 UNIQUE 已經會建立索引，但這裡明確建立，方便報告說明
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_id
            ON analysis_results(id)
        """)

        # 讓依狀態查詢或未來篩選 completed/error 時更快
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_status
            ON analysis_results(status)
        """)

        # 讓依時間排序或查詢最近資料時更有效率
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_created_at
            ON analysis_results(created_at)
        """)

        # sequence_no 本身是 INTEGER PRIMARY KEY，已具備索引效果
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_sequence_no
            ON analysis_results(sequence_no)
        """)

        # 讓查詢 is_safe = false 的高風險紀錄更快
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_is_safe
            ON analysis_results(is_safe)
        """)

        # 讓 WHERE is_safe = 0 ORDER BY sequence_no DESC 查詢更有效率
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_results_unsafe_order
            ON analysis_results(is_safe, sequence_no DESC)
        """)

        conn.commit()
        conn.close()


def generate_analysis_id() -> str:
    """
    產生 UUID 格式的分析紀錄 ID。
    使用 UUID 可避免伺服器重開後 ID 重複。
    """
    return str(uuid.uuid4())


def create_queued_analysis_result(analysis_id: str, sql_query: str) -> int:
    """
    建立 queued 狀態的分析紀錄。
    sequence_no 由 SQLite AUTOINCREMENT 自動產生。
    回傳 sequence_no。
    """
    with analysis_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO analysis_results (
                id,
                status,
                is_safe,
                confidence_score,
                reason,
                sql_query,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                "queued",
                None,
                None,
                "SQL 查詢已接收，等待背景 AI 分析",
                sql_query,
                now_iso(),
                now_iso()
            )
        )

        sequence_no = cursor.lastrowid
        conn.commit()
        conn.close()

    return sequence_no


def update_analysis_result(analysis_id: str, updated_fields: dict) -> bool:
    """
    根據 analysis_id 更新既有分析紀錄。
    WHERE id = ? 會使用 id 索引，不需要逐筆掃描。
    """
    if not updated_fields:
        return False

    updated_fields["updated_at"] = now_iso()

    allowed_fields = {
        "status",
        "is_safe",
        "confidence_score",
        "reason",
        "raw_sql_length",
        "llm_sql_length",
        "started_at",
        "completed_at",
        "updated_at"
    }

    filtered_fields = {
        key: value for key, value in updated_fields.items()
        if key in allowed_fields
    }

    if not filtered_fields:
        return False

    columns = ", ".join([f"{key} = ?" for key in filtered_fields.keys()])
    values = list(filtered_fields.values())
    values.append(analysis_id)

    with analysis_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            f"""
            UPDATE analysis_results
            SET {columns}
            WHERE id = ?
            """,
            values
        )

        affected = cursor.rowcount
        conn.commit()
        conn.close()

    return affected > 0


def row_to_dict(row: sqlite3.Row) -> dict:
    """
    將 SQLite Row 轉成 JSON 可回傳的 dict。
    SQLite 沒有 boolean 型別，因此將 0/1 轉回 False/True。
    """
    result = dict(row)

    if result.get("is_safe") is not None:
        result["is_safe"] = bool(result["is_safe"])

    return result


def get_recent_analysis_results(
    limit: int = DEFAULT_RESULT_LIMIT,
    offset: int = 0
) -> list[dict]:
    """
    查詢最近的分析結果。
    limit 只是單次 API 回傳筆數，不是資料庫儲存上限。
    ORDER BY sequence_no DESC 可利用 sequence_no 索引。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM analysis_results
        ORDER BY sequence_no DESC
        LIMIT ?
        OFFSET ?
        """,
        (limit, offset)
    )

    rows = cursor.fetchall()
    conn.close()

    return [row_to_dict(row) for row in rows]


def get_analysis_result_by_id_from_db(analysis_id: str) -> dict | None:
    """
    根據 UUID analysis_id 查詢單筆分析結果。
    id 欄位有 UNIQUE / INDEX，因此查詢不需要 O(N) 掃描。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM analysis_results
        WHERE id = ?
        """,
        (analysis_id,)
    )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return row_to_dict(row)


def get_analysis_result_by_sequence_no(sequence_no: int) -> dict | None:
    """
    根據 sequence_no 查詢單筆分析結果。
    sequence_no 是 INTEGER PRIMARY KEY，因此查詢效率高。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM analysis_results
        WHERE sequence_no = ?
        """,
        (sequence_no,)
    )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return row_to_dict(row)


def get_total_analysis_count() -> int:
    """
    查詢目前資料庫中總共儲存幾筆分析紀錄。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM analysis_results")
    row = cursor.fetchone()
    conn.close()

    return int(row["total"])


def get_unsafe_analysis_results(
    limit: int = DEFAULT_RESULT_LIMIT,
    offset: int = 0
) -> list[dict]:
    """
    查詢所有 AI 判定為不安全的分析結果。
    SQLite 中 is_safe = 0 代表 false。
    透過 is_safe 與 sequence_no 複合索引查詢，避免逐筆掃描。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM analysis_results
        WHERE is_safe = 0
        ORDER BY sequence_no DESC
        LIMIT ?
        OFFSET ?
        """,
        (limit, offset)
    )

    rows = cursor.fetchall()
    conn.close()

    return [row_to_dict(row) for row in rows]


def get_unsafe_analysis_count() -> int:
    """
    查詢目前資料庫中 AI 判定為不安全的總筆數。
    SQLite 中 is_safe = 0 代表 false。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM analysis_results
        WHERE is_safe = 0
        """
    )

    row = cursor.fetchone()
    conn.close()

    return int(row["total"])


def generate_cache_key(sql: str) -> str:
    """
    將 SQL 語句轉成唯一 SHA-256 雜湊指紋。
    """
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def is_cache_key_exists(cache_key: str) -> bool:
    """
    檢查安全查詢快取是否已存在。
    cache_key 是 PRIMARY KEY，因此查詢可走索引。
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT cache_key
        FROM safe_query_cache
        WHERE cache_key = ?
        """,
        (cache_key,)
    )

    row = cursor.fetchone()
    conn.close()

    return row is not None


def add_safe_query_cache(cache_key: str, sql_query: str):
    """
    將已判定安全的 SQL 指紋寫入 SQLite 快取表。
    使用 INSERT OR IGNORE 避免重複寫入。
    """
    with analysis_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO safe_query_cache (
                cache_key,
                sql_query,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                cache_key,
                sql_query,
                now_iso()
            )
        )

        conn.commit()
        conn.close()


def compress_sql_for_llm(raw_sql: str) -> str:
    """
    智慧型壓縮：
    只縮短 SQL 內的超長字串資料，保留完整 SQL 指令結構。
    防止超長正常資料造成 LLM 推理延遲過高。
    """
    pattern = r"'([^'\\]*(?:\\.[^'\\]*)*)'"

    def replacer(match):
        content = match.group(1)

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
    在背景執行 AI 分析，不阻擋 MySQL Proxy 主流程。
    """
    raw_sql = payload.get("sql_query", "")

    payload["analysis_id"] = analysis_id
    payload["sequence_no"] = sequence_no

    # 1. 第一道防線：精確比對安全查詢快取表
    cache_key = generate_cache_key(raw_sql)

    if is_cache_key_exists(cache_key):
        print(
            f"[快取池命中] sequence_no={sequence_no}, "
            f"analysis_id={analysis_id}，發現完全相同的安全查詢，直接略過 LLM"
        )

        update_analysis_result(
            analysis_id,
            {
                "status": "cached",
                "is_safe": 1,
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

        is_safe = bool(result_json.get("is_safe"))

        update_analysis_result(
            analysis_id,
            {
                "status": "completed",
                "is_safe": 1 if is_safe else 0,
                "confidence_score": result_json.get("confidence_score"),
                "reason": result_json.get("reason"),
                "completed_at": now_iso()
            }
        )

        if not is_safe:
            print(
                f"[偵測到高風險查詢] sequence_no={sequence_no}, "
                f"analysis_id={analysis_id}，開始調度 n8n 進行自動化事件回應"
            )
            trigger_n8n_webhook(payload, result_json)
        else:
            print(f"[寫入 SQLite 快取池] sequence_no={sequence_no}, analysis_id={analysis_id}，學習到全新的安全查詢")
            add_safe_query_cache(cache_key, raw_sql)

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
    接收 MySQL Proxy 傳送請求的進入點。

    IDS 非阻塞模式：
    1. API 收到 SQL 後，立即產生 UUID analysis_id。
    2. SQLite 自動產生 sequence_no。
    3. 立即回傳 queued 與 is_safe=True 給 Proxy。
    4. AI 在背景分析，不阻擋網站正常運作。
    5. 分析完成後，可由 /api/v1/results/{analysis_id} 查詢結果。
    """
    print("\n====== 成功接收 API 請求，進入 IDS 非阻塞模式 ======")

    analysis_id = generate_analysis_id()
    payload_dict = payload.model_dump()
    raw_sql = payload_dict.get("sql_query")

    sequence_no = create_queued_analysis_result(
        analysis_id=analysis_id,
        sql_query=raw_sql
    )

    update_analysis_result(
        analysis_id,
        {
            "reason": f"SQL 查詢已接收，這是第 {sequence_no} 筆背景分析任務，等待 AI 分析"
        }
    )

    background_tasks.add_task(analyze_sql_with_llm, analysis_id, sequence_no, payload_dict)

    print(
        f"====== 已排入背景分析，sequence_no={sequence_no}, "
        f"analysis_id={analysis_id}，立即回傳放行訊號給 Proxy ======\n"
    )

    return JSONResponse(content={
        "status": "queued",
        "analysis_id": analysis_id,
        "sequence_no": sequence_no,
        "is_safe": True,
        "result_url": f"{PUBLIC_BASE_URL}/api/v1/results/{analysis_id}",
        "message": f"SQL 查詢已接收，這是第 {sequence_no} 筆背景分析任務，正在背景進行安全稽核"
    })


@app.get("/api/v1/results")
async def get_analysis_results(
    limit: int = Query(DEFAULT_RESULT_LIMIT, ge=1, le=MAX_RESULT_LIMIT),
    offset: int = Query(0, ge=0)
):
    """
    查看 AI 背景分析結果。
    預設回傳最近 100 筆，但資料庫不只保存 100 筆。
    可用 limit / offset 分頁查詢。
    """
    results = get_recent_analysis_results(limit=limit, offset=offset)
    total = get_total_analysis_count()

    return JSONResponse(content={
        "count": len(results),
        "total": total,
        "limit": limit,
        "offset": offset,
        "storage": "sqlite",
        "results": results
    })


@app.get("/api/v1/results/unsafe")
async def get_unsafe_results(
    limit: int = Query(DEFAULT_RESULT_LIMIT, ge=1, le=MAX_RESULT_LIMIT),
    offset: int = Query(0, ge=0)
):
    """
    查詢所有 AI 判定為不安全的 SQL 分析結果。

    SQLite 中：
    - is_safe = 0 代表 false
    - is_safe = 1 代表 true
    - is_safe = NULL 代表尚未分析完成或錯誤
    """
    results = get_unsafe_analysis_results(limit=limit, offset=offset)
    total_unsafe = get_unsafe_analysis_count()

    return JSONResponse(content={
        "count": len(results),
        "total_unsafe": total_unsafe,
        "limit": limit,
        "offset": offset,
        "storage": "sqlite",
        "filter": {
            "is_safe": False
        },
        "results": results
    })


@app.get("/api/v1/results/{analysis_id}")
async def get_analysis_result_by_id(analysis_id: str):
    """
    根據 UUID analysis_id 查詢單筆 AI 背景分析結果。
    id 欄位已建立索引，查詢不需要線性掃描。
    """
    record = get_analysis_result_by_id_from_db(analysis_id)

    if record is not None:
        return JSONResponse(content=record)

    return JSONResponse(
        status_code=404,
        content={
            "status": "not_found",
            "analysis_id": analysis_id,
            "message": f"找不到 analysis_id={analysis_id} 的分析結果，可能該 ID 不存在，或資料庫中沒有此紀錄"
        }
    )


@app.get("/api/v1/results/by-sequence/{sequence_no}")
async def get_analysis_result_by_sequence(sequence_no: int):
    """
    根據 sequence_no 查詢單筆 AI 背景分析結果。
    sequence_no 是 SQLite INTEGER PRIMARY KEY，查詢效率高。
    """
    record = get_analysis_result_by_sequence_no(sequence_no)

    if record is not None:
        return JSONResponse(content=record)

    return JSONResponse(
        status_code=404,
        content={
            "status": "not_found",
            "sequence_no": sequence_no,
            "message": f"找不到 sequence_no={sequence_no} 的分析結果"
        }
    )


@app.get("/api/v1/stats")
async def get_stats():
    """
    查詢目前資料庫統計資訊。
    """
    total = get_total_analysis_count()
    total_unsafe = get_unsafe_analysis_count()

    return JSONResponse(content={
        "storage": "sqlite",
        "database": DB_PATH,
        "total_analysis_results": total,
        "total_unsafe_results": total_unsafe,
        "query_note": "analysis_id、sequence_no、is_safe 皆使用 SQLite 索引查詢，避免以 for 迴圈線性掃描"
    })


@app.get("/")
async def root():
    """
    API 檢查。
    """
    return JSONResponse(content={
        "service": "SQL 注入防禦系統 API",
        "mode": "IDS non-blocking",
        "status": "running",
        "storage": "sqlite",
        "database": DB_PATH,
        "public_base_url": PUBLIC_BASE_URL,
        "endpoints": {
            "analyze": "POST /api/v1/analyze",
            "all_results": "GET /api/v1/results?limit=100&offset=0",
            "unsafe_results": "GET /api/v1/results/unsafe?limit=100&offset=0",
            "single_result_by_id": "GET /api/v1/results/{analysis_id}",
            "single_result_by_sequence": "GET /api/v1/results/by-sequence/{sequence_no}",
            "stats": "GET /api/v1/stats"
        },
        "status_meaning": {
            "queued": "SQL 已接收，已寫入 SQLite，等待背景 AI 分析",
            "analyzing": "背景 AI 分析任務正在執行",
            "completed": "AI 已完成分析，可查看 is_safe、confidence_score 與 reason",
            "cached": "命中 SQLite 安全查詢快取，未重新呼叫 LLM",
            "error": "模型分析或後端處理發生錯誤",
            "not_found": "查詢的 analysis_id 或 sequence_no 不存在於 SQLite 紀錄中"
        },
        "storage_note": {
            "previous_design": "初版使用 Python list 暫存，只保留最近 100 筆，且查詢單筆需要 O(N) 掃描",
            "current_design": "目前改用 SQLite 持久化儲存，不再限制只能保存 100 筆；analysis_id、sequence_no、cache_key、is_safe 皆透過索引查詢，接近 O(log n)"
        }
    })


# 啟動時初始化資料庫
init_db()