from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Any
from openai import OpenAI
import json

# 初始化 Client：設定指向你本機運行的Ollama服務
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"  # Ollama不需要金鑰驗證，這裡隨便填而已
)

# 初始化 FastAPI 應用程式
app = FastAPI(title="SQL 注入與 ORM 漏洞防禦系統 API")

# 定義接收 Laravel 資料的 Pydantic 模型
class SQLPayload(BaseModel):
    sql_query: str = Field(..., description="原始 SQL 查詢語句")
    bindings: list[Any] | dict[str, Any] = Field(default=[], description="SQL 綁定參數")

# 資安提示詞設計
SYSTEM_PROMPT = """
你是一位資深的資料庫安全專家。任務是分析應用程式傳來的 SQL 查詢與綁定參數 (Bindings)。
請特別注意：
1. 傳統 SQL 注入 (如恆真式 1=1, UNION SELECT, 堆疊查詢)。
2. ORM 型態濫用：若單一數值欄位收到陣列 (Array) 或物件 (Dict)，極可能是攻擊者企圖利用如 CVE-2021-21263 漏洞觸發非預期綁定數量的惡意行為。

【重要】你必須「只」回傳標準的 JSON 字串，不要包含任何 Markdown 標記 (如 ```json) 或自然語言解釋。格式如下：
{
  "is_safe": false,
  "confidence_score": 0.95,
  "reason": "判斷理由說明"
}
"""

def analyze_sql_with_llm(payload: dict):
    """
    非阻塞背景任務：單獨處理耗時的本地 LLM 推論
    """
    sql = payload.get("sql_query")
    bindings = payload.get("bindings")
    print(f"\n[背景分析啟動] SQL: {sql}")
    print(f"[參數綁定內容]: {bindings}")

    try:
        # 呼叫本機的 Llama 3 模型
        response = client.chat.completions.create(
            model="llama3", 
            response_format={ "type": "json_object" },  # 強制模型輸出 JSON 物件
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"SQL Query: {sql}\nBindings: {bindings}"}
            ],
            temperature=0.1  # 調低溫度以確保分析結果的嚴謹與穩定
        )
        
        # 解析並列印 AI 的安全稽核報告
        result_json = json.loads(response.choices[0].message.content)
        print(f"[AI 稽核報告產出]:\n{json.dumps(result_json, indent=2, ensure_ascii=False)}")
        
    except Exception as e:
        print(f"[模型分析發生錯誤]: {e}")

@app.post("/api/v1/analyze")
async def analyze_sql(payload: SQLPayload, background_tasks: BackgroundTasks):
    """
    接收 Laravel 傳送請求的進入點
    """
    # 將接收到的資料轉成 Python 字典，並塞進背景任務佇列中
    background_tasks.add_task(analyze_sql_with_llm, payload.model_dump())
    
    # 瞬間回傳結果給前端，完成非阻塞設計
    return {
        "status": "queued",
        "message": "SQL 分析請求已成功接收，正在背景調度 Llama3 進行審查"
    }