import json
import logging
import os
import select
import socket
import struct
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import requests
import sqlparse
from flask import Flask, Response, jsonify


CLIENT_SSL = 0x0800
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "3306"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
TARGET_HOST = os.environ.get("TARGET_HOST", "db")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "3306"))
SERVICE_NAME = os.environ.get("SERVICE_NAME", TARGET_HOST)
FORCE_UNENCRYPTED = os.environ.get("FORCE_UNENCRYPTED") == "1"
DEBUG = os.environ.get("DEBUG") == "1"
MAX_STORED_QUERIES = int(os.environ.get("MAX_STORED_QUERIES", "1000"))
LOG_FILE = os.environ.get("LOG_FILE", "/app/logs/sql.log")
SOCKET_TIMEOUT_SECONDS = float(os.environ.get("SOCKET_TIMEOUT_SECONDS", "30"))
ENFORCEMENT_MODE = os.environ.get("ENFORCEMENT_MODE", "observe").lower()
TARGET_CONNECT_RETRIES = int(os.environ.get("TARGET_CONNECT_RETRIES", "30"))
TARGET_CONNECT_RETRY_DELAY_SECONDS = float(os.environ.get("TARGET_CONNECT_RETRY_DELAY_SECONDS", "1"))

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG if DEBUG else logging.INFO,
)
logger = logging.getLogger("mysql-proxy")

app = Flask(__name__)
stored_queries = deque(maxlen=MAX_STORED_QUERIES)
stored_queries_lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_mysql_packet(sock):
    header = recv_exact(sock, 4)
    if not header:
        return None

    payload_len = int.from_bytes(header[:3], byteorder="little")
    payload = recv_exact(sock, payload_len)
    if payload is None:
        return None

    return header + payload


def payload(packet):
    return packet[4:]


def is_initial_handshake(packet):
    packet_payload = payload(packet)
    return bool(packet_payload and packet_payload[0] == 10)


def disable_server_ssl_capability(packet):
    packet_payload = bytearray(payload(packet))
    nul = packet_payload.find(b"\x00", 1)
    if nul == -1:
        return packet

    lower_offset = nul + 1 + 4 + 8 + 1
    upper_offset = lower_offset + 2 + 1 + 2
    if lower_offset + 2 > len(packet_payload):
        return packet

    lower_flags = struct.unpack("<H", packet_payload[lower_offset : lower_offset + 2])[0]
    lower_flags &= ~CLIENT_SSL
    packet_payload[lower_offset : lower_offset + 2] = struct.pack("<H", lower_flags)

    if upper_offset + 2 <= len(packet_payload):
        upper_flags = struct.unpack("<H", packet_payload[upper_offset : upper_offset + 2])[0]
        upper_flags &= ~(CLIENT_SSL >> 16)
        packet_payload[upper_offset : upper_offset + 2] = struct.pack("<H", upper_flags)

    return packet[:4] + bytes(packet_payload)


def disable_client_ssl_capability(packet):
    packet_payload = bytearray(payload(packet))
    if len(packet_payload) < 4:
        return packet

    flags = struct.unpack("<I", packet_payload[:4])[0]
    if not flags & CLIENT_SSL:
        return packet

    flags &= ~CLIENT_SSL
    packet_payload[:4] = struct.pack("<I", flags)
    return packet[:4] + bytes(packet_payload)


def decode_sql(raw_sql):
    return raw_sql.decode("utf-8", "replace").strip()


def one_line_sql(sql):
    return " ".join(sql.split())


def classify_sql(sql):
    stripped = sql.strip()
    upper = stripped.upper()
    if upper.startswith("SET "):
        return "SET"
    if upper.startswith("SHOW "):
        return "SHOW"
    if upper.startswith("USE "):
        return "USE"

    try:
        statements = sqlparse.parse(stripped)
        if not statements:
            return "UNKNOWN"
        query_type = statements[0].get_type()
        return query_type if query_type != "UNKNOWN" else "OTHER"
    except sqlparse.exceptions.SQLParseError:
        return "INVALID"


def should_allow_query(record):
    # Hook point for future LLM or rule-based policy checks.
    return True


def append_log_file(record):
    if not LOG_FILE:
        return

    log_path = Path(LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_sql_record(addr, command, sql):
    compact_sql = one_line_sql(sql)
    record = {
        "timestamp": now_iso(),
        "service": SERVICE_NAME,
        "client": f"{addr[0]}:{addr[1]}",
        "target": f"{TARGET_HOST}:{TARGET_PORT}",
        "command": command,
        "type": classify_sql(sql) if sql else "UNKNOWN",
        "sql": sql,
        "sql_one_line": compact_sql,
    }
    record["decision"] = "allowed" if should_allow_query(record) else "blocked"
    return record


def store_sql_record(record):
    with stored_queries_lock:
        stored_queries.append(record)
    append_log_file(record)

    logger.info(
        "[%s] %s %s %s: %s",
        SERVICE_NAME,
        record["decision"],
        record["command"],
        record["type"],
        record["sql_one_line"],
    )

def _async_send_to_judge(sql):
    """在背景執行的函式，負責發送 HTTP 請求並記錄分析 ID"""
    try:
        payload = {"sql_query": sql}
        # 發送 POST 請求
        response = requests.post(
            "https://sql-judge.ntut.me/api/v1/analyze", 
            json=payload, 
            timeout=10.0
        )
        
        # 檢查 HTTP 狀態碼是否為 200
        if response.status_code == 200:
            try:
                # 解析回傳的 JSON 資料
                res_data = response.json()
                analysis_id = res_data.get("analysis_id", "N/A")
                
                # 印出成功日誌與 uuid (analysis_id)
                logger.info(f"SQL Judge API Success! [Status: 200] [Analysis ID: {analysis_id}]")
            except ValueError:
                logger.warning("SQL Judge API response [Status: 200] but failed to parse JSON.")
        else:
            logger.info(f"SQL Judge API response [Status: {response.status_code}]")
            
    except requests.exceptions.RequestException as e:
        # 即使超時或失敗，也只會記錄在日誌中，完全不影響主程式
        logger.error(f"Async SQL Judge API request failed: {e}")
        
def record_sql(addr, command, sql):
    record = build_sql_record(addr, command, sql)
    store_sql_record(record)
    # TODO: if command == "COM_QUERY" then send sql content to https://sql-judge.ntut.me 
    # ---- 異步執行 TODO 區塊 ----
    if command == "COM_QUERY" and sql:
        # 建立一個獨立的 thread 來處理 HTTP 請求
        # 設定 daemon=True 確保主程式結束時，這些後台 thread 會自動釋放
        async_thread = threading.Thread(
            target=_async_send_to_judge, 
            args=(sql,), 
            daemon=True
        )
        async_thread.start()
    # ----------------------------
    return record["decision"] == "allowed"


def connect_target():
    last_error = None
    for attempt in range(1, TARGET_CONNECT_RETRIES + 1):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            server_sock.connect((TARGET_HOST, TARGET_PORT))
            return server_sock
        except OSError as exc:
            last_error = exc
            server_sock.close()
            logger.info(
                "[%s] target %s:%s not ready, retrying (%s/%s): %s",
                SERVICE_NAME,
                TARGET_HOST,
                TARGET_PORT,
                attempt,
                TARGET_CONNECT_RETRIES,
                exc,
            )
            threading.Event().wait(TARGET_CONNECT_RETRY_DELAY_SECONDS)

    raise last_error


def inspect_client_packet(packet, addr):
    packet_payload = payload(packet)
    if not packet_payload:
        return True

    command = packet_payload[0]
    if command == COM_QUERY:
        return record_sql(addr, "COM_QUERY", decode_sql(packet_payload[1:]))
    elif command == COM_STMT_PREPARE:
        return record_sql(addr, "COM_STMT_PREPARE", decode_sql(packet_payload[1:]))
    elif command == COM_INIT_DB:
        return record_sql(addr, "COM_INIT_DB", decode_sql(packet_payload[1:]))
    elif command == COM_FIELD_LIST:
        return record_sql(addr, "COM_FIELD_LIST", decode_sql(packet_payload[1:]))
    elif command == COM_STMT_EXECUTE:
        statement_id = packet_payload[1:5].hex() if len(packet_payload) >= 5 else ""
        return record_sql(addr, "COM_STMT_EXECUTE", f"statement_id=0x{statement_id}")

    return True


def parse_error_packet(packet):
    packet_payload = payload(packet)
    if not packet_payload or packet_payload[0] != 0xFF:
        return None

    errno = int.from_bytes(packet_payload[1:3], byteorder="little") if len(packet_payload) >= 3 else 0
    sql_state = ""
    message_offset = 3
    if len(packet_payload) >= 9 and packet_payload[3:4] == b"#":
        sql_state = packet_payload[4:9].decode("ascii", "replace")
        message_offset = 9
    message = packet_payload[message_offset:].decode("utf-8", "replace")
    return errno, sql_state, message


def inspect_server_packet(packet):
    error = parse_error_packet(packet)
    if not error:
        return

    errno, sql_state, message = error
    logger.warning("[%s] MySQL ERR %s %s: %s", SERVICE_NAME, errno, sql_state, message)


@app.route("/")
def home():
    with stored_queries_lock:
        lines = [
            f"{record['timestamp']} [{record['service']}] {record['command']} {record['type']} {record.get('sql_one_line', one_line_sql(record['sql']))}"
            for record in stored_queries
        ]
    return Response("\n".join(lines) + ("\n" if lines else ""), content_type="text/plain; charset=utf-8")


@app.route("/json")
def query_json():
    with stored_queries_lock:
        return jsonify(list(stored_queries))


@app.route("/reset")
def reset():
    with stored_queries_lock:
        stored_queries.clear()
    return Response("", content_type="text/plain")


def handle_client(client_sock, addr):
    logger.info("[%s] new client connection from %s:%s", SERVICE_NAME, addr[0], addr[1])
    server_sock = None
    client_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

    try:
        server_sock = connect_target()
        logger.info("[%s] connected to target %s:%s", SERVICE_NAME, TARGET_HOST, TARGET_PORT)

        sockets = [server_sock, client_sock]
        awaiting_server_handshake = True
        awaiting_client_handshake = False
        while True:
            readable, _, _ = select.select(sockets, [], [], SOCKET_TIMEOUT_SECONDS)
            if not readable:
                logger.debug("[%s] socket idle timeout", SERVICE_NAME)
                break

            for ready_sock in readable:
                packet = recv_mysql_packet(ready_sock)
                if packet is None:
                    return

                if ready_sock is server_sock:
                    if FORCE_UNENCRYPTED and awaiting_server_handshake and is_initial_handshake(packet):
                        logger.info("[%s] disabling SSL capability in server handshake", SERVICE_NAME)
                        packet = disable_server_ssl_capability(packet)
                        awaiting_client_handshake = True
                    awaiting_server_handshake = False
                    inspect_server_packet(packet)
                    client_sock.sendall(packet)
                else:
                    if FORCE_UNENCRYPTED and awaiting_client_handshake:
                        packet = disable_client_ssl_capability(packet)
                        awaiting_client_handshake = False
                    if ENFORCEMENT_MODE == "enforce":
                        if inspect_client_packet(packet, addr) is False:
                            logger.warning("[%s] blocked packet by policy", SERVICE_NAME)
                            return
                        server_sock.sendall(packet)
                    else:
                        server_sock.sendall(packet)
                        try:
                            inspect_client_packet(packet, addr)
                        except Exception:
                            logger.exception("[%s] failed to record SQL; packet was already allowed", SERVICE_NAME)
    except OSError as exc:
        logger.info("[%s] connection closed: %s", SERVICE_NAME, exc)
    finally:
        client_sock.close()
        if server_sock:
            server_sock.close()


def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(64)
    logger.info("[%s] listening on %s:%s", SERVICE_NAME, LISTEN_HOST, LISTEN_PORT)

    while True:
        client_sock, addr = server_sock.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
        client_thread.start()


def start_http():
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)


if __name__ == "__main__":
    proxy_thread = threading.Thread(target=start_server, daemon=True)
    http_thread = threading.Thread(target=start_http, daemon=True)

    proxy_thread.start()
    http_thread.start()

    proxy_thread.join()
    http_thread.join()
